import {EncryptedPayload, KeeperHttpResponse, KeyValueStorage, platform, TransmissionKey, inMemoryStorage} from "../platform";
import {KeeperError, KeeperStorageError} from "../errors";
import {KEY_APP_KEY, deriveCacheKey, encodeCacheBlob, decodeCacheBlob, DEFAULT_MAX_CACHE_AGE_MS, isRawKeyBytes} from "../cache";
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {randomBytes} from 'crypto';

// fs.openSync's mode argument is only honored when the file is created; it is a no-op on an
// existing file, so permissions must be re-asserted after every write, not just the first one.
const chmodSecure = (filePath: string) => fs.chmodSync(filePath, 0o600)

// Duck-typed rather than `instanceof Error`: native fs errors are not reliably `instanceof
// Error` under Jest's test environment, since Node's own bindings throw from a different realm
// than the one Jest exposes as the global Error. This also guards against a non-Error throw
// (throw null, throw 'x') ever reaching a property access. Unlike the browser platform's
// describeCause (src/browser/localConfigStorage.ts), which also includes the error's `.name`
// (IndexedDB failures surface as DOMException, where `.name` carries the meaningful category,
// e.g. "QuotaExceededError"), this Node version only surfaces `.message` - Node's fs error
// messages already include the error code inline (e.g. "ENOENT: no such file or directory"),
// so a separate `.name` lookup adds nothing here.
const describeCause = (cause: unknown): string => {
    const message = (cause as { message?: unknown } | null | undefined)?.message
    return typeof message === 'string' ? message : 'unknown error'
}

// Same duck-typing rationale as describeCause. Populates KeeperStorageError.code so a caller
// can branch on failure type (retry on ENOSPC, alert immediately on EACCES) instead of
// string-matching the message; undefined for a cause with no such code (a JSON parse/shape
// error, not an fs failure).
const errorCode = (cause: unknown): string | undefined => {
    const code = (cause as { code?: unknown } | null | undefined)?.code
    return typeof code === 'string' ? code : undefined
}

const isEnoent = (cause: unknown): boolean =>
    typeof cause === 'object' && cause !== null && (cause as NodeJS.ErrnoException).code === 'ENOENT'

// Write-then-rename instead of truncate-then-write: fs.openSync(finalPath, 'w', ...)
// truncates the destination before a single byte of new content lands, so a write
// failure used to leave a 0-byte file behind, which the empty-file self-heal in
// readStorage then treated as a legitimate fresh start on the next read - silently
// discarding the previous config. Renaming a same-directory temp file over the
// destination is atomic on POSIX (the destination is always either fully-old or
// fully-new content, never partial) and replaces an existing destination on Windows
// too. fsyncSync before the rename means this survives a real power-loss event, not
// just a killed process.
//
// Deliberately does NOT resolve a symlink at finalPath - it operates on the literal path
// given, and renameSync replaces whatever directory entry is there (a symlink included)
// rather than dereferencing it (specified POSIX rename(2) behavior, not a bug to work around
// here). This is the safe default: a caller-supplied or attacker-plantable symlink at the
// write destination is never followed. The config file's write-through-a-symlink behavior
// (an explicit, opt-in feature for an externally-managed "current config" convention) is the
// caller's own choice, made by saveStorage resolving configName via realpathSync *before*
// calling in here - see saveStorage below. The cache file (writeCacheFile) deliberately does
// not do that resolution: there is no legitimate externally-managed symlink convention for a
// path the SDK itself names and owns, so a symlink there is presumptively hostile and must be
// replaced, never written through (this is exactly the arbitrary-file-overwrite KSM-1265's
// security fix closes - regression test: "a symlink at the cache path is replaced by the
// write, never followed").
//
// A hard link is a different problem symlink resolution can't help with either way: it's a
// second directory entry for the same inode, not a link to resolve, and renameSync only ever
// updates the one entry it's given, leaving every other hard-linked path frozen at the old
// content. Detecting nlink > 1 (via lstatSync, so a symlink at finalPath is never followed
// here either) and writing in place instead trades away atomicity for that one file - but
// only that file, every other write through this function still gets the crash-safe path
// above. This mirrors Vim's backupcopy=auto: rename when the destination is a plain,
// singly-linked file, write-through when it's a link.
//
// Shared by both the config file (saveStorage) and the cache file (writeCacheFile) - one
// atomic-write primitive, so a protection added for one (hard-link write-in-place,
// fsync-before-rename) isn't something the other has to reimplement or drift out of sync with.
//
// fs.writeSync's overloads don't distribute over a string | Uint8Array union, so the two data
// types need their own branch rather than one unbranched call.
const writeFileAtomic = (finalPath: string, data: string | Uint8Array): void => {
    let stat: fs.Stats | undefined
    try {
        stat = fs.lstatSync(finalPath)
    } catch (e) {
        if (!isEnoent(e)) {
            throw e
        }
    }

    if (stat && stat.nlink > 1) {
        // O_NOFOLLOW: unlike the rename below, a plain open follows a symlink. Without it, an
        // attacker with write access to this directory could swap finalPath into a symlink
        // between the lstatSync above and this open, redirecting the write to wherever it now
        // points.
        //
        // fs.constants.O_NOFOLLOW does not exist on Windows (confirmed against Node's own
        // platform constants, the same gap KSM-1265's round-4 review found for O_DIRECTORY), so
        // this protection is accepted as POSIX-only for now, tracked alongside that same gap
        // rather than worked around here with a separate, weaker fallback.
        const fd = fs.openSync(finalPath, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW)
        try {
            const bytesWritten = typeof data === 'string' ? fs.writeSync(fd, data) : fs.writeSync(fd, data)
            fs.ftruncateSync(fd, bytesWritten)
            fs.fsyncSync(fd)
        } catch (writeError) {
            try {
                fs.closeSync(fd)
            } catch {
                // A close failure here is secondary - the write error is what caused this and
                // is what must propagate, not whatever closing a doomed fd produced.
            }
            throw writeError
        }
        fs.closeSync(fd)
        chmodSecure(finalPath)
        return
    }

    const tmpPath = `${finalPath}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
    const fd = fs.openSync(tmpPath, 'w', 0o600)
    try {
        if (typeof data === 'string') {
            fs.writeSync(fd, data)
        } else {
            fs.writeSync(fd, data)
        }
        fs.fsyncSync(fd)
    } catch (writeError) {
        try {
            fs.closeSync(fd)
        } catch {
            // Same as above: a close failure here is secondary to the write error that
            // caused this branch, don't let it replace the error that actually matters.
        }
        throw writeError
    }
    fs.closeSync(fd)
    // Rename takes on the source file's mode, not the destination's, so the temp file
    // must already be 0600 before the rename.
    chmodSecure(tmpPath)
    try {
        fs.renameSync(tmpPath, finalPath)
    } catch (e) {
        try {
            fs.unlinkSync(tmpPath)
        } catch {
            // Best-effort cleanup - the write failure below is the error that matters; a
            // leftover temp file is cosmetic, it's never read back.
        }
        throw e
    }
}

// A SIGKILL/OOM between opening the temp file and the rename in writeFileAtomic leaves the
// temp file behind permanently - it's never read back as config data, but it does hold a full
// snapshot of every secret that was in storageData at that moment, so it shouldn't just sit on
// disk forever. Swept here, on the next read, rather than at write time, since the crash that
// creates one is exactly what prevents the write that would otherwise have cleaned it up.
//
// Only removes a temp file older than ORPHANED_TEMP_FILE_MAX_AGE_MS. A concurrent writer (e.g.
// another pod sharing this same mounted config path) has its own temp file open right now with
// a name matching this same pattern; a PID-liveness check would be the more precise filter, but
// PIDs aren't visible across the container/pod boundary this matters most for, so an age
// threshold - a plain filesystem timestamp any process can see - is the check that actually
// holds up here. The threshold is generous relative to how long a write+fsync+rename actually
// takes (milliseconds, even under load).
const ORPHANED_TEMP_FILE_MAX_AGE_MS = 60_000

const cleanupOrphanedTempFiles = (configName: string): void => {
    let resolvedPath = configName
    try {
        resolvedPath = fs.realpathSync(configName)
    } catch (e) {
        if (!isEnoent(e)) {
            return
        }
    }
    const dir = path.dirname(resolvedPath)
    const base = path.basename(resolvedPath)
    let entries: string[]
    try {
        entries = fs.readdirSync(dir)
    } catch {
        return
    }
    const prefix = `${base}.`
    const suffix = '.tmp'
    const now = Date.now()
    for (const entry of entries) {
        if (!entry.startsWith(prefix) || !entry.endsWith(suffix)) {
            continue
        }
        // Matches the exact shape writeFileAtomic produces (<pid>.<12 hex chars>) so this never
        // sweeps an unrelated file that merely shares the config's name as a prefix.
        const middle = entry.slice(prefix.length, entry.length - suffix.length)
        if (!/^\d+\.[0-9a-f]{12}$/.test(middle)) {
            continue
        }
        const entryPath = path.join(dir, entry)
        try {
            if (now - fs.statSync(entryPath).mtimeMs < ORPHANED_TEMP_FILE_MAX_AGE_MS) {
                continue
            }
            fs.unlinkSync(entryPath)
        } catch {
            // Best-effort: a concurrent writer already renamed or removed this, or a
            // permissions quirk - not worth failing config load over either way.
        }
    }
}

export const localConfigStorage = (configName?: string): KeyValueStorage => {

    // Node validates config readability eagerly, here at construction, because fs is
    // synchronous. The browser localConfigStorage defers the equivalent check lazily to first
    // getString/saveString/delete, because IndexedDB has no synchronous API to check eagerly
    // against - a structural difference between the two platforms, not a
    // stylistic one.
    //
    // Deliberately does not reject a symlinked configName. Kubernetes always mounts a Secret or
    // ConfigMap as a symlink chain (configName -> ..data/<key> -> a timestamped directory), so
    // rejecting a read through a symlink here breaks every pod that mounts config.json this way.
    // Reading through a symlink was never the vulnerability - only a write redirected through one
    // is - so symlink protection lives on the write path (saveStorage) instead.
    const readStorage = (): any => {
        if (!configName) {
            return {}
        }
        cleanupOrphanedTempFiles(configName)
        let raw: string
        try {
            // TextDecoder with fatal:true throws on an invalid UTF-8 byte sequence instead of
            // silently substituting U+FFFD (what Buffer#toString('utf8') does), so single-byte
            // corruption inside a JSON string value is caught here rather than sailing through
            // into a plausible-looking but wrong parsed value. It also strips a leading BOM per
            // the WHATWG Encoding spec's default ignoreBOM:false for the 'utf-8' label, so no
            // separate BOM-stripping step is needed.
            raw = new TextDecoder('utf-8', {fatal: true}).decode(fs.readFileSync(configName))
        } catch (e) {
            if (isEnoent(e)) {
                return {}
            }
            throw new KeeperStorageError(`Unable to read local config ${configName}: ${describeCause(e)}`, errorCode(e))
        }
        // An empty (or whitespace-only) file is a legitimate fresh start, not corruption.
        // writeFileAtomic's atomic rename path can no longer produce this by itself - a kill
        // mid-write only ever leaves a temp file behind, configName itself is untouched until
        // the rename completes - but its hard-link write-in-place branch still writes into
        // configName directly, so a kill mid-write there can still leave it empty, and some
        // other writer entirely (a stray `echo -n > config.json`, a pre-atomic-write version of
        // this SDK) can too. The sibling KMS storage backends and the Python SDK already treat
        // this as a fresh start for exactly this reason. A partially-written (nonempty,
        // non-whitespace but truncated) file is not self-healed: there is no reliable way to
        // distinguish "truncated" from "genuinely corrupt" JSON, and this fix's whole point is
        // to fail loudly rather than guess.
        if (raw.trim().length === 0) {
            return {}
        }
        let parsed: any
        try {
            parsed = JSON.parse(raw)
        } catch {
            // JSON.parse's SyntaxError text can echo a snippet of the surrounding malformed
            // input, which for a corrupted config could be a fragment of an adjacent secret
            // value - unlike the fs-error branch above, this message must not forward anything
            // from the underlying error.
            throw new KeeperStorageError(`Local config ${configName} contains malformed JSON`, undefined)
        }
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new KeeperStorageError(`Local config ${configName} does not contain a JSON object`, undefined)
        }
        return parsed
    }

    const storageData = readStorage()
    const storage: KeyValueStorage = inMemoryStorage(storageData)

    const saveStorage = () => {
        if (!configName) {
            return
        }
        try {
            // Resolved here, not inside writeFileAtomic: this is the config file's own opt-in
            // choice to write through a symlinked configName (an externally-managed "current
            // config" convention some deployments use), not a default writeFileAtomic extends
            // to every caller - the cache file (writeCacheFile) deliberately skips this
            // resolution, see writeFileAtomic's own comment for why. Falls back to the literal
            // path on ENOENT (a first-ever write, nothing to resolve yet).
            let resolvedPath = configName
            try {
                resolvedPath = fs.realpathSync(configName)
            } catch (e) {
                if (!isEnoent(e)) {
                    throw e
                }
            }
            writeFileAtomic(resolvedPath, JSON.stringify(storageData, null, 2))
        } catch (e) {
            throw new KeeperStorageError(`Unable to save local config ${configName}: ${describeCause(e)}`, errorCode(e))
        }
    }

    // storage.saveString/saveBytes/delete all mutate storageData in place (inMemoryStorage
    // closes over this exact object, supporting nested "a/b/c" keys), before saveStorage ever
    // runs. Without this, a failed save leaves storageData - and so this instance's getString/
    // getBytes for the rest of its lifetime - holding a value that was never actually persisted;
    // a caller that catches the rejection and keeps going is then acting on a value that
    // reverts the moment the process restarts. Restoring in place (clear then reassign),
    // rather than pointing storageData at a new object, matters because inMemoryStorage's own
    // closure only ever sees this one object reference.
    const snapshotStorageData = (): any => JSON.parse(JSON.stringify(storageData))

    const restoreStorageData = (snapshot: any): void => {
        for (const key of Object.keys(storageData)) {
            delete storageData[key]
        }
        Object.assign(storageData, snapshot)
    }

    // storage.saveString/etc. mutate storageData synchronously, before the very first `await`
    // in this function even suspends. Without serializing, two overlapping calls interleave:
    // B's snapshot ends up taken after A's mutation already landed, so if A's saveStorage then
    // fails, A's rollback reverts to a snapshot from before B ever ran - destroying B's already-
    // applied mutation even though B never failed. Chaining every call onto pendingOperation
    // means each call's entire snapshot-mutate-persist(-rollback) sequence fully finishes before
    // the next one's snapshot is even taken, so this can no longer happen.
    let pendingOperation: Promise<void> = Promise.resolve()

    const mutateAndPersist = (mutate: () => Promise<void>): Promise<void> => {
        const operation = pendingOperation.then(async () => {
            const snapshot = snapshotStorageData()
            await mutate()
            try {
                saveStorage()
            } catch (e) {
                restoreStorageData(snapshot)
                throw e
            }
        })
        // A rejected promise assigned here would permanently poison every later call chained
        // onto it; swallowing the rejection only for chaining purposes still lets the rejection
        // this function returns to its actual caller propagate normally.
        pendingOperation = operation.catch(() => {})
        return operation
    }

    return {
        getString: storage.getString,
        saveString: (key, value) => mutateAndPersist(() => storage.saveString(key, value)),
        getBytes: storage.getBytes,
        saveBytes: (key, value) => mutateAndPersist(() => storage.saveBytes(key, value)),
        delete: (key) => mutateAndPersist(() => storage.delete(key))
    }
}

// fs.constants.O_DIRECTORY/O_NOFOLLOW are undefined on Windows (same gap already tracked for
// writeFileAtomic's hard-link branch). There, `x | undefined` coerces to plain `x` and the two
// checks below silently stop verifying anything - not a crash, just a directory/file open with
// no symlink protection at all. Unlike writeFileAtomic's hard-link branch (where O_NOFOLLOW is
// one layer of defense-in-depth on top of an already-safe rename), this is the *only*
// protection the cache directory/file has, so a silent no-op here is a bigger gap. There is no
// good fallback available without a real openat()-style relative-to-fd primitive, which Node's
// public fs API doesn't expose - accepted as a documented, POSIX-only limitation rather than
// building a weaker check-then-open substitute, matching how KSM-1266's own review already
// decided the identical Windows gap for O_NOFOLLOW.
const hasDirectorySymlinkProtection = typeof fs.constants.O_DIRECTORY === 'number' && typeof fs.constants.O_NOFOLLOW === 'number'
const cacheDirOpenFlags = hasDirectorySymlinkProtection ? fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW : fs.constants.O_DIRECTORY
const cacheFileReadFlags = hasDirectorySymlinkProtection ? fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW : fs.constants.O_RDONLY

const writeCacheFile = async (cachePath: string, cacheKey: Uint8Array, plaintext: Uint8Array): Promise<void> => {
    cleanupOrphanedTempFiles(cachePath)
    const dir = path.dirname(cachePath)
    // A relative cachePath with no directory component resolves dir to '.', the process's
    // current working directory - not a directory this function created or owns. Hardening a
    // directory the caller never named is a surprising side effect, so directory-level
    // hardening only applies when cachePath actually names a directory component. The default
    // path is always absolute, so the security-relevant case is unaffected.
    if (dir !== '.') {
        // mkdirSync(recursive: true) follows a symlink in any existing ancestor segment of a
        // custom, multi-segment cachePath - only the leaf gets an O_NOFOLLOW check below. A
        // pre-planted symlink ancestor (e.g. an attacker who can write to /shared pre-creates
        // /shared/ksm as a symlink before this code ever runs, given cachePath under
        // /shared/ksm/nested/cache.dat) silently relocates the whole cache, no race required.
        // Accepted as a structurally-unclosable limitation without a native openat2()-style
        // RESOLVE_NO_SYMLINKS binding (Linux-only even then, and its own author documents that
        // blanket rejection breaks legitimate ancestor symlinks - confirmed directly: a first
        // attempt at a plain lstat-every-segment check broke on macOS's own /tmp -> /private/tmp
        // convention, indistinguishable by inspection from an attacker-planted one). No portable
        // fix exists in Node's plain fs API; none of mkdirp/make-dir/write-file-atomic attempt
        // one either. Same shape as the Windows O_NOFOLLOW gap already documented in this file.
        // Unlike KSM-1263's file-level re-assertion (which runs on every write, since the SDK
        // exclusively owns that one file it names), this only re-chmods the directory when this
        // call is the one that just created it. A directory that already existed - most
        // plausibly a caller-supplied cachePath pointing somewhere the caller manages, e.g. a
        // file directly inside $HOME - keeps whatever permissions its actual owner set; the SDK
        // doesn't forcibly narrow permissions on a resource it doesn't own. This matches the
        // pattern documented for npm's own cache/config directory ("there are times when you do
        // not want to change ownership of the default directory... configure a different
        // directory altogether") and avoids the exact bug shape filed against another CLI's
        // config-dir hardening (unconditional per-run chmod silently overriding a user's own
        // chosen mode on a directory they own) - researched this session, not just inferred.
        const dirExistedBefore = fs.existsSync(dir)
        fs.mkdirSync(dir, {recursive: true, mode: 0o700})
        // O_DIRECTORY|O_NOFOLLOW makes "is this a real directory, not a symlink" and the open
        // the same syscall, so there's no gap between a check and a separate mkdirSync/chmodSync
        // for a symlink to be swapped into (Windows caveat above). fchmodSync operates on the fd
        // this open returned, pinning the exact inode instead of re-resolving the path a second
        // time - though re-resolution still happens at the later file open below, since Node
        // has no relative-to-this-fd open; that residual window is narrow (already-checked
        // directory to already-checked file, both immediately adjacent to their use) but real.
        const dfd = fs.openSync(dir, cacheDirOpenFlags)
        try {
            if (!dirExistedBefore) {
                fs.fchmodSync(dfd, 0o700)
            }
        } finally {
            fs.closeSync(dfd)
        }
    }
    const blob = await encodeCacheBlob(plaintext, cacheKey)
    writeFileAtomic(cachePath, blob)
}

// Bounds how much a corrupted, misconfigured, or maliciously-placed file at the cache path can
// force this to allocate before decodeCacheBlob gets any chance to reject it. Real cache blobs
// are tiny (a version byte, an 8-byte timestamp, and the encrypted response); generous headroom
// over any real response, same shape as MAX_ERROR_BODY_DECODE_BYTES in keeper.ts.
const MAX_CACHE_FILE_BYTES = 10 * 1024 * 1024

const readCacheFile = async (cachePath: string, cacheKey: Uint8Array, maxCacheAgeMs: number): Promise<Uint8Array> => {
    cleanupOrphanedTempFiles(cachePath)
    let raw: Buffer
    try {
        const dir = path.dirname(cachePath)
        if (dir !== '.') {
            // open-then-close is enough here (nothing needs to persist past the check), but it's
            // the same O_DIRECTORY|O_NOFOLLOW atomic check-and-open writeCacheFile uses, so a
            // symlinked cache directory is rejected on the read path too. Same residual
            // re-resolution window as writeCacheFile's comment above.
            const dfd = fs.openSync(dir, cacheDirOpenFlags)
            fs.closeSync(dfd)
        }
        // O_NOFOLLOW folds the "not a symlink" check into the open itself, closing the gap a
        // separate lstat-then-readFileSync would leave open (Windows caveat above).
        const fd = fs.openSync(cachePath, cacheFileReadFlags)
        try {
            const size = fs.fstatSync(fd).size
            if (size > MAX_CACHE_FILE_BYTES) {
                throw new KeeperError(`Cache file ${cachePath} exceeds the maximum expected size`)
            }
            raw = fs.readFileSync(fd)
        } finally {
            fs.closeSync(fd)
        }
    } catch (e) {
        if (e instanceof KeeperError) {
            throw e
        }
        if (isEnoent(e)) {
            throw new KeeperError('Cached value does not exist')
        }
        throw new KeeperError(`Unable to read cache file ${cachePath}: ${describeCause(e)}`)
    }
    try {
        return await decodeCacheBlob(raw, cacheKey, maxCacheAgeMs)
    } catch (e) {
        throw new KeeperError(`Cache file ${cachePath} is invalid: ${describeCause(e)}`)
    }
}

// Same closure shape and cache codec (../cache) as browser/localConfigStorage.ts's
// createCachingFunction; only the storage medium differs (a file here, IndexedDB there).
// Replaces the old standalone cachingPostFunction, which kept the AES key in plaintext beside
// the ciphertext it protected, in a fixed CWD-relative file, with no integrity check on restore.
// Fixing all three requires access to the config (to derive a cache key that isn't the
// transmission key itself) and a chosen cache location, so the factory shape - not the old
// zero-argument function - is what the fix needs.
// An options object, not positional args: browser's createCachingFunction takes
// (storage, maxCacheAgeMs?) - same position, different meaning than Node's second positional arg
// would otherwise be. A number intended for maxCacheAgeMs silently landing on cachePath (or vice
// versa) fails at runtime with a confusing path error; naming both fields turns that into a
// compile-time type error instead.
export const createCachingFunction = (
    storage: KeyValueStorage,
    {
        // Computed here, not at module scope: os.homedir() throws in an environment with no $HOME
        // and no matching /etc/passwd entry for the current uid (some containers), and a default
        // parameter only evaluates when the caller omits the field - so that failure now only
        // reaches a caller who actually relies on the default, at call time, not every consumer
        // who merely imports this module.
        cachePath = path.join(os.homedir(), '.keeper', 'ksm-cache.dat'),
        maxCacheAgeMs = DEFAULT_MAX_CACHE_AGE_MS
    }: {cachePath?: string, maxCacheAgeMs?: number} = {}
): (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload, allowUnverifiedCertificate?: boolean) => Promise<KeeperHttpResponse> =>
    async (url, transmissionKey, payload, allowUnverifiedCertificate) => {
        let response: KeeperHttpResponse
        try {
            response = await platform.post(url, payload.payload, {
                PublicKeyId: transmissionKey.publicKeyId.toString(),
                TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
                Authorization: `Signature ${platform.bytesToBase64(payload.signature)}`
            }, allowUnverifiedCertificate)
        } catch (e) {
            // A storage failure here (plausible during the same outage that took the network
            // down, for a KMS-backed KeyValueStorage) is treated the same as "no usable app key
            // yet" - both mean the cache can't be read, not a reason to let a different,
            // unrelated exception replace the original network error's context.
            let appKey: Uint8Array | undefined
            try {
                appKey = await storage.getBytes(KEY_APP_KEY)
            } catch {
                appKey = undefined
            }
            if (!appKey || !isRawKeyBytes(appKey)) {
                throw new KeeperError('Cached value does not exist')
            }
            const cachedData = await readCacheFile(cachePath, await deriveCacheKey(appKey), maxCacheAgeMs)
            console.error(`Network request failed (${describeCause(e)}); serving cached response, which may be stale`)
            transmissionKey.key = cachedData.slice(0, 32)
            return {
                statusCode: 200,
                data: cachedData.slice(32),
                headers: []
            }
        }
        if (response.statusCode == 200) {
            try {
                const appKey = await storage.getBytes(KEY_APP_KEY)
                // Same isRawKeyBytes guard as the fallback branch above - without it, a
                // non-raw-bytes value (e.g. a wrapped CryptoKey under a hypothetical Node
                // useObjects mode) reaches deriveCacheKey unchecked and logs a confusing
                // internal TypeError instead of just skipping the cache write cleanly.
                if (appKey && isRawKeyBytes(appKey)) {
                    await writeCacheFile(cachePath, await deriveCacheKey(appKey), Buffer.concat([transmissionKey.key, response.data]))
                }
            } catch (e) {
                console.error(`Failed to update cached response: ${describeCause(e)}`)
            }
        }
        return response
    }
