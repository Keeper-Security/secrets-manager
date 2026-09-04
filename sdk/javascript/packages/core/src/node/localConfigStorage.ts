import {EncryptedPayload, KeeperHttpResponse, KeyValueStorage, platform, TransmissionKey, inMemoryStorage} from "../platform";
import {KeeperStorageError} from "../errors";
import * as fs from 'fs';
import * as path from 'path';
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

// Write-then-rename instead of truncate-then-write: fs.openSync(configName, 'w', ...)
// truncates the destination before a single byte of new content lands, so a write
// failure used to leave a 0-byte file behind, which the empty-file self-heal in
// readStorage then treated as a legitimate fresh start on the next read - silently
// discarding the previous config. Renaming a same-directory temp file over the
// destination is atomic on POSIX (the destination is always either fully-old or
// fully-new content, never partial) and replaces an existing destination on Windows
// too. fsyncSync before the rename means this survives a real power-loss event, not
// just a killed process.
//
// Resolving through realpathSync first (falling back to the literal path on ENOENT,
// i.e. a first-ever write) means a symlinked configName - an externally-managed
// "current config" convention, or the destination a caller's own tooling maintains -
// gets written through rather than replaced by renameSync, which operates on the link
// itself and never dereferences it (this is specified POSIX rename(2) behavior, not a
// bug to work around here). This is the same approach the write-file-atomic package
// (the de facto standard for this in the npm ecosystem) uses.
//
// A hard link is a different problem realpathSync can't help with: it's a second
// directory entry for the same inode, not a link to resolve, and renameSync only ever
// updates the one entry it's given, leaving every other hard-linked path frozen at the
// old content. Detecting nlink > 1 and writing in place instead trades away atomicity
// for that one file - but only that file, every other config file still gets the
// crash-safe path above. This mirrors Vim's backupcopy=auto: rename when the
// destination is a plain, singly-linked file, write-through when it's a link.
const writeConfigFile = (configName: string, data: string): void => {
    let resolvedPath = configName
    let stat: fs.Stats | undefined
    try {
        resolvedPath = fs.realpathSync(configName)
        stat = fs.statSync(resolvedPath)
    } catch (e) {
        if (!isEnoent(e)) {
            throw e
        }
    }

    if (stat && stat.nlink > 1) {
        // O_NOFOLLOW: unlike the rename below, a plain open follows a symlink. Without it, an
        // attacker with write access to this directory (the same threat the realpathSync
        // resolution above defends against) could swap resolvedPath into a symlink between the
        // statSync above and this open, redirecting the write to wherever it now points.
        //
        // fs.constants.O_NOFOLLOW does not exist on Windows (confirmed against Node's own
        // platform constants, the same gap KSM-1265's round-4 review found for O_DIRECTORY), so
        // this protection is accepted as POSIX-only for now, tracked alongside that same gap
        // rather than worked around here with a separate, weaker fallback.
        const fd = fs.openSync(resolvedPath, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW)
        try {
            const bytesWritten = fs.writeSync(fd, data)
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
        chmodSecure(resolvedPath)
        return
    }

    const tmpPath = `${resolvedPath}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
    const fd = fs.openSync(tmpPath, 'w', 0o600)
    try {
        fs.writeSync(fd, data)
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
        fs.renameSync(tmpPath, resolvedPath)
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

// A SIGKILL/OOM between opening the temp file and the rename in writeConfigFile leaves the
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
        // Matches the exact shape writeConfigFile produces (<pid>.<12 hex chars>) so this never
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
        // writeConfigFile's atomic rename path can no longer produce this by itself - a kill
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
            writeConfigFile(configName, JSON.stringify(storageData, null, 2))
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

export const cachingPostFunction = async (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload): Promise<KeeperHttpResponse> => {
    try {
        const response = await platform.post(url, payload.payload, {
            PublicKeyId: transmissionKey.publicKeyId.toString(),
            TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
            Authorization: `Signature ${platform.bytesToBase64(payload.signature)}`
        })
        if (response.statusCode == 200) {
            // Create cache file with secure permissions (0600)
            const cacheFd = fs.openSync('cache.dat', 'w', 0o600)
            try {
                fs.writeSync(cacheFd, Buffer.concat([transmissionKey.key, response.data]))
            } finally {
                fs.closeSync(cacheFd)
            }
        }
        return response
    } catch (e) {
        let cachedData
        try {
            cachedData = fs.readFileSync('cache.dat')
        } catch {
        }
        if (!cachedData) {
            throw new Error('Cached value does not exist')
        }
        transmissionKey.key = cachedData.slice(0, 32)
        return {
            statusCode: 200,
            data: cachedData.slice(32),
            headers: []
        }
    }
}