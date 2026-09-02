import {EncryptedPayload, KeeperHttpResponse, KeyValueStorage, platform, TransmissionKey, inMemoryStorage} from "../platform";
import {KeeperError} from "../errors";
import * as fs from 'fs';
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

const isEnoent = (cause: unknown): boolean =>
    typeof cause === 'object' && cause !== null && (cause as NodeJS.ErrnoException).code === 'ENOENT'

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
            throw new KeeperError(`Unable to read local config ${configName}: ${describeCause(e)}`)
        }
        // A process killed mid-write by saveStorage (or by some other writer entirely) leaves
        // an empty (or whitespace-only) file - not corruption. The sibling KMS storage backends
        // and the Python SDK already treat this as a fresh start for exactly this reason. A
        // partially-written (nonempty, non-whitespace but truncated) file is not self-healed:
        // there is no reliable way to distinguish "truncated" from "genuinely corrupt" JSON,
        // and this fix's whole point is to fail loudly rather than guess.
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
            throw new KeeperError(`Local config ${configName} contains malformed JSON`)
        }
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new KeeperError(`Local config ${configName} does not contain a JSON object`)
        }
        return parsed
    }

    const storageData = readStorage()
    const storage: KeyValueStorage = inMemoryStorage(storageData)

    const saveStorage = (storage: any) => {
        if (!configName) {
            return
        }
        // Write-then-rename instead of truncate-then-write: fs.openSync(configName, 'w', ...)
        // truncates the destination before a single byte of new content lands, so a write
        // failure used to leave a 0-byte file behind, which the empty-file self-heal above then
        // treated as a legitimate fresh start on the next read - silently discarding the
        // previous config. Renaming a same-directory temp file over the destination is atomic
        // on POSIX (the destination is always either fully-old or fully-new content, never
        // partial) and replaces an existing destination on Windows too. Same-directory
        // placement keeps the rename on one filesystem, since a cross-device rename fails
        // outright rather than silently falling back to a copy.
        const tmpPath = `${configName}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
        try {
            const fd = fs.openSync(tmpPath, 'w', 0o600)
            try {
                fs.writeSync(fd, JSON.stringify(storageData, null, 2))
            } finally {
                fs.closeSync(fd)
            }
            // Rename takes on the source file's mode, not the destination's, so the temp file
            // must already be 0600 before the rename.
            chmodSecure(tmpPath)
            fs.renameSync(tmpPath, configName)
        } catch (e) {
            try {
                fs.unlinkSync(tmpPath)
            } catch {
                // Best-effort cleanup - the write failure below is the error that matters; a
                // leftover temp file is cosmetic, it's never read back.
            }
            throw new KeeperError(`Unable to save local config ${configName}: ${describeCause(e)}`)
        }
    }

    return {
        getString: storage.getString,
        saveString: async (key, value) => {
            await storage.saveString(key, value)
            saveStorage(storage)
            return Promise.resolve()
        },
        getBytes: storage.getBytes,
        saveBytes: async (key, value) => {
            await storage.saveBytes(key, value)
            saveStorage(storage)
            return Promise.resolve()
        },
        delete: async (key) => {
            await storage.delete(key)
            saveStorage(storage)
            return Promise.resolve()
        }
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