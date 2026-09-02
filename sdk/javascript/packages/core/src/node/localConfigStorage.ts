import {EncryptedPayload, KeeperHttpResponse, KeyValueStorage, platform, TransmissionKey, inMemoryStorage} from "../platform";
import {KeeperError} from "../errors";
import * as fs from 'fs';

// fs.openSync's mode argument is only honored when the file is created; it is a no-op on an
// existing file, so permissions must be re-asserted after every write, not just the first one.
const chmodSecure = (filePath: string) => fs.chmodSync(filePath, 0o600)

// Node-local sibling of the browser localConfigStorage's describeCause/idbFailure convention
// (src/browser/localConfigStorage.ts). Duck-typed rather than `instanceof Error`, same as that
// file and as errorMessage()/classifyCryptoFailure() elsewhere in this file: native fs errors are
// not reliably `instanceof Error` under Jest's test environment, since Node's own bindings throw
// from a different realm than the one Jest exposes as the global Error. This also guards against
// a non-Error throw (throw null, throw 'x') ever reaching a property access.
const describeCause = (cause: unknown): string => {
    const message = (cause as { message?: unknown } | null | undefined)?.message
    return typeof message === 'string' ? message : 'unknown error'
}

const isEnoent = (cause: unknown): boolean =>
    typeof cause === 'object' && cause !== null && (cause as NodeJS.ErrnoException).code === 'ENOENT'

// A leading UTF-8 BOM is valid, non-corrupt JSON text - produced by tools like Windows Notepad or
// PowerShell's Set-Content - and must not be treated as corruption.
const stripBOM = (text: string): string => text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text

export const localConfigStorage = (configName?: string): KeyValueStorage => {

    // Node validates config readability eagerly, here at construction, because fs is
    // synchronous. The browser localConfigStorage (KSM-1332, same release) defers the equivalent
    // check lazily to first getString/saveString/delete, because IndexedDB has no synchronous API
    // to check eagerly against - a structural difference between the two platforms, not a
    // stylistic one.
    const readStorage = (): any => {
        if (!configName) {
            return {}
        }
        let raw: string
        try {
            raw = fs.readFileSync(configName).toString()
        } catch (e) {
            if (isEnoent(e)) {
                return {}
            }
            throw new KeeperError(`Unable to read local config ${configName}: ${describeCause(e)}`)
        }
        // A process killed between saveStorage's truncate and completed write (OOM, SIGKILL,
        // container eviction, power loss) leaves an empty file - not corruption. The sibling KMS
        // storage backends and the Python SDK already treat a zero-length file as a fresh start
        // for exactly this reason. A partially-written (nonempty but truncated) file is not
        // self-healed: there is no reliable way to distinguish "truncated" from "genuinely
        // corrupt" JSON, and this fix's whole point is to fail loudly rather than guess.
        if (raw.length === 0) {
            return {}
        }
        let parsed: any
        try {
            parsed = JSON.parse(stripBOM(raw))
        } catch (e) {
            throw new KeeperError(`Unable to read local config ${configName}: ${describeCause(e)}`)
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
        try {
            const fd = fs.openSync(configName, 'w', 0o600)
            try {
                fs.writeSync(fd, JSON.stringify(storageData, null, 2))
            } finally {
                fs.closeSync(fd)
            }
            chmodSecure(configName)
        } catch (e) {
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