import {EncryptedPayload, KeeperHttpResponse, KeyValueStorage, platform, TransmissionKey, inMemoryStorage} from "../platform";
import {KeeperError} from "../errors";
import * as fs from 'fs';

// fs.openSync's mode argument is only honored when the file is created; it is a no-op on an
// existing file, so permissions must be re-asserted after every write, not just the first one.
const chmodSecure = (filePath: string) => fs.chmodSync(filePath, 0o600)

export const localConfigStorage = (configName?: string): KeyValueStorage => {

    const readStorage = (): any => {
        if (!configName) {
            return {}
        }
        try {
            return JSON.parse(fs.readFileSync(configName).toString())
        } catch (e) {
            return {}
        }
    }

    const storageData = readStorage()
    const storage: KeyValueStorage = inMemoryStorage(storageData)

    const saveStorage = (storage: any) => {
        if (!configName) {
            return
        }
        const fd = fs.openSync(configName, 'w', 0o600)
        try {
            fs.writeSync(fd, JSON.stringify(storageData, null, 2))
        } finally {
            fs.closeSync(fd)
        }
        chmodSecure(configName)
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

// Signature matches SecretManagerOptions.queryFunction so the trailing options, including
// requestTimeoutMs, reach platform.post instead of being dropped on the floor.
export const cachingPostFunction = async (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload, allowUnverifiedCertificate?: boolean, timeoutMs?: number): Promise<KeeperHttpResponse> => {
    try {
        const response = await platform.post(url, payload.payload, {
            PublicKeyId: transmissionKey.publicKeyId.toString(),
            TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
            Authorization: `Signature ${platform.bytesToBase64(payload.signature)}`
        }, allowUnverifiedCertificate, timeoutMs)
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
        // A deliberate client-side timeout is not a transport failure: falling back to stale
        // cache here would silently turn a slow/hung request into a fake success instead of
        // surfacing it to the caller.
        if (e instanceof KeeperError) {
            throw e
        }
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