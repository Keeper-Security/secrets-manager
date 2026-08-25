import {EncryptedPayload, KeeperHttpResponse, KeyValueStorage, platform, TransmissionKey, inMemoryStorage} from "../platform";
import {KeeperError} from "../errors";
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// Duplicated from keeper.ts's private KEY_APP_KEY - not exported there, so the literal is repeated here.
const KEY_APP_KEY = 'appKey'
const CACHE_KEY_LABEL = Buffer.from('KSM-cache-v1')
const CACHE_FORMAT_VERSION = 0x02
const DEFAULT_CACHE_PATH = path.join(os.homedir(), '.keeper', 'ksm-cache.dat')
const DEFAULT_MAX_CACHE_AGE_MS = 24 * 60 * 60 * 1000

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
        } catch (e: Error | any) {
            if (e.code === 'ENOENT') {
                return {}
            }
            throw new KeeperError(`Unable to read local config ${configName}: ${e.message}`)
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

const deriveCacheKey = (appKey: Uint8Array): Promise<Uint8Array> =>
    platform.getHmacDigest('SHA256', appKey, CACHE_KEY_LABEL)

const writeCacheFile = async (cachePath: string, cacheKey: Uint8Array, plaintext: Uint8Array): Promise<void> => {
    fs.mkdirSync(path.dirname(cachePath), {recursive: true, mode: 0o700})
    const encrypted = await platform.encryptWithKey(plaintext, cacheKey)
    const header = Buffer.alloc(9)
    header.writeUInt8(CACHE_FORMAT_VERSION, 0)
    header.writeBigUInt64BE(BigInt(Date.now()), 1)
    const fd = fs.openSync(cachePath, 'w', 0o600)
    try {
        fs.writeSync(fd, Buffer.concat([header, encrypted]))
    } finally {
        fs.closeSync(fd)
    }
    chmodSecure(cachePath)
}

const readCacheFile = async (cachePath: string, cacheKey: Uint8Array, maxCacheAgeMs: number): Promise<Uint8Array> => {
    let raw: Buffer
    try {
        raw = fs.readFileSync(cachePath)
    } catch (e: Error | any) {
        if (e.code === 'ENOENT') {
            throw new KeeperError('Cached value does not exist')
        }
        throw new KeeperError(`Unable to read cache file ${cachePath}: ${e.message}`)
    }
    if (raw.length < 9 || raw[0] !== CACHE_FORMAT_VERSION) {
        throw new KeeperError(`Cache file ${cachePath} is not in a recognized format`)
    }
    const timestamp = Number(raw.readBigUInt64BE(1))
    if (Date.now() - timestamp > maxCacheAgeMs) {
        throw new KeeperError(`Cached value at ${cachePath} is stale (age exceeds ${maxCacheAgeMs}ms)`)
    }
    try {
        return await platform.decryptWithKey(raw.subarray(9), cacheKey)
    } catch (e: Error | any) {
        throw new KeeperError(`Cache file ${cachePath} failed integrity check: ${e.message}`)
    }
}

// Node counterpart to browser/localConfigStorage.ts's createCachingFunction - same factory shape
// on both platforms. Replaces the old standalone cachingPostFunction, which kept the AES key in
// plaintext beside the ciphertext it protected, in a fixed CWD-relative file, with no integrity
// check on restore. Fixing all three requires access to the config (to derive a cache key that
// isn't the transmission key itself) and a chosen cache location, so the factory shape - not the
// old zero-argument function - is what the fix needs.
export const createCachingFunction = (
    storage: KeyValueStorage,
    cachePath: string = DEFAULT_CACHE_PATH,
    maxCacheAgeMs: number = DEFAULT_MAX_CACHE_AGE_MS
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
            const appKey = await storage.getBytes(KEY_APP_KEY)
            if (!appKey) {
                throw new KeeperError('Cached value does not exist')
            }
            const cachedData = await readCacheFile(cachePath, await deriveCacheKey(appKey), maxCacheAgeMs)
            transmissionKey.key = cachedData.slice(0, 32)
            return {
                statusCode: 200,
                data: cachedData.slice(32),
                headers: []
            }
        }
        if (response.statusCode == 200) {
            const appKey = await storage.getBytes(KEY_APP_KEY)
            if (appKey) {
                await writeCacheFile(cachePath, await deriveCacheKey(appKey), Buffer.concat([transmissionKey.key, response.data]))
            }
        }
        return response
    }
