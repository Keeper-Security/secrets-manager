import {
    createCachingFunction,
    inMemoryStorage,
    localConfigStorage,
    platform,
    KeeperError,
    KeyValueStorage,
    TransmissionKey,
    EncryptedPayload,
} from '../'

import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'

const enc = new TextEncoder()

const makeStorageWithAppKey = async (): Promise<KeyValueStorage> => {
    const storage = inMemoryStorage({})
    await storage.saveBytes('appKey', new Uint8Array(32).fill(7))
    return storage
}

const fakeTransmissionKey = (): TransmissionKey => ({
    publicKeyId: 7,
    key: platform.getRandomBytes(32),
    encryptedKey: new Uint8Array(),
})

const fakePayload: EncryptedPayload = { payload: new Uint8Array(), signature: new Uint8Array() }
const networkFailure = () => Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })

let tmpDir: string
let cachePath: string
const originalPost = platform.post

beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ksm-cache-test-'))
    cachePath = path.join(tmpDir, 'cache.dat')
})

afterEach(() => {
    platform.post = originalPost
    fs.rmSync(tmpDir, { recursive: true, force: true })
})

describe('localConfigStorage file permissions (KSM-1263)', () => {
    test('re-asserts 0600 on save even if the file started more permissive', async () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, '{}')
        fs.chmodSync(configPath, 0o644)

        const kvs = localConfigStorage(configPath)
        await kvs.saveString('foo', 'bar')

        expect(fs.statSync(configPath).mode & 0o777).toBe(0o600)
    })
})

describe('localConfigStorage readStorage error handling (KSM-1266)', () => {
    test('a missing config file is a legitimate fresh start', () => {
        const configPath = path.join(tmpDir, 'does-not-exist.json')
        expect(() => localConfigStorage(configPath)).not.toThrow()
    })

    test('an unreadable config file throws KeeperError instead of silently starting fresh', () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, '{}')
        fs.chmodSync(configPath, 0o000)
        try {
            expect(() => localConfigStorage(configPath)).toThrow(KeeperError)
        } finally {
            fs.chmodSync(configPath, 0o600)
        }
    })

    test('malformed JSON throws KeeperError instead of silently starting fresh', () => {
        const configPath = path.join(tmpDir, 'config.json')
        fs.writeFileSync(configPath, 'not json{{{')
        expect(() => localConfigStorage(configPath)).toThrow(KeeperError)
    })
})

describe('createCachingFunction (KSM-1265)', () => {
    test('round-trip: caches a successful response, then serves it when the network fails', async () => {
        const storage = await makeStorageWithAppKey()
        const responseData = enc.encode('{"ok":true}')
        const tk = fakeTransmissionKey()
        const caching = createCachingFunction(storage, cachePath)

        platform.post = async () => ({ statusCode: 200, data: responseData, headers: [] })
        const first = await caching('https://example.com', tk, fakePayload)
        expect(first.statusCode).toBe(200)
        expect(Buffer.from(first.data)).toEqual(Buffer.from(responseData))

        platform.post = async () => { throw networkFailure() }
        const tk2 = fakeTransmissionKey()
        const second = await caching('https://example.com', tk2, fakePayload)
        expect(second.statusCode).toBe(200)
        expect(Buffer.from(second.data)).toEqual(Buffer.from(responseData))
        expect(Buffer.from(tk2.key)).toEqual(Buffer.from(tk.key))
    })

    test('rejects a tampered cache file instead of returning a synthetic 200', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, cachePath)

        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        const raw = fs.readFileSync(cachePath)
        raw[raw.length - 1] ^= 0xff
        fs.writeFileSync(cachePath, raw)

        platform.post = async () => { throw networkFailure() }
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
            .rejects.toBeInstanceOf(KeeperError)
    })

    test('rejects a cache file older than maxCacheAgeMs', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage, cachePath, 1000)

        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        const raw = fs.readFileSync(cachePath)
        raw.writeBigUInt64BE(BigInt(Date.now() - 5000), 1)
        fs.writeFileSync(cachePath, raw)

        platform.post = async () => { throw networkFailure() }
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
            .rejects.toBeInstanceOf(KeeperError)
    })

    test('rejects an old-format cache file instead of misparsing it', async () => {
        const storage = await makeStorageWithAppKey()
        fs.mkdirSync(path.dirname(cachePath), { recursive: true })
        fs.writeFileSync(cachePath, Buffer.concat([Buffer.alloc(32, 1), Buffer.from('legacy-plaintext-response')]))

        platform.post = async () => { throw networkFailure() }
        const caching = createCachingFunction(storage, cachePath)
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
            .rejects.toBeInstanceOf(KeeperError)
    })

    test('a write failure after a successful response propagates instead of being treated as a fallback trigger', async () => {
        const storage = await makeStorageWithAppKey()
        const blockerFile = path.join(tmpDir, 'blocker')
        fs.writeFileSync(blockerFile, '')
        const badCachePath = path.join(blockerFile, 'cache.dat')
        const caching = createCachingFunction(storage, badCachePath)

        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        const err = await caching('https://example.com', fakeTransmissionKey(), fakePayload).catch(e => e)
        // A real fs error propagating raw (not a KeeperError, not the fallback's "does not exist"
        // message) proves this took the write-failure path, not the cache-restore fallback path.
        expect(err).not.toBeInstanceOf(KeeperError)
        expect(err.message).not.toBe('Cached value does not exist')
    })
})
