import {connectPlatform, inMemoryStorage, platform, KeyValueStorage, TransmissionKey, EncryptedPayload} from '../src/platform'
import {browserPlatform} from '../src/browser/browserPlatform'
import {createCachingFunction} from '../src/browser/localConfigStorage'
import {KeeperError} from '../src/errors'

connectPlatform(browserPlatform)

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
const originalPost = platform.post

afterEach(() => {
    platform.post = originalPost
})

describe('browser createCachingFunction (KSM-1265)', () => {
    test('round-trip: caches a successful response, then serves it when the network fails', async () => {
        const storage = await makeStorageWithAppKey()
        const responseData = enc.encode('{"ok":true}')
        const tk = fakeTransmissionKey()
        const caching = createCachingFunction(storage)

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

    test('rejects a tampered cached blob instead of returning a synthetic 200', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage)

        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        const raw = await storage.getBytes('cache')
        const tampered = new Uint8Array(raw!)
        tampered[tampered.length - 1] ^= 0xff
        await storage.saveBytes('cache', tampered)

        platform.post = async () => { throw networkFailure() }
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload)).rejects.toThrow()
    })

    test('rejects a cached blob older than maxCacheAgeMs', async () => {
        jest.useFakeTimers()
        try {
            const storage = await makeStorageWithAppKey()
            const caching = createCachingFunction(storage, 1000)

            platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
            await caching('https://example.com', fakeTransmissionKey(), fakePayload)

            jest.advanceTimersByTime(5000)

            platform.post = async () => { throw networkFailure() }
            await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload)).rejects.toThrow()
        } finally {
            jest.useRealTimers()
        }
    })

    test('treats an old-format (pre-fix, plaintext) cached value as a cache miss instead of misparsing it', async () => {
        const storage = await makeStorageWithAppKey()
        await storage.saveBytes('cache', new Uint8Array([...new Uint8Array(32).fill(1), ...enc.encode('legacy-plaintext-response')]))

        platform.post = async () => { throw networkFailure() }
        const caching = createCachingFunction(storage)
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload)).rejects.toThrow()
    })

    test('a cache write failure is swallowed so the caller still gets the successful response', async () => {
        const storage = await makeStorageWithAppKey()
        const originalSaveBytes = storage.saveBytes
        storage.saveBytes = async () => { throw new Error('storage quota exceeded') }
        const caching = createCachingFunction(storage)

        const responseData = enc.encode('{"ok":true}')
        platform.post = async () => ({ statusCode: 200, data: responseData, headers: [] })
        const result = await caching('https://example.com', fakeTransmissionKey(), fakePayload)
        expect(result.statusCode).toBe(200)
        expect(Buffer.from(result.data)).toEqual(Buffer.from(responseData))

        storage.saveBytes = originalSaveBytes
    })

    test('no appKey in storage: a successful response is not cached', async () => {
        const storage = inMemoryStorage({})
        const caching = createCachingFunction(storage)

        platform.post = async () => ({ statusCode: 200, data: enc.encode('{}'), headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        expect(await storage.getBytes('cache')).toBeUndefined()
    })

    test('no appKey in storage: the fallback path throws instead of serving a nonexistent cache', async () => {
        const storage = inMemoryStorage({})
        const caching = createCachingFunction(storage)

        platform.post = async () => { throw networkFailure() }
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
            .rejects.toBeInstanceOf(KeeperError)
    })

    test('storage.getBytes throwing on the success path is not misrouted into serving stale cached data', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCachingFunction(storage)

        const staleData = enc.encode('{"stale":true}')
        platform.post = async () => ({ statusCode: 200, data: staleData, headers: [] })
        await caching('https://example.com', fakeTransmissionKey(), fakePayload)

        const originalGetBytes = storage.getBytes
        let failNextAppKeyLookup = true
        storage.getBytes = async (key: string) => {
            if (key === 'appKey' && failNextAppKeyLookup) {
                failNextAppKeyLookup = false
                throw new Error('storage backend unavailable')
            }
            return originalGetBytes(key)
        }
        try {
            const freshData = enc.encode('{"fresh":true}')
            platform.post = async () => ({ statusCode: 200, data: freshData, headers: [] })
            const result = await caching('https://example.com', fakeTransmissionKey(), fakePayload)
            expect(result.statusCode).toBe(200)
            expect(Buffer.from(result.data)).toEqual(Buffer.from(freshData))
        } finally {
            storage.getBytes = originalGetBytes
        }
    })

    test('a CryptoKey appKey (useObjects: true) degrades caching to a no-op instead of throwing', async () => {
        const storage = inMemoryStorage({})
        const cryptoKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt', 'unwrapKey'])
        // A non-empty 'cache' entry too, so the fallback path actually reaches deriveCacheKey(appKey)
        // instead of short-circuiting earlier on a missing cache entry - which would pass on both
        // fixed and unfixed code for the wrong reason.
        storage.getBytes = async (key: string) => {
            if (key === 'appKey') return cryptoKey as unknown as Uint8Array
            if (key === 'cache') return new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
            return undefined
        }
        const saveBytesSpy = jest.fn()
        storage.saveBytes = saveBytesSpy
        const caching = createCachingFunction(storage)

        // Confirms the no-op is signaled, not silent: before this fix, a caller who opted into
        // useObjects: true had no way to know caching was doing nothing for them until their
        // first real outage hit the exact-message assertion below.
        const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
        platform.post = async () => ({ statusCode: 200, data: enc.encode('{"ok":true}'), headers: [] })
        const first = await caching('https://example.com', fakeTransmissionKey(), fakePayload)
        expect(first.statusCode).toBe(200)
        expect(saveBytesSpy).not.toHaveBeenCalled()
        expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('useObjects: true'))
        consoleErrorSpy.mockRestore()

        platform.post = async () => { throw networkFailure() }
        // Exact message, not just KeeperError: pre-fix code also throws a KeeperError here, but
        // a confusing one ("Cached value is invalid: Failed to execute 'importKey'...") leaking
        // the underlying crypto TypeError instead of the clean "no cache available" message this
        // fix produces.
        await expect(caching('https://example.com', fakeTransmissionKey(), fakePayload))
            .rejects.toThrow('Cached value does not exist')
    })
})
