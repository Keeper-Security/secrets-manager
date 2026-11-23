import {connectPlatform, inMemoryStorage, platform, KeyValueStorage, TransmissionKey} from '../src/platform'
import {browserPlatform} from '../src/browser/browserPlatform'
import {createCachingFunction} from '../src/browser/localConfigStorage'
import {registerCacheRequest} from '../src/cache'
import {markBrowserCacheTransportFailure} from '../src/cacheTransport'

connectPlatform(browserPlatform)

const enc = new TextEncoder()
const cacheUrl = 'https://example.com/api/rest/sm/v1/get_secret'
const requestBody = '{"clientId":"test-client","clientVersion":"ms18.0.0"}'
const responseBody = enc.encode('{"records":[]}')
const nextResponseBody = enc.encode('{"records":[],"expiresOn":1}')
const serverPublicKey = new Uint8Array(65).fill(7)
const clientPublicKey = new Uint8Array(65)
clientPublicKey[0] = 4

const makeStorageWithAppKey = async (): Promise<KeyValueStorage> => {
    const storage = inMemoryStorage({clientId: 'test-client', hostname: 'example.com'})
    await storage.saveBytes('appKey', new Uint8Array(32).fill(7))
    return storage
}

const fakeTransmissionKey = (): TransmissionKey => ({
    publicKeyId: 7,
    key: platform.getRandomBytes(32),
    encryptedKey: new Uint8Array(),
})

const createCacheQuery = (storage: KeyValueStorage, maxCacheAgeMs?: number) => {
    const query = createCachingFunction(storage, maxCacheAgeMs)
    return async (transmissionKey = fakeTransmissionKey()): Promise<Uint8Array> => {
        const payload = { payload: new Uint8Array(), signature: new Uint8Array() }
        const ctx = registerCacheRequest(payload, {
            storage, url: cacheUrl, requestBody, transmissionKey, serverPublicKey,
            clientPublicKey
        })
        const response = await query(cacheUrl, transmissionKey, payload).catch(async (error: unknown) => {
            const cached = await ctx.read?.(error)
            if (cached === undefined) throw error
            return cached
        })
        if (response instanceof Uint8Array) return response
        await ctx.write?.(response, response.data, JSON.parse(platform.bytesToString(response.data)))
        return response.data
    }
}

const mockNetworkFailure = () => {
    const error = new TypeError('Failed to fetch')
    markBrowserCacheTransportFailure(error)
    platform.post = async () => { throw error }
    return error
}

const originalPost = platform.post

afterEach(() => {
    platform.post = originalPost
})

describe('browser createCachingFunction', () => {
    test('returns the cached reply after a network error without changing the transmission key', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCacheQuery(storage)

        platform.post = async () => ({ statusCode: 200, data: responseBody, headers: [] })
        await expect(caching()).resolves.toEqual(responseBody)
        expect((await storage.getBytes('cache'))?.[0]).toBe(0x03)

        mockNetworkFailure()
        const transmissionKey = fakeTransmissionKey()
        const originalKey = transmissionKey.key.slice()
        await expect(caching(transmissionKey)).resolves.toEqual(responseBody)
        expect(transmissionKey.key).toEqual(originalKey)
    })

    test('keeps the network error when the cache entry fails authentication', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCacheQuery(storage)

        platform.post = async () => ({ statusCode: 200, data: responseBody, headers: [] })
        await caching()

        const raw = await storage.getBytes('cache')
        const tampered = new Uint8Array(raw!)
        tampered[tampered.length - 1] ^= 0xff
        await storage.saveBytes('cache', tampered)

        const error = mockNetworkFailure()
        await expect(caching()).rejects.toBe(error)
    })

    test('rejects a cached blob older than maxCacheAgeMs', async () => {
        jest.useFakeTimers()
        try {
            const storage = await makeStorageWithAppKey()
            const caching = createCacheQuery(storage, 1000)

            platform.post = async () => ({ statusCode: 200, data: responseBody, headers: [] })
            await caching()

            jest.advanceTimersByTime(5000)

            const error = mockNetworkFailure()
            await expect(caching()).rejects.toBe(error)
        } finally {
            jest.useRealTimers()
        }
    })

    test.each([0x01, 0x02])('ignores a cache entry with legacy version byte %i', async version => {
        const storage = await makeStorageWithAppKey()
        await storage.saveBytes('cache', new Uint8Array(64).fill(version))

        const error = mockNetworkFailure()
        const caching = createCacheQuery(storage)
        await expect(caching()).rejects.toBe(error)
    })

    test('returns the live reply when the cache write fails', async () => {
        const storage = await makeStorageWithAppKey()
        const saveBytes = jest.spyOn(storage, 'saveBytes').mockRejectedValue(new Error('Storage quota exceeded'))
        const caching = createCacheQuery(storage)

        platform.post = async () => ({ statusCode: 200, data: responseBody, headers: [] })
        await expect(caching()).resolves.toEqual(responseBody)
        expect(saveBytes).toHaveBeenCalledWith('cache', expect.any(Uint8Array))
        expect(await storage.getBytes('cache')).toBeUndefined()
    })

    test('does not store a cache entry without appKey', async () => {
        const storage = inMemoryStorage({clientId: 'test-client', hostname: 'example.com'})
        const caching = createCacheQuery(storage)

        platform.post = async () => ({ statusCode: 200, data: responseBody, headers: [] })
        await caching()

        expect(await storage.getBytes('cache')).toBeUndefined()
    })

    test('keeps the network error without appKey', async () => {
        const storage = inMemoryStorage({clientId: 'test-client', hostname: 'example.com'})
        const caching = createCacheQuery(storage)

        const error = mockNetworkFailure()
        await expect(caching()).rejects.toBe(error)
    })

    test('returns the live reply when storage.getBytes fails during a cache write', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCacheQuery(storage)

        platform.post = async () => ({ statusCode: 200, data: responseBody, headers: [] })
        await caching()
        const cacheEntry = await storage.getBytes('cache')
        expect(cacheEntry).toBeDefined()

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
            platform.post = async () => ({ statusCode: 200, data: nextResponseBody, headers: [] })
            await expect(caching()).resolves.toEqual(nextResponseBody)
            expect(await storage.getBytes('cache')).toEqual(cacheEntry)
        } finally {
            storage.getBytes = originalGetBytes
        }
    })

    test('does not use the cache when appKey is a CryptoKey', async () => {
        const storage = await makeStorageWithAppKey()
        const caching = createCacheQuery(storage)
        platform.post = async () => ({ statusCode: 200, data: responseBody, headers: [] })
        await caching()
        expect(await storage.getBytes('cache')).toBeDefined()

        const cryptoKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt', 'unwrapKey'])
        const originalGetBytes = storage.getBytes
        storage.getBytes = async (key: string) => {
            if (key === 'appKey') return cryptoKey as unknown as Uint8Array
            return originalGetBytes(key)
        }
        const saveBytes = jest.spyOn(storage, 'saveBytes')
        await expect(caching()).resolves.toEqual(responseBody)
        expect(saveBytes).not.toHaveBeenCalled()

        const error = mockNetworkFailure()
        await expect(caching()).rejects.toBe(error)
    })
})
