import {connectPlatform, platform, inMemoryStorage, TransmissionKey, EncryptedPayload} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'
import {cachingPostFunction} from '../src/node/localConfigStorage'
import {createCachingFunction} from '../src/browser/localConfigStorage'
import {timeoutError} from '../src/deadline'
import {KeeperError} from '../src/errors'
import * as fs from 'fs'

connectPlatform(nodePlatform)

const transmissionKey = (): TransmissionKey => ({
    publicKeyId: 7,
    key: new Uint8Array(32),
    encryptedKey: new Uint8Array([9, 9, 9])
})

const payload = (): EncryptedPayload => ({
    payload: new Uint8Array([1, 2, 3]),
    signature: new Uint8Array([4, 5, 6])
})

// The offline-cache helpers stand in for the default query function, so they have to accept and
// forward everything SecretManagerOptions.queryFunction is handed. Dropping the trailing arguments
// silently pins every cached-mode consumer to the default timeout.
describe.each([
    ['cachingPostFunction (node)', () => cachingPostFunction],
    ['createCachingFunction (browser)', () => createCachingFunction(inMemoryStorage({}))]
])('%s', (_name, build) => {
    const savedPost = platform.post
    let seen: any[]

    beforeEach(() => {
        seen = []
        // A non-200 keeps the helper off its cache-writing path; the forwarded arguments are what
        // is under test here, not the caching itself.
        platform.post = (async (...args: any[]) => {
            seen = args
            return {statusCode: 500, headers: [], data: new Uint8Array()}
        }) as typeof platform.post
    })

    afterEach(() => { platform.post = savedPost })

    test('forwards allowUnverifiedCertificate and timeoutMs to platform.post', async () => {
        await build()('https://example.com', transmissionKey(), payload(), true, 4321)
        expect(seen[3]).toBe(true)
        expect(seen[4]).toBe(4321)
    })

    test('passes them through as undefined when the caller omits them', async () => {
        await build()('https://example.com', transmissionKey(), payload())
        expect(seen[3]).toBeUndefined()
        expect(seen[4]).toBeUndefined()
    })

    test('a deliberate timeout propagates instead of being served as a fake success from cache', async () => {
        const timeout = timeoutError('https://example.com', 4321)
        platform.post = (async () => { throw timeout }) as typeof platform.post
        await expect(build()('https://example.com', transmissionKey(), payload())).rejects.toBe(timeout)
    })

    test('a non-timeout failure still falls back to cache', async () => {
        platform.post = (async () => { throw new Error('ECONNRESET') }) as typeof platform.post
        await expect(build()('https://example.com', transmissionKey(), payload())).rejects.toThrow('Cached value does not exist')
    })

    test('rejects an unusable timeoutMs before calling platform.post', async () => {
        let error: any
        try {
            await build()('https://example.com', transmissionKey(), payload(), false, 0)
        } catch (e) {
            error = e
        }
        expect(error).toBeInstanceOf(Error)
        expect(error).not.toBeInstanceOf(KeeperError)
        expect(error.message).toMatch(/at least 1/)
        expect(seen).toEqual([])
    })
})

test('timeoutError produces a KeeperError, distinct from a plain transport failure', () => {
    expect(timeoutError('https://example.com', 1)).toBeInstanceOf(KeeperError)
})

test('cachingPostFunction still returns the fresh response when the cache write fails', async () => {
    const originalPost = platform.post
    const freshData = new Uint8Array([1, 2, 3])
    platform.post = (async () => ({statusCode: 200, headers: [], data: freshData})) as typeof platform.post
    const openSyncSpy = jest.spyOn(fs, 'openSync').mockImplementation(() => { throw new Error('ENOSPC') })
    try {
        const result = await cachingPostFunction('https://example.com', transmissionKey(), payload())
        expect(result.statusCode).toBe(200)
        expect(result.data).toBe(freshData)
    } finally {
        openSyncSpy.mockRestore()
        platform.post = originalPost
    }
})

test('createCachingFunction still returns the fresh response when the cache write fails', async () => {
    const originalPost = platform.post
    const freshData = new Uint8Array([1, 2, 3])
    platform.post = (async () => ({statusCode: 200, headers: [], data: freshData})) as typeof platform.post
    const storage = {...inMemoryStorage({}), saveBytes: async () => { throw new Error('quota exceeded') }}
    try {
        const result = await createCachingFunction(storage)('https://example.com', transmissionKey(), payload())
        expect(result.statusCode).toBe(200)
        expect(result.data).toBe(freshData)
    } finally {
        platform.post = originalPost
    }
})
