import {connectPlatform, platform, inMemoryStorage, TransmissionKey, EncryptedPayload, KeyValueStorage} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'
import {createCachingFunction as createCachingFunctionNode} from '../src/node/localConfigStorage'
import {createCachingFunction} from '../src/browser/localConfigStorage'
import {timeoutError} from '../src/deadline'
import {KeeperError} from '../src/errors'
import {registerCacheRequest} from '../src/cache'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'

connectPlatform(nodePlatform)

// An explicit cachePath keeps these tests off the real default (~/.keeper/ksm-cache.dat) -
// without it, writeCacheFile's mkdirSync(dir, ...) call runs against the real home directory
// before the mocked fs.openSync below ever gets a chance to reject the write.
const nodeTestCachePath = path.join(os.tmpdir(), 'ksm-caching-functions-test-cache.dat')

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
    ['createCachingFunction (node)', () => createCachingFunctionNode(inMemoryStorage({}), {cachePath: nodeTestCachePath})],
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

    test('returns the transport error for a request without cache scope', async () => {
        const error = Object.assign(new Error('Connection reset'), {code: 'ECONNRESET'})
        platform.post = async () => { throw error }
        await expect(build()('https://example.com', transmissionKey(), payload())).rejects.toBe(error)
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

const writeReadReply = async (query: ReturnType<typeof createCachingFunction>, storage: KeyValueStorage) => {
    const url = 'https://example.com/api/rest/sm/v1/get_secret'
    const key = transmissionKey()
    const encrypted = payload()
    const clientPublicKey = new Uint8Array(65)
    clientPublicKey[0] = 4
    const cache = registerCacheRequest(encrypted, {
        storage, url, requestBody: '{"clientId":"test"}', transmissionKey: key, serverPublicKey: new Uint8Array([1]),
        clientPublicKey
    })
    const response = await query(url, key, encrypted)
    expect(cache.write).toBeDefined()
    await cache.write!(response, response.data, JSON.parse(platform.bytesToString(response.data)))
    return response
}

test('createCachingFunction (node) still returns the fresh response when the cache write fails', async () => {
    const originalPost = platform.post
    const freshData = platform.stringToBytes('{"records":[]}')
    platform.post = (async () => ({statusCode: 200, headers: [], data: freshData})) as typeof platform.post
    const storage = inMemoryStorage({})
    await storage.saveBytes('appKey', new Uint8Array(32))
    const openSyncSpy = jest.spyOn(fs, 'openSync').mockImplementation(() => { throw new Error('ENOSPC') })
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
    try {
        const result = await writeReadReply(createCachingFunctionNode(storage, {cachePath: nodeTestCachePath}), storage)
        expect(result.statusCode).toBe(200)
        expect(result.data).toBe(freshData)
        // Proves the write was actually attempted (and failed) rather than skipped - without
        // this, a missing appKey would make the test pass for the wrong reason.
        expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('Failed to update cached response'))
    } finally {
        openSyncSpy.mockRestore()
        consoleErrorSpy.mockRestore()
        platform.post = originalPost
    }
})

test('createCachingFunction still returns the fresh response when the cache write fails', async () => {
    const originalPost = platform.post
    const freshData = platform.stringToBytes('{"records":[]}')
    platform.post = (async () => ({statusCode: 200, headers: [], data: freshData})) as typeof platform.post
    // appKey must be seeded through the base storage's own saveBytes before overriding it below -
    // the override throws unconditionally, and without a raw-bytes appKey present,
    // createCachingFunction skips the write entirely, so this test would pass without ever
    // exercising the write-failure path it's named for.
    const baseStorage = inMemoryStorage({})
    await baseStorage.saveBytes('appKey', new Uint8Array(32))
    const storage = {...baseStorage, saveBytes: async () => { throw new Error('quota exceeded') }}
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
    try {
        const result = await writeReadReply(createCachingFunction(storage), storage)
        expect(result.statusCode).toBe(200)
        expect(result.data).toBe(freshData)
        expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('Failed to update cached response'))
    } finally {
        consoleErrorSpy.mockRestore()
        platform.post = originalPost
    }
})
