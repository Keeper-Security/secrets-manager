import {connectPlatform, platform, inMemoryStorage, TransmissionKey, EncryptedPayload} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'
import {cachingPostFunction} from '../src/node/localConfigStorage'
import {createCachingFunction} from '../src/browser/localConfigStorage'

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
})
