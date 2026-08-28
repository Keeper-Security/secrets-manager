import {browserPlatform} from '../src/browser/browserPlatform'
import {KeeperCryptoError, KeeperError} from '../src/errors'
import {KeyValueStorage} from '../src/platform'
import {DEFAULT_REQUEST_TIMEOUT_MS} from '../src/deadline'

describe('crypto failure classification', () => {

// These tests exercise browserPlatform directly against Node's real, built-in WebCrypto
// (crypto.subtle), which is a genuine, accurate stand-in for a browser's implementation - no
// jsdom or mock browser required (Node >=20, this package's engines requirement).

// Minimal KeyValueStorage backed by plain Maps, so these tests can call browserPlatform's
// functions directly without depending on the module-level platform singleton (inMemoryStorage
// needs connectPlatform to have run first). Deliberately has no getObject/saveObject, so loadKey
// and loadPrivateKey exercise the getBytes/raw-import path rather than the object-storage path.
const makeStorage = (initial: Record<string, Uint8Array> = {}): KeyValueStorage => {
    const bytes = new Map<string, Uint8Array>(Object.entries(initial))
    const strings = new Map<string, string>()
    return {
        getString: async key => strings.get(key),
        saveString: async (key, value) => {
            strings.set(key, value)
        },
        getBytes: async key => bytes.get(key),
        saveBytes: async (key, value) => {
            bytes.set(key, value)
        },
        delete: async key => {
            bytes.delete(key)
            strings.delete(key)
        },
    }
}

// browserPlatform's key cache is a module-level singleton (see keyCache in browserPlatform.ts).
// unwrap()'s wrapping-key handling special-cases the literal id "appKey" (it forces that key to
// load as AES-GCM regardless of useCBC), so several tests below must reuse that exact string as
// the wrapping key id. Clearing the cache before each test keeps them independent of run order.
beforeEach(() => {
    browserPlatform.cleanKeyCache()
})

test('unwrap throws a KeeperCryptoError with failure "missing-key" when the wrapping key (appKey) is not in storage', async () => {
    const storage = makeStorage()
    const wrappedFolderKey = new Uint8Array(28).fill(9) // never reached; loadKey throws first
    const err = await browserPlatform
        .unwrap(wrappedFolderKey, 'folder-uid-missing-appkey', 'appKey', storage, true, true)
        .catch(e => e)
    expect(err).toBeInstanceOf(KeeperCryptoError)
    expect(err.failure).toBe('missing-key')
    expect(err.uid).toBe('appKey')
})

test('unwrap reports the clean wrapping-key id, not the internal "cbc:" cache key, when a CBC-mode wrapping key is missing', async () => {
    const storage = makeStorage()
    const wrappedFolderKey = new Uint8Array(28).fill(9) // never reached; loadKey throws first
    // Mirrors the nested-folder call shape (unwrappingKeyId is the shared folder's uid, not
    // "appKey"), so useCBC=true really does make loadKey look up the "cbc:"-prefixed cache key.
    const err = await browserPlatform
        .unwrap(wrappedFolderKey, 'folder-uid-nested-missing', 'shared-folder-uid-missing', storage, true, true)
        .catch(e => e)
    expect(err).toBeInstanceOf(KeeperCryptoError)
    expect(err.failure).toBe('missing-key')
    // The lookup itself used the "cbc:"-prefixed cache key internally (see loadKey in
    // browserPlatform.ts), but the reported uid must be the caller-facing id, not that detail.
    expect(err.uid).toBe('shared-folder-uid-missing')
})

test('decrypt reports the clean keyId, not the internal "cbc:" cache key, for a folder key that was never unwrapped', async () => {
    const storage = makeStorage()
    const data = new Uint8Array(28).fill(9) // never reached; loadKey throws first
    const err = await browserPlatform
        .decrypt(data, 'never-unwrapped-folder-uid', storage, true)
        .catch(e => e)
    expect(err).toBeInstanceOf(KeeperCryptoError)
    expect(err.failure).toBe('missing-key')
    expect(err.uid).toBe('never-unwrapped-folder-uid')
})

test('sign throws a KeeperCryptoError with failure "missing-key" when the private key is not in storage (loadPrivateKey)', async () => {
    const storage = makeStorage()
    const data = new TextEncoder().encode('data to sign')
    const err = await browserPlatform
        .sign(data, 'device-private-key-missing', storage)
        .catch(e => e)
    expect(err).toBeInstanceOf(KeeperCryptoError)
    expect(err.failure).toBe('missing-key')
    expect(err.uid).toBe('device-private-key-missing')
})

test('unwrap still throws for a structurally too-short wrapped-key ciphertext, and it is not a KeeperCryptoError', async () => {
    const storage = makeStorage({appKey: new Uint8Array(32).fill(2)})
    // A 16-byte wrapped value is 12 bytes of IV plus only 4 bytes of "ciphertext", well under
    // AES-GCM's 16-byte authentication tag, so crypto.subtle.unwrapKey rejects it outright. This
    // pins the native length enforcement WebCrypto already provided before this fix; unlike a
    // missing key or a bad CBC padding, this is not one of the classified failure reasons.
    const tooShortWrappedKey = new Uint8Array(16).fill(9)
    const promise = browserPlatform.unwrap(tooShortWrappedKey, 'folder-uid-too-short', 'appKey', storage, true, true)
    await expect(promise).rejects.toThrow()
    await expect(promise).rejects.not.toBeInstanceOf(KeeperCryptoError)
})

test('unwrap rejects an unwrapped key whose length is not 32 bytes, even though WebCrypto itself accepts it', async () => {
    const appKeyBytes = new Uint8Array(32).fill(2)
    const storage = makeStorage({appKey: appKeyBytes})

    // A 16-byte payload is itself a structurally valid AES-128 key, so - unlike the
    // "structurally too short" case above - crypto.subtle.unwrapKey does NOT reject this on its
    // own (confirmed directly against Node's real WebCrypto: it returns a CryptoKey with
    // algorithm {name:'AES-GCM', length:128}, no error). Only this SDK's explicit AES-256 length
    // check (assertUnwrappedKeyLength in browserPlatform.ts) catches it.
    const shortPayload = new Uint8Array(16).fill(7)
    const wrapped = await browserPlatform.encryptWithKey(shortPayload, appKeyBytes)

    const err = await browserPlatform
        .unwrap(wrapped, 'folder-uid-short-unwrapped', 'appKey', storage, true, true)
        .catch(e => e)
    expect(err.message).toMatch(/length/i)
    // Classifying format vs integrity happens at the keeper.ts call site, not in the platform,
    // so this stays a plain Error rather than a KeeperCryptoError (matches nodePlatform's
    // equivalent check).
    expect(err).not.toBeInstanceOf(KeeperCryptoError)
})

test('unwrap with useCBC=true caches both a GCM and a CBC key for the same keyId (appKey-wrapped folder key needs both)', async () => {
    const appKeyBytes = new Uint8Array(32).fill(2)
    const folderKeyBytes = new Uint8Array(32).fill(3)
    const storage = makeStorage({appKey: appKeyBytes})

    // The vault always wraps a top-level folder's key in GCM under the app key.
    const wrappedFolderKey = await browserPlatform.encryptWithKey(folderKeyBytes, appKeyBytes)

    // Exact 6-argument shape keeper.ts uses at the appKey-wrapped (top-level folder) call site:
    // unwrappingKeyId is the literal "appKey", memoryOnly=true, useCBC=true. useCBC=true here is
    // purely to populate the second (CBC) cache slot below - the wrapping-key load itself is
    // still forced to GCM internally because unwrappingKeyId is "appKey".
    await browserPlatform.unwrap(wrappedFolderKey, 'folder-uid-dual-cache', 'appKey', storage, true, true)

    // folder.data is always wrapped in CBC regardless of how the folder key itself was wrapped,
    // so decrypting it needs a CBC-mode CryptoKey cached under the same keyId as the GCM one.
    const gcmCiphertext = await browserPlatform.encryptWithKey(
        new TextEncoder().encode('gcm payload'), folderKeyBytes)
    const cbcCiphertext = await browserPlatform.encryptWithKey(
        new TextEncoder().encode('{"name":"Folder Data"}'), folderKeyBytes, true)

    const decryptedGcm = await browserPlatform.decrypt(gcmCiphertext, 'folder-uid-dual-cache', storage)
    const decryptedCbc = await browserPlatform.decrypt(cbcCiphertext, 'folder-uid-dual-cache', storage, true)

    expect(new TextDecoder().decode(decryptedGcm)).toBe('gcm payload')
    expect(new TextDecoder().decode(decryptedCbc)).toBe('{"name":"Folder Data"}')
})

test('unwrap without useCBC only caches the GCM key; the CBC slot for the same keyId stays missing', async () => {
    const appKeyBytes = new Uint8Array(32).fill(2)
    const folderKeyBytes = new Uint8Array(32).fill(6)
    const storage = makeStorage({appKey: appKeyBytes})

    const wrappedFolderKey = await browserPlatform.encryptWithKey(folderKeyBytes, appKeyBytes)

    // Same call shape as the test above, but useCBC omitted: the exact mistake that broke
    // browser-only folder decryption during implementation (see unwrap() in browserPlatform.ts).
    await browserPlatform.unwrap(wrappedFolderKey, 'folder-uid-gcm-only', 'appKey', storage, true)

    const gcmCiphertext = await browserPlatform.encryptWithKey(new TextEncoder().encode('ok'), folderKeyBytes)
    const decryptedGcm = await browserPlatform.decrypt(gcmCiphertext, 'folder-uid-gcm-only', storage)
    expect(new TextDecoder().decode(decryptedGcm)).toBe('ok')

    const cbcCiphertext = await browserPlatform.encryptWithKey(new TextEncoder().encode('{}'), folderKeyBytes, true)
    const err = await browserPlatform
        .decrypt(cbcCiphertext, 'folder-uid-gcm-only', storage, true)
        .catch(e => e)
    expect(err).toBeInstanceOf(KeeperCryptoError)
    expect(err.failure).toBe('missing-key')
})

})

describe('request timeout', () => {

const fetchMock = jest.fn()

beforeEach(() => {
    fetchMock.mockReset()
    fetchMock.mockResolvedValue({
        status: 200,
        headers: new Headers(),
        statusText: 'OK',
        arrayBuffer: async () => new ArrayBuffer(0)
    })
    global.fetch = fetchMock as unknown as typeof fetch
})

// fetch rejects an aborted request with a DOMException. Reproduce that so the platform's
// translation to KeeperError is what is under test, not the runtime's abort machinery.
const rejectsWhenAborted = () => fetchMock.mockImplementation((_url: string, init: RequestInit) =>
    new Promise((_resolve, reject) => {
        init.signal!.addEventListener('abort', () =>
            reject(new DOMException('This operation was aborted', 'AbortError')))
    }))

const calls: [string, (timeoutMs?: number) => Promise<unknown>][] = [
    ['get', t => browserPlatform.get('https://example.com', {}, t)],
    ['post', t => browserPlatform.post('https://example.com', new Uint8Array([1, 2, 3]), {}, false, t)],
    ['fileUpload', t => browserPlatform.fileUpload('https://example.com', {field: 'value'}, new Uint8Array([1, 2, 3]), t)]
]

describe.each(calls)('%s', (name, call) => {
    test('passes an AbortSignal to fetch', async () => {
        await call(5000)
        expect(fetchMock.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal)
    })

    test('still produces a signal when timeoutMs is omitted', async () => {
        await call()
        expect(fetchMock.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal)
    })

    // Node wraps its timeout in a KeeperError. Leaving the browser to surface a raw DOMException
    // means `catch (e) { if (e instanceof KeeperError) ... }` silently misses timeouts on one
    // platform.
    test('a fired deadline rejects with a KeeperError, not a DOMException', async () => {
        if (name === 'fileUpload') {
            jest.spyOn(console, 'error').mockImplementation(() => {})
        }
        jest.useFakeTimers()
        try {
            rejectsWhenAborted()
            const promise = call(5000)
            jest.advanceTimersByTime(5000)
            await expect(promise).rejects.toBeInstanceOf(KeeperError)
            await expect(promise).rejects.toThrow(/timed out after 5000ms/)
        } finally {
            jest.useRealTimers()
            jest.restoreAllMocks()
        }
    })

    test('a failure that is not a timeout is passed through untouched', async () => {
        if (name === 'fileUpload') {
            jest.spyOn(console, 'error').mockImplementation(() => {})
        }
        const networkError = new TypeError('Failed to fetch')
        fetchMock.mockRejectedValue(networkError)
        await expect(call(5000)).rejects.toBe(networkError)
        jest.restoreAllMocks()
    })

    test('an unusable timeoutMs is rejected before any request is made', async () => {
        await expect(call(0)).rejects.toBeInstanceOf(Error)
        await expect(call(0)).rejects.not.toBeInstanceOf(KeeperError)
        expect(fetchMock).not.toHaveBeenCalled()
    })

    // Every request arms a setTimeout. Failing to clear it on the way out leaves one pending timer
    // per call for up to the full timeout, which a mocked-fetch assertion would never notice.
    test('a settled request leaves no pending timer behind', async () => {
        if (name === 'fileUpload') {
            jest.spyOn(console, 'error').mockImplementation(() => {})
        }
        jest.useFakeTimers()
        try {
            expect(jest.getTimerCount()).toBe(0)
            await call(5000)
            expect(jest.getTimerCount()).toBe(0)

            fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
            await expect(call(5000)).rejects.toBeInstanceOf(TypeError)
            expect(jest.getTimerCount()).toBe(0)
        } finally {
            jest.useRealTimers()
            jest.restoreAllMocks()
        }
    })
})

test('the default deadline is the shared default', async () => {
    jest.useFakeTimers()
    try {
        rejectsWhenAborted()
        const promise = browserPlatform.get('https://example.com', {}).catch(e => e)
        jest.advanceTimersByTime(DEFAULT_REQUEST_TIMEOUT_MS - 1)
        jest.advanceTimersByTime(1)
        await expect(promise).resolves.toThrow(new RegExp(`timed out after ${DEFAULT_REQUEST_TIMEOUT_MS}ms`))
    } finally {
        jest.useRealTimers()
    }
})

test('omitting timeoutMs aborts the deadline signal at DEFAULT_REQUEST_TIMEOUT_MS, not before', () => {
    jest.useFakeTimers()
    try {
        // Fire-and-forget rather than awaiting: get() clears its deadline timer once fetchMock's
        // already-resolved promise settles, which would erase the signal state this test needs
        // to observe. Staying synchronous keeps that resolution's microtask from running before
        // the assertions below do.
        void browserPlatform.get('https://example.com', {}).catch(() => {})
        const init = fetchMock.mock.calls[0][1]
        expect(init.signal.aborted).toBe(false)
        jest.advanceTimersByTime(DEFAULT_REQUEST_TIMEOUT_MS - 1)
        expect(init.signal.aborted).toBe(false)
        jest.advanceTimersByTime(1)
        expect(init.signal.aborted).toBe(true)
    } finally {
        jest.useRealTimers()
    }
})

})
