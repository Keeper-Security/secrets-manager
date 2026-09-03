import {nodePlatform} from '../src/node/nodePlatform'
import {createHmac} from 'crypto'
import {KeeperCryptoError} from '../src/errors'
import {KeyValueStorage} from '../src/platform'

test('hash produces different digests for different tags with the same data', async () => {
    const data = new TextEncoder().encode('client-key-bytes')
    const digestA = await nodePlatform.hash(data, 'TAG_A')
    const digestB = await nodePlatform.hash(data, 'TAG_B')
    expect(Buffer.from(digestA).equals(Buffer.from(digestB))).toBe(false)
})

test('hash matches an independently computed HMAC-SHA512 over data and tag', async () => {
    const data = new TextEncoder().encode('client-key-bytes')
    const tag = 'KEEPER_SECRETS_MANAGER_CLIENT_ID'
    const digest = await nodePlatform.hash(data, tag)
    const expected = createHmac('sha512', data).update(tag).digest()
    expect(Buffer.from(digest).equals(expected)).toBe(true)
})

// Minimal KeyValueStorage backed by plain Maps, so these tests can call nodePlatform's functions
// directly without depending on the module-level platform singleton (inMemoryStorage needs
// connectPlatform to have run first).
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

test('unwrap throws a KeeperCryptoError with failure "missing-key" when the unwrapping key is not in storage', async () => {
    const storage = makeStorage()
    const wrappedKeyBytes = new Uint8Array([1, 2, 3, 4]) // never reached; loadKey throws first
    const err = await nodePlatform
        .unwrap(wrappedKeyBytes, 'target-key-id', 'nonexistent-key-id', storage)
        .catch(e => e)
    expect(err).toBeInstanceOf(KeeperCryptoError)
    expect(err.failure).toBe('missing-key')
    expect(err.uid).toBe('nonexistent-key-id')
})

test('decrypt throws a KeeperCryptoError with failure "missing-key" when the key is not in storage', async () => {
    const storage = makeStorage()
    const data = new Uint8Array(28).fill(9) // never reached; loadKey throws first
    const err = await nodePlatform
        .decrypt(data, 'nonexistent-key-id-decrypt', storage)
        .catch(e => e)
    expect(err).toBeInstanceOf(KeeperCryptoError)
    expect(err.failure).toBe('missing-key')
    expect(err.uid).toBe('nonexistent-key-id-decrypt')
})

test('unwrap rejects an unwrapped key whose length is not 32 bytes', async () => {
    const wrappingKeyId = 'wrapping-key-id-length-check'
    const wrappingKey = new Uint8Array(32).fill(9)
    const storage = makeStorage()
    await storage.saveBytes(wrappingKeyId, wrappingKey)

    // A real GCM-wrapped 16-byte payload decrypts cleanly, so the failure asserted below is
    // purely the post-decrypt length check, not a decrypt error.
    const shortPayload = new Uint8Array(16).fill(7)
    const wrapped = await nodePlatform.encryptWithKey(shortPayload, wrappingKey)

    const err = await nodePlatform
        .unwrap(wrapped, 'short-key-id', wrappingKeyId, storage)
        .catch(e => e)
    expect(err.message).toMatch(/length/i)
    // Classifying format vs integrity happens at the keeper.ts call site, not in the platform,
    // so this stays a plain Error rather than a KeeperCryptoError.
    expect(err).not.toBeInstanceOf(KeeperCryptoError)
})

test('unwrap rejects a short unwrapped key even when the wrap used CBC', async () => {
    const wrappingKeyId = 'wrapping-key-id-cbc-length-check'
    const wrappingKey = new Uint8Array(32).fill(4)
    const storage = makeStorage()
    await storage.saveBytes(wrappingKeyId, wrappingKey)

    const shortPayload = new Uint8Array(16).fill(8)
    const wrapped = await nodePlatform.encryptWithKey(shortPayload, wrappingKey, true)

    await expect(
        nodePlatform.unwrap(wrapped, 'short-key-id-cbc', wrappingKeyId, storage, false, true)
    ).rejects.toThrow(/length/i)
})

test('unwrap accepts a 32-byte key, and the unwrapped key round-trips through encrypt/decrypt', async () => {
    const wrappingKeyId = 'wrapping-key-id-roundtrip'
    const wrappingKey = new Uint8Array(32).fill(3)
    const storage = makeStorage()
    await storage.saveBytes(wrappingKeyId, wrappingKey)

    const originalKey = new Uint8Array(32).fill(5)
    const wrapped = await nodePlatform.encryptWithKey(originalKey, wrappingKey)

    const unwrappedKeyId = 'unwrapped-key-id-roundtrip'
    await nodePlatform.unwrap(wrapped, unwrappedKeyId, wrappingKeyId, storage)

    const plaintext = new TextEncoder().encode('hello keeper')
    const encrypted = await nodePlatform.encrypt(plaintext, unwrappedKeyId, storage)
    const decrypted = await nodePlatform.decrypt(encrypted, unwrappedKeyId, storage)
    expect(new TextDecoder().decode(decrypted)).toBe('hello keeper')
})
