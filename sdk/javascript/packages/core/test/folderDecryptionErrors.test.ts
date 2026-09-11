import {
    getFolders,
    initializeStorage,
    platform,
    inMemoryStorage,
    SecretManagerOptions,
    KeeperHttpResponse,
} from '../'

// Every AES key in this SDK (app key, folder keys, record keys, client key) is 32 raw bytes; a
// fixed Uint8Array(32).fill(N) is the existing convention for a deterministic fake key (see
// test/keeper.test.ts).
const TRANSMISSION_KEY = new Uint8Array(32).fill(1)
const APP_KEY = new Uint8Array(32).fill(2)

// Builds SecretManagerOptions wired to a fake encrypted server response containing the given raw
// (pre-encryption) folders, following test/keeper.test.ts's
// 'getFolders skips an undecryptable folder and returns the good one' construction exactly: pin
// platform.getRandomBytes to a fixed transmission key, encrypt the JSON response with that same
// key, stub queryFunction (not platform.post - postQuery reads options.queryFunction) to return
// it, initializeStorage with a fake one-time token, then save the app key directly into storage.
const setupFolders = async (rawFolders: any[]): Promise<SecretManagerOptions> => {
    const serverResponse = {
        folders: rawFolders,
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), TRANSMISSION_KEY)

    platform.getRandomBytes = () => TRANSMISSION_KEY
    const queryFn = (): Promise<KeeperHttpResponse> =>
        Promise.resolve({data: encryptedResponse, statusCode: 200, headers: []})

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, 'US:FAKE_CLIENT_KEY')
    await kvs.saveBytes('appKey', APP_KEY)

    return {storage: kvs, queryFunction: queryFn}
}

// folder.data is always wrapped in CBC by the vault regardless of which mode wrapped the folder
// key (see keeper.ts's fetchAndDecryptFolders), so every folder.data fixture below is CBC.
const encryptFolderData = (name: string, folderKey: Uint8Array): Promise<Uint8Array> =>
    platform.encryptWithKey(platform.stringToBytes(JSON.stringify({name})), folderKey, true)

// Flips the last byte of a wrapped-key ciphertext so an unwrap deterministically fails instead of
// relying on random tamper odds. Against a CBC wrap this breaks PKCS7 padding (padding lives
// entirely in the final ciphertext block, so a non-final-byte tamper leaves padding valid about
// half the time - only the final byte reliably breaks it). Against a GCM wrap the last byte falls
// inside the trailing authentication tag, so this also reliably fails the tag check.
const tamperLastByte = (bytes: Uint8Array): Uint8Array => {
    const tampered = new Uint8Array(bytes)
    tampered[tampered.length - 1] ^= 0xff
    return tampered
}

test('nested folder: tampering the last byte of its shared-folder-key-wrapped key is skipped with failure "format"', async () => {
    const sharedFolderUid = 'shared-folder-uid'
    const nestedFolderUid = 'nested-folder-uid'
    const sharedFolderKey = new Uint8Array(32).fill(10)
    const nestedFolderKey = new Uint8Array(32).fill(11)

    // Top-level (shared) folder: wrapped by appKey, GCM. Listed first so its key lands in the
    // platform's key cache before the nested folder below needs it as its wrapping key.
    const sharedFolderKeyWrapped = await platform.encryptWithKey(sharedFolderKey, APP_KEY)
    const sharedFolderData = await encryptFolderData('Shared Folder', sharedFolderKey)

    // Nested folder: wrapped by the shared folder's key, CBC - this is the real KSM-1267
    // exposure. Tamper the last byte so the unwrap deterministically fails.
    const nestedFolderKeyWrapped = await platform.encryptWithKey(nestedFolderKey, sharedFolderKey, true)
    const tamperedNestedFolderKeyWrapped = tamperLastByte(nestedFolderKeyWrapped)

    const options = await setupFolders([
        {
            folderUid: sharedFolderUid,
            folderKey: platform.bytesToBase64(sharedFolderKeyWrapped),
            data: platform.bytesToBase64(sharedFolderData)
        },
        {
            folderUid: nestedFolderUid,
            parent: sharedFolderUid,
            folderKey: platform.bytesToBase64(tamperedNestedFolderKeyWrapped),
            data: ''
        }
    ])

    const onDecryptionError = jest.fn()
    const folders = await getFolders({...options, onDecryptionError})

    expect(folders.length).toBe(1)
    expect(folders[0].folderUid).toBe(sharedFolderUid)
    expect(onDecryptionError).toHaveBeenCalledTimes(1)
    expect(onDecryptionError.mock.calls[0][0].uid).toBe(nestedFolderUid)
    expect(onDecryptionError.mock.calls[0][0].failure).toBe('format')
})

test('top-level folder: tampering the last byte of its appKey-wrapped key is skipped with failure "integrity"', async () => {
    const folderUid = 'top-folder-uid'
    const folderKey = new Uint8Array(32).fill(20)
    const wrapped = await platform.encryptWithKey(folderKey, APP_KEY)
    const tampered = tamperLastByte(wrapped)

    const options = await setupFolders([
        {folderUid, folderKey: platform.bytesToBase64(tampered), data: ''}
    ])

    const onDecryptionError = jest.fn()
    const folders = await getFolders({...options, onDecryptionError})

    expect(folders.length).toBe(0)
    expect(onDecryptionError).toHaveBeenCalledTimes(1)
    expect(onDecryptionError.mock.calls[0][0].uid).toBe(folderUid)
    expect(onDecryptionError.mock.calls[0][0].failure).toBe('integrity')
})

test('folder whose folderKey unwraps fine but whose decrypted data is not valid JSON is skipped with failure "malformed-data"', async () => {
    const folderUid = 'not-json-folder-uid'
    const folderKey = new Uint8Array(32).fill(30)
    const wrappedFolderKey = await platform.encryptWithKey(folderKey, APP_KEY)
    // A real key and real (CBC) ciphertext, so the unwrap and decrypt both succeed; the
    // recovered plaintext is simply not valid JSON.
    const notJsonData = await platform.encryptWithKey(platform.stringToBytes('not valid json at all'), folderKey, true)

    const options = await setupFolders([
        {folderUid, folderKey: platform.bytesToBase64(wrappedFolderKey), data: platform.bytesToBase64(notJsonData)}
    ])

    const onDecryptionError = jest.fn()
    const folders = await getFolders({...options, onDecryptionError})

    expect(folders.length).toBe(0)
    expect(onDecryptionError).toHaveBeenCalledTimes(1)
    expect(onDecryptionError.mock.calls[0][0].uid).toBe(folderUid)
    expect(onDecryptionError.mock.calls[0][0].failure).toBe('malformed-data')
})

test('folder whose decrypted data is valid JSON but not an object is skipped with failure "unknown"', async () => {
    // JSON.parse('null') succeeds (null is valid JSON), so the explicit malformed-data catch
    // around JSON.parse in fetchAndDecryptFolders never fires; the following property access
    // (parsedData['name']) then throws a plain TypeError reading a property off null, which is
    // not a KeeperCryptoError, so the catch block's fallback classification applies: failure
    // instanceof KeeperCryptoError ? e.failure : 'unknown'. This is the only reachable path that
    // ever produces the 'unknown' bucket, since every other throw in the try block is already an
    // explicit KeeperCryptoError (either from runCrypto or thrown directly).
    const folderUid = 'null-json-folder-uid'
    const folderKey = new Uint8Array(32).fill(31)
    const wrappedFolderKey = await platform.encryptWithKey(folderKey, APP_KEY)
    const nullJsonData = await platform.encryptWithKey(platform.stringToBytes('null'), folderKey, true)

    const options = await setupFolders([
        {folderUid, folderKey: platform.bytesToBase64(wrappedFolderKey), data: platform.bytesToBase64(nullJsonData)}
    ])

    const onDecryptionError = jest.fn()
    const folders = await getFolders({...options, onDecryptionError})

    expect(folders.length).toBe(0)
    expect(onDecryptionError).toHaveBeenCalledTimes(1)
    expect(onDecryptionError.mock.calls[0][0].uid).toBe(folderUid)
    expect(onDecryptionError.mock.calls[0][0].failure).toBe('unknown')
})

test('folder with an empty (falsy) folderKey is skipped with failure "missing-key"', async () => {
    const folderUid = 'empty-key-folder-uid'
    const options = await setupFolders([
        {folderUid, folderKey: '', data: ''}
    ])

    const onDecryptionError = jest.fn()
    const folders = await getFolders({...options, onDecryptionError})

    expect(folders.length).toBe(0)
    expect(onDecryptionError).toHaveBeenCalledTimes(1)
    expect(onDecryptionError.mock.calls[0][0].uid).toBe(folderUid)
    expect(onDecryptionError.mock.calls[0][0].failure).toBe('missing-key')
})

test('nested folder whose parent uid matches no folder in the response (orphaned) is skipped with failure "missing-key"', async () => {
    const folderUid = 'orphan-folder-uid'
    // Never read: getSharedFolderUid fails to resolve the parent before any unwrap is attempted,
    // so the wrapped-key bytes below do not matter, only that the field is truthy.
    const unusedWrappedKey = platform.bytesToBase64(new Uint8Array(48).fill(9))

    const options = await setupFolders([
        {folderUid, parent: 'no-such-parent-uid', folderKey: unusedWrappedKey, data: ''}
    ])

    const onDecryptionError = jest.fn()
    const folders = await getFolders({...options, onDecryptionError})

    expect(folders.length).toBe(0)
    expect(onDecryptionError).toHaveBeenCalledTimes(1)
    expect(onDecryptionError.mock.calls[0][0].uid).toBe(folderUid)
    expect(onDecryptionError.mock.calls[0][0].failure).toBe('missing-key')
})

test('onDecryptionError is called with the exact {uid, failure, message} shape once per skipped folder, for multiple simultaneous failures', async () => {
    const goodFolderUid = 'good-folder-uid-multi'
    const goodFolderKey = new Uint8Array(32).fill(50)
    const goodFolderKeyWrapped = await platform.encryptWithKey(goodFolderKey, APP_KEY)
    const goodFolderData = await encryptFolderData('Good Folder', goodFolderKey)

    const emptyKeyFolderUid = 'empty-key-folder-uid-multi'
    const orphanFolderUid = 'orphan-folder-uid-multi'
    const notJsonFolderUid = 'not-json-folder-uid-multi'
    const notJsonFolderKey = new Uint8Array(32).fill(51)
    const notJsonFolderKeyWrapped = await platform.encryptWithKey(notJsonFolderKey, APP_KEY)
    const notJsonData = await platform.encryptWithKey(platform.stringToBytes('not valid json at all'), notJsonFolderKey, true)

    const options = await setupFolders([
        {folderUid: goodFolderUid, folderKey: platform.bytesToBase64(goodFolderKeyWrapped), data: platform.bytesToBase64(goodFolderData)},
        {folderUid: emptyKeyFolderUid, folderKey: '', data: ''},
        {folderUid: orphanFolderUid, parent: 'no-such-parent-uid-multi', folderKey: platform.bytesToBase64(new Uint8Array(48).fill(9)), data: ''},
        {folderUid: notJsonFolderUid, folderKey: platform.bytesToBase64(notJsonFolderKeyWrapped), data: platform.bytesToBase64(notJsonData)}
    ])

    const onDecryptionError = jest.fn()
    const folders = await getFolders({...options, onDecryptionError})

    expect(folders.length).toBe(1)
    expect(folders[0].folderUid).toBe(goodFolderUid)

    expect(onDecryptionError).toHaveBeenCalledTimes(3)
    expect(onDecryptionError).toHaveBeenCalledWith({
        uid: emptyKeyFolderUid,
        failure: 'missing-key',
        message: `Folder key missing for UID ${emptyKeyFolderUid}`
    })
    expect(onDecryptionError).toHaveBeenCalledWith({
        uid: orphanFolderUid,
        failure: 'missing-key',
        message: `Folder data inconsistent - unable to locate shared folder for ${orphanFolderUid}`
    })
    expect(onDecryptionError).toHaveBeenCalledWith({
        uid: notJsonFolderUid,
        failure: 'malformed-data',
        message: `Folder ${notJsonFolderUid} decrypted data is not valid JSON`
    })
})

test('fail closed: getFolders rejects with the callback error when onDecryptionError throws', async () => {
    const folderUid = 'empty-key-folder-uid-failclosed'
    const options = await setupFolders([
        {folderUid, folderKey: '', data: ''}
    ])

    const distinctiveMessage = 'KSM-1267 fail-closed probe: onDecryptionError deliberately threw'
    const onDecryptionError = () => {
        throw new Error(distinctiveMessage)
    }

    await expect(getFolders({...options, onDecryptionError})).rejects.toThrow(distinctiveMessage)
})

test('backward compatibility: getFolders with no onDecryptionError set still resolves with just the good folder', async () => {
    const goodFolderUid = 'good-folder-uid-backcompat'
    const goodFolderKey = new Uint8Array(32).fill(60)
    const goodFolderKeyWrapped = await platform.encryptWithKey(goodFolderKey, APP_KEY)
    const goodFolderData = await encryptFolderData('Good Folder', goodFolderKey)
    const badFolderUid = 'bad-folder-uid-backcompat'

    const options = await setupFolders([
        {folderUid: goodFolderUid, folderKey: platform.bytesToBase64(goodFolderKeyWrapped), data: platform.bytesToBase64(goodFolderData)},
        {folderUid: badFolderUid, folderKey: '', data: ''}
    ])

    const folders = await getFolders(options)

    expect(folders.length).toBe(1)
    expect(folders[0].folderUid).toBe(goodFolderUid)
    expect(folders[0].name).toBe('Good Folder')
})

test('logs a partial-list summary line naming the skipped uid when 1 or more folders are skipped', async () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
    try {
        const goodFolderUid = 'good-folder-uid-summary'
        const goodFolderKey = new Uint8Array(32).fill(70)
        const goodFolderKeyWrapped = await platform.encryptWithKey(goodFolderKey, APP_KEY)
        const goodFolderData = await encryptFolderData('Good Folder', goodFolderKey)
        const badFolderUid = 'bad-folder-uid-summary'

        const options = await setupFolders([
            {folderUid: goodFolderUid, folderKey: platform.bytesToBase64(goodFolderKeyWrapped), data: platform.bytesToBase64(goodFolderData)},
            {folderUid: badFolderUid, folderKey: '', data: ''}
        ])

        await getFolders(options)

        const summaryLine = consoleErrorSpy.mock.calls
            .map(args => args.join(' '))
            .find(line => /getFolders:.*could not be decrypted/.test(line))
        expect(summaryLine).toBeDefined()
        expect(summaryLine).toContain(badFolderUid)
    } finally {
        consoleErrorSpy.mockRestore()
    }
})

test('top-level folder whose appKey-wrapped key decrypts cleanly to the wrong byte length is skipped with failure "integrity" (Node UNWRAPPED_KEY_LENGTH check, end-to-end)', async () => {
    // nodePlatform.unwrap()'s UNWRAPPED_KEY_LENGTH check (see nodePlatform.ts) is otherwise only
    // unit-tested directly against nodePlatform.unwrap() (see nodePlatform.test.ts); nothing
    // confirms it produces the correct caller-facing classification through a real getFolders()
    // call. Build a real GCM-wrapped 16-byte payload under APP_KEY (a real key, real ciphertext,
    // so the decrypt itself succeeds cleanly) - the same way nodePlatform.test.ts's own
    // "unwrap rejects an unwrapped key whose length is not 32 bytes" test builds its fixture -
    // and confirm the folder is skipped via the top-level (appKey) call site's 'integrity'
    // classification, not silently accepted with a malformed cached key.
    const folderUid = 'wrong-length-unwrapped-key-folder-uid'
    const shortPayload = new Uint8Array(16).fill(40)
    const wrappedShortKey = await platform.encryptWithKey(shortPayload, APP_KEY)

    const options = await setupFolders([
        {folderUid, folderKey: platform.bytesToBase64(wrappedShortKey), data: ''}
    ])

    const onDecryptionError = jest.fn()
    const folders = await getFolders({...options, onDecryptionError})

    expect(folders.length).toBe(0)
    expect(onDecryptionError).toHaveBeenCalledTimes(1)
    expect(onDecryptionError.mock.calls[0][0].uid).toBe(folderUid)
    expect(onDecryptionError.mock.calls[0][0].failure).toBe('integrity')
    expect(onDecryptionError.mock.calls[0][0].message).toMatch(/length/i)
})

test('does not log a partial-list summary line when zero folders are skipped', async () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
    try {
        const goodFolderUid = 'good-folder-uid-nosummary'
        const goodFolderKey = new Uint8Array(32).fill(71)
        const goodFolderKeyWrapped = await platform.encryptWithKey(goodFolderKey, APP_KEY)
        const goodFolderData = await encryptFolderData('Good Folder', goodFolderKey)

        const options = await setupFolders([
            {folderUid: goodFolderUid, folderKey: platform.bytesToBase64(goodFolderKeyWrapped), data: platform.bytesToBase64(goodFolderData)}
        ])

        await getFolders(options)

        const summaryLine = consoleErrorSpy.mock.calls
            .map(args => args.join(' '))
            .find(line => /getFolders:.*could not be decrypted/.test(line))
        expect(summaryLine).toBeUndefined()
    } finally {
        consoleErrorSpy.mockRestore()
    }
})
