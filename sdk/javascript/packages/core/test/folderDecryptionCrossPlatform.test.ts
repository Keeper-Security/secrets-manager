// KSM-1267 cross-platform regression coverage for getFolders()'s crypto failure classification.
//
// The goal here is narrower than a general getFolders test: it is to prove that node and the
// browser platform agree on the classification (KeeperCryptoFailureReason) for the same input,
// even though their underlying crypto libraries (OpenSSL vs WebCrypto) throw completely
// differently-shaped errors for the same logical failure. Every scenario below therefore runs
// once per platform against otherwise-identical fixtures, and assertions only ever look at
// KeeperDecryptionErrorInfo.failure / folder shape, never at raw error message text.
//
// This file also regression-pins the specific bug caught during implementation: dropping the
// useCBC argument from the appKey-wrapped (top-level) folder's unwrap() call broke browser-only
// folder decryption, because that call's only job (on the browser platform) besides unwrapping
// the folder's own key is to populate the second, CBC-mode cache slot that both the folder's own
// data decrypt and any child folder's unwrap later depend on. Scenario 1 exercises exactly that
// two-folder (shared + nested) shape on the browser platform, not just node, since node's
// raw-byte keys never needed that second cache slot and would not have caught this bug.
//
// Per the project's gotchas (see the KSM-1267 implementation notes):
// - Native crypto errors are not reliably `instanceof Error` under Jest's test environment, so
//   only the SDK's own KeeperCryptoError / KeeperDecryptionErrorInfo shapes are asserted on here.
// - getFolders/fetchAndDecryptFolders read the shared module-level `platform` singleton, so each
//   test explicitly reconnects the platform it needs instead of relying on import side effects.

import {getFolders, initialize, initializeStorage, SecretManagerOptions} from '../src/keeper'
import {connectPlatform, inMemoryStorage, KeeperHttpResponse, Platform, platform} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'
import {browserPlatform} from '../src/browser/browserPlatform'
import {KeeperDecryptionErrorInfo} from '../src/errors'

// A one-time token whose client-key segment decodes to exactly 32 bytes. The browser platform's
// crypto.subtle.importKey validates raw AES key length immediately (unlike node's, which never
// validates at import time), so an arbitrary ad hoc string here would throw only on browser.
const FAKE_ONE_TIME_TOKEN = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

// One-time module setup: initialize() populates the module-level Keeper public key table used by
// generateTransmissionKey. It only decodes fixed base64 strings, so it does not matter which
// platform is connected when it runs; every test below reconnects the platform it actually needs.
connectPlatform(nodePlatform)
initialize()

const enc = (s: string): Uint8Array => platform.stringToBytes(s)

const flipLastByte = (data: Uint8Array): Uint8Array => {
    const tampered = new Uint8Array(data)
    tampered[tampered.length - 1] ^= 0xff
    return tampered
}

const SHARED_FOLDER_UID = 'shared-folder-uid'
const NESTED_FOLDER_UID = 'nested-folder-uid'

type Tamper = 'shared' | 'nested' | undefined

// Builds a fresh, self-contained fixture (storage + queryFunction) entirely against whichever
// platform is currently connected: a top-level shared folder wrapped by the app key, and a nested
// subfolder of that shared folder whose key is wrapped by the shared folder's key. `tamper`
// deterministically corrupts one of the two wrapped folder keys by flipping its last byte
// (KSM-1267 gotcha: this reliably breaks CBC padding for the nested wrap and always breaks the
// GCM tag for the app-key-wrapped top-level wrap, so neither failure depends on tamper odds).
const buildFixture = async (tamper?: Tamper): Promise<{
    storage: ReturnType<typeof inMemoryStorage>
    queryFunction: SecretManagerOptions['queryFunction']
}> => {
    const transmissionKey = new Uint8Array(32).fill(1)
    const appKey = new Uint8Array(32).fill(2)
    const sharedFolderKey = new Uint8Array(32).fill(3)
    const nestedFolderKey = new Uint8Array(32).fill(4)

    let wrappedSharedFolderKey = await platform.encryptWithKey(sharedFolderKey, appKey)
    if (tamper === 'shared') {
        wrappedSharedFolderKey = flipLastByte(wrappedSharedFolderKey)
    }

    // Wrapped by the shared folder's key, in CBC: this is the real KSM-1267 exposure (the vault's
    // wire format for this wrap is fixed to unauthenticated AES-256-CBC server-side).
    let wrappedNestedFolderKey = await platform.encryptWithKey(nestedFolderKey, sharedFolderKey, true)
    if (tamper === 'nested') {
        wrappedNestedFolderKey = flipLastByte(wrappedNestedFolderKey)
    }

    const sharedFolderData = await platform.encryptWithKey(enc(JSON.stringify({name: 'Shared Folder'})), sharedFolderKey, true)
    const nestedFolderData = await platform.encryptWithKey(enc(JSON.stringify({name: 'Nested Folder'})), nestedFolderKey, true)

    // Order matters: the shared folder must be processed before the nested one so that, on the
    // browser platform, its CBC-mode key cache slot ('cbc:' + sharedFolderUid) is already
    // populated by the time the nested folder's unwrap needs it as the wrapping key.
    const serverResponse = {
        folders: [
            {
                folderUid: SHARED_FOLDER_UID,
                folderKey: platform.bytesToBase64(wrappedSharedFolderKey),
                data: platform.bytesToBase64(sharedFolderData)
            },
            {
                folderUid: NESTED_FOLDER_UID,
                folderKey: platform.bytesToBase64(wrappedNestedFolderKey),
                data: platform.bytesToBase64(nestedFolderData),
                parent: SHARED_FOLDER_UID
            }
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(enc(JSON.stringify(serverResponse)), transmissionKey)

    // postQuery uses options.queryFunction (not platform.post); pin getRandomBytes so the
    // transmission key generateTransmissionKey produces matches the key used to encrypt the
    // response above.
    platform.getRandomBytes = () => transmissionKey
    const queryFunction = (): Promise<KeeperHttpResponse> =>
        Promise.resolve({data: encryptedResponse, statusCode: 200, headers: []})

    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    await storage.saveBytes('appKey', appKey)

    return {storage, queryFunction}
}

const platforms: [string, Platform][] = [
    ['node', nodePlatform],
    ['browser', browserPlatform]
]

describe.each(platforms)('getFolders folder decryption classification (%s platform)', (_name, plat) => {
    beforeEach(() => {
        connectPlatform(plat)
    })

    test('shared folder and its nested subfolder both decrypt successfully', async () => {
        const {storage, queryFunction} = await buildFixture()
        const errors: KeeperDecryptionErrorInfo[] = []

        const folders = await getFolders({
            storage,
            queryFunction,
            onDecryptionError: info => errors.push(info)
        })

        // No failures at all: this is the regression pin for the useCBC-dropped bug. If that bug
        // were reintroduced, the shared folder would fail its own data decrypt (missing the
        // second, CBC-mode cache slot) and the nested folder would fail to unwrap entirely
        // (missing the shared folder's cached CBC key), so both folders would disappear.
        expect(errors).toEqual([])
        expect(folders.length).toBe(2)

        const shared = folders.find(f => f.folderUid === SHARED_FOLDER_UID)
        const nested = folders.find(f => f.folderUid === NESTED_FOLDER_UID)

        expect(shared).toBeDefined()
        expect(shared!.name).toBe('Shared Folder')

        expect(nested).toBeDefined()
        expect(nested!.name).toBe('Nested Folder')
        expect(nested!.parentUid).toBe(SHARED_FOLDER_UID)
    })

    test('a tampered nested-folder key wrap is classified as format', async () => {
        const {storage, queryFunction} = await buildFixture('nested')
        const errors: KeeperDecryptionErrorInfo[] = []

        const folders = await getFolders({
            storage,
            queryFunction,
            onDecryptionError: info => errors.push(info)
        })

        // The shared folder is wrapped and processed independently, so it still decrypts fine;
        // only the nested folder (whose key wrap was tampered) is skipped.
        expect(folders.length).toBe(1)
        expect(folders[0].folderUid).toBe(SHARED_FOLDER_UID)

        const nestedError = errors.find(e => e.uid === NESTED_FOLDER_UID)
        expect(nestedError).toBeDefined()
        expect(nestedError!.failure).toBe('format')
    })

    test('a tampered top-level shared-folder key wrap is classified as integrity', async () => {
        const {storage, queryFunction} = await buildFixture('shared')
        const errors: KeeperDecryptionErrorInfo[] = []

        const folders = await getFolders({
            storage,
            queryFunction,
            onDecryptionError: info => errors.push(info)
        })

        const sharedError = errors.find(e => e.uid === SHARED_FOLDER_UID)
        expect(sharedError).toBeDefined()
        expect(sharedError!.failure).toBe('integrity')

        // The nested folder cascades to a skip too (it needs the shared folder's key, which
        // never got cached once the shared folder's own unwrap threw), so neither folder survives.
        expect(folders.length).toBe(0)

        // The cascading nested-folder failure is classified 'missing-key', NOT 'format', even
        // though the nested folder's own key wrap is a real, untampered CBC wrap. getSharedFolderUid
        // resolves purely off the raw response.folders array (folderUid/parent fields only), so it
        // still successfully resolves SHARED_FOLDER_UID as the nested folder's shared-folder uid
        // even though the shared folder's own unwrap threw before ever reaching
        // keyCache[keyId]=... / storage.saveBytes(...). The nested folder's subsequent
        // platform.unwrap(..., sharedFolderUid, ...) call then fails inside loadKey (the shared
        // folder's key was never cached or persisted), which throws a KeeperCryptoError already
        // tagged 'missing-key' - and runCrypto's classifyCryptoFailure only overrides the mode
        // ('format' here) when the caught error is NOT already a KeeperCryptoError, so 'missing-key'
        // passes through unchanged. A future change to getSharedFolderUid or the cache-population
        // order that silently altered this cascade classification would only be caught here.
        const nestedError = errors.find(e => e.uid === NESTED_FOLDER_UID)
        expect(nestedError).toBeDefined()
        expect(nestedError!.failure).toBe('missing-key')
    })
})
