// Browser-platform counterpart to the parent-cycle tests in keeper.test.ts.
//
// Importing '../src/browser' (for its side effect only) connects the browser platform
// implementation instead of the node one: browserPlatform.ts is built entirely on the standard
// WebCrypto API (crypto.subtle) and global fetch, with no window or document dependency, so it
// runs correctly here under plain Node-based Jest without any DOM emulation. getSharedFolderUid
// itself has no platform-specific code (plain arrays and a Set), so what these tests actually
// prove is that the surrounding wrap/unwrap and encrypt/decrypt machinery still cooperates
// correctly with the fix once real WebCrypto, not Node's crypto module, is doing the work.
//
// platform.ts holds a single shared mutable module-level "platform" variable, set once by
// connectPlatform. src/browser/index.ts calls connectPlatform with the browser platform and only
// re-exports loadJsonConfig/inMemoryStorage from platform.ts by name (not the platform object
// itself), so platform and the rest of the needed exports are imported directly from their
// source modules below rather than through '../src/browser'.
import '../src/browser'
import {platform, inMemoryStorage, KeeperHttpResponse} from '../src/platform'
import {getFolders, initializeStorage, SecretManagerOptions} from '../src/keeper'

// initializeStorage imports this as an AES key via the browser platform's importKey, which goes
// through crypto.subtle and therefore (unlike the node platform) requires a real 16/24/32 byte
// key once base64 decoded; a short placeholder string is not valid key material under WebCrypto.
const FAKE_CLIENT_KEY = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

afterEach(() => {
    jest.restoreAllMocks()
})

test('getFolders skips a folder that names itself as its own parent instead of hanging (browser platform)', async () => {
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})

    const transmissionKey = new Uint8Array(32).fill(1)
    const appKey = new Uint8Array(32).fill(2)
    const rootFolderKey = new Uint8Array(32).fill(3)
    const selfCycleUid = 'self-cycle-uid'
    const rootUid = 'root-uid'

    const rootFolderKeyWrapped = await platform.encryptWithKey(rootFolderKey, appKey)
    const rootFolderData = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify({name: 'Valid Root Folder'})), rootFolderKey, true)

    const serverResponse = {
        folders: [
            // Never decrypted: getSharedFolderUid throws before folderKey/data are read.
            {folderUid: selfCycleUid, folderKey: '', data: '', parent: selfCycleUid},
            {folderUid: rootUid, folderKey: platform.bytesToBase64(rootFolderKeyWrapped), data: platform.bytesToBase64(rootFolderData)}
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    // postQuery uses options.queryFunction (not platform.post); pin getRandomBytes so the
    // transmission key matches the key used to encrypt the response above.
    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({data: encryptedResponse, statusCode: 200, headers: []})

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, `US:${FAKE_CLIENT_KEY}`)
    await kvs.saveBytes('appKey', appKey)

    const options: SecretManagerOptions = {storage: kvs, queryFunction: queryFn}
    const folders = await getFolders(options)

    expect(folders.length).toBe(1)
    expect(folders[0].folderUid).toBe(rootUid)
    expect(folders[0].name).toBe('Valid Root Folder')
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('parent cycle detected at folder UID'))
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining(selfCycleUid))

    errorSpy.mockRestore()
})

test('getFolders detects a two-folder parent cycle and logs each folder naming the other as the cycle point (browser platform)', async () => {
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})

    const transmissionKey = new Uint8Array(32).fill(1)
    const appKey = new Uint8Array(32).fill(2)

    const serverResponse = {
        folders: [
            // Neither folder ever decrypts: getSharedFolderUid throws for both before
            // folderKey/data are read, so they can stay empty.
            {folderUid: 'folder-a', folderKey: '', data: '', parent: 'folder-b'},
            {folderUid: 'folder-b', folderKey: '', data: '', parent: 'folder-a'}
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({data: encryptedResponse, statusCode: 200, headers: []})

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, `US:${FAKE_CLIENT_KEY}`)
    await kvs.saveBytes('appKey', appKey)

    const options: SecretManagerOptions = {storage: kvs, queryFunction: queryFn}
    const folders = await getFolders(options)

    expect(folders.length).toBe(0)
    expect(errorSpy).toHaveBeenCalledTimes(2)
    // folder-a resolves its shared-folder lookup starting at folder-b: the walk visits folder-b
    // then folder-a again, so the cycle closes back at folder-b.
    expect(errorSpy.mock.calls[0][0]).toBe(
        'Folder folder-a skipped due to error: Error, Folder data inconsistent - parent cycle detected at folder UID folder-b'
    )
    // folder-b's lookup starts at folder-a and symmetrically closes back at folder-a.
    expect(errorSpy.mock.calls[1][0]).toBe(
        'Folder folder-b skipped due to error: Error, Folder data inconsistent - parent cycle detected at folder UID folder-a'
    )

    errorSpy.mockRestore()
})

// The wall-clock bound below is the real regression guard: a synchronous infinite loop cannot be
// preempted by Jest's timer-based timeout, so a future revert of the fix would hang this test
// indefinitely rather than fail fast; the bounded implementation is what keeps this test reliable.
test('getFolders resolves a large folder-parent cycle quickly instead of hanging the event loop (browser platform)', async () => {
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})

    const transmissionKey = new Uint8Array(32).fill(1)
    const ringSize = 500
    const ringFolders: { folderUid: string, folderKey: string, data: string, parent: string }[] = []
    for (let i = 0; i < ringSize; i++) {
        ringFolders.push({folderUid: `folder-${i}`, folderKey: '', data: '', parent: `folder-${(i + 1) % ringSize}`})
    }

    const serverResponse = {folders: ringFolders, records: [], expiresOn: 0, warnings: []}
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({data: encryptedResponse, statusCode: 200, headers: []})

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, `US:${FAKE_CLIENT_KEY}`)

    const start = Date.now()
    const folders = await getFolders({storage: kvs, queryFunction: queryFn})
    const elapsed = Date.now() - start

    expect(folders).toEqual([])
    expect(elapsed).toBeLessThan(2000)

    errorSpy.mockRestore()
}, 5000)

test('getFolders decrypts a real two-level, non-cyclic parent chain (root then child) (browser platform)', async () => {
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})

    const transmissionKey = new Uint8Array(32).fill(1)
    const appKey = new Uint8Array(32).fill(2)
    const rootFolderKey = new Uint8Array(32).fill(3)
    const childFolderKey = new Uint8Array(32).fill(4)
    const rootUid = 'root-folder-uid'
    const childUid = 'child-folder-uid'

    const rootFolderKeyWrapped = await platform.encryptWithKey(rootFolderKey, appKey)
    const rootFolderData = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify({name: 'Root Folder'})), rootFolderKey, true)

    // The child's folder key is wrapped with the root's raw key bytes, matching how
    // fetchAndDecryptFolders unwraps a nested folder's key against its resolved shared folder.
    const childFolderKeyWrapped = await platform.encryptWithKey(childFolderKey, rootFolderKey, true)
    const childFolderData = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify({name: 'Child Folder'})), childFolderKey, true)

    const serverResponse = {
        folders: [
            // Root listed before child: the root's key must be cached before the child's own
            // unwrap (which unwraps against the root) runs later in the same loop.
            {folderUid: rootUid, folderKey: platform.bytesToBase64(rootFolderKeyWrapped), data: platform.bytesToBase64(rootFolderData)},
            {folderUid: childUid, folderKey: platform.bytesToBase64(childFolderKeyWrapped), data: platform.bytesToBase64(childFolderData), parent: rootUid}
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({data: encryptedResponse, statusCode: 200, headers: []})

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, `US:${FAKE_CLIENT_KEY}`)
    await kvs.saveBytes('appKey', appKey)

    const options: SecretManagerOptions = {storage: kvs, queryFunction: queryFn}
    const folders = await getFolders(options)

    expect(folders.length).toBe(2)
    expect(folders.find(f => f.folderUid === rootUid)?.name).toBe('Root Folder')
    expect(folders.find(f => f.folderUid === childUid)?.name).toBe('Child Folder')
    expect(errorSpy).not.toHaveBeenCalled()

    errorSpy.mockRestore()
})
