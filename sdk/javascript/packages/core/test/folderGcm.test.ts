// Folder cipher selection for GCM-wrapped subfolders: read dispatch by wrapped-key length,
// create/update writing GCM, and failure classification for tampered GCM folders.
//
// Every read scenario runs once per platform. The browser platform binds a CryptoKey to one
// algorithm, so a GCM subfolder needs its parent key cached in GCM form and the subfolder's own
// key cached in GCM form; node's raw-byte keys would not catch a missing cache slot.

import {createFolder, getFolders, initialize, initializeStorage, KeeperFolder, SecretManagerOptions, updateFolder} from '../src/keeper'
import {connectPlatform, inMemoryStorage, KeeperHttpResponse, Platform, platform} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'
import {browserPlatform} from '../src/browser/browserPlatform'
import {KeeperDecryptionErrorInfo} from '../src/errors'
import {webSafe64ToBytes} from '../src/utils'

// Client-key segment decodes to 32 bytes; WebCrypto validates raw AES key length at import time.
const FAKE_ONE_TIME_TOKEN = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

connectPlatform(nodePlatform)
initialize()

const enc = (s: string): Uint8Array => platform.stringToBytes(s)

const flipLastByte = (data: Uint8Array): Uint8Array => {
    const tampered = new Uint8Array(data)
    tampered[tampered.length - 1] ^= 0xff
    return tampered
}

const SHARED_UID = 'shared-folder-uid'
const NESTED_GCM_UID = 'nested-gcm-folder-uid'
const NESTED_CBC_UID = 'nested-cbc-folder-uid'

const transmissionKey = new Uint8Array(32).fill(1)
const appKey = new Uint8Array(32).fill(2)
const sharedFolderKey = new Uint8Array(32).fill(3)
const nestedGcmKey = new Uint8Array(32).fill(4)
const nestedCbcKey = new Uint8Array(32).fill(5)

type Tamper = 'gcm-key' | 'gcm-data' | undefined

type PostedBody = { path: string, body: any }

// One shared (root) folder wrapped by the app key, plus two subfolders of it: one wrapped and
// encrypted with AES-GCM (60-byte key), one with the legacy AES-CBC (64-byte key). Create and
// update requests are captured and decrypted so tests can inspect the exact bytes sent.
const buildFixture = async (tamper?: Tamper): Promise<{
    storage: ReturnType<typeof inMemoryStorage>
    queryFunction: SecretManagerOptions['queryFunction']
    posted: PostedBody[]
    calls: string[]
}> => {
    const wrappedSharedKey = await platform.encryptWithKey(sharedFolderKey, appKey)
    const sharedData = await platform.encryptWithKey(enc(JSON.stringify({name: 'Shared Folder'})), sharedFolderKey, true)

    let wrappedGcmKey = await platform.encryptWithKey(nestedGcmKey, sharedFolderKey)
    let gcmData = await platform.encryptWithKey(enc(JSON.stringify({name: 'Nested GCM'})), nestedGcmKey)
    if (tamper === 'gcm-key') {
        wrappedGcmKey = flipLastByte(wrappedGcmKey)
    }
    if (tamper === 'gcm-data') {
        gcmData = flipLastByte(gcmData)
    }

    const wrappedCbcKey = await platform.encryptWithKey(nestedCbcKey, sharedFolderKey, true)
    const cbcData = await platform.encryptWithKey(enc(JSON.stringify({name: 'Nested CBC'})), nestedCbcKey, true)

    const serverResponse = {
        folders: [
            {folderUid: SHARED_UID, folderKey: platform.bytesToBase64(wrappedSharedKey), data: platform.bytesToBase64(sharedData)},
            {folderUid: NESTED_GCM_UID, folderKey: platform.bytesToBase64(wrappedGcmKey), data: platform.bytesToBase64(gcmData), parent: SHARED_UID},
            {folderUid: NESTED_CBC_UID, folderKey: platform.bytesToBase64(wrappedCbcKey), data: platform.bytesToBase64(cbcData), parent: SHARED_UID}
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(enc(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey

    const posted: PostedBody[] = []
    const calls: string[] = []
    const queryFunction: SecretManagerOptions['queryFunction'] = async (url, tk, encryptedPayload): Promise<KeeperHttpResponse> => {
        const path = url.substring(url.lastIndexOf('/') + 1)
        calls.push(path)
        if (path === 'create_folder' || path === 'update_folder') {
            const body = JSON.parse(platform.bytesToString(await platform.decryptWithKey(encryptedPayload.payload, tk.key)))
            posted.push({path, body})
        }
        return {data: encryptedResponse, statusCode: 200, headers: []}
    }

    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    await storage.saveBytes('appKey', appKey)

    return {storage, queryFunction, posted, calls}
}

const platforms: [string, Platform][] = [
    ['node', nodePlatform],
    ['browser', browserPlatform]
]

describe.each(platforms)('GCM-wrapped subfolders (%s platform)', (_name, plat) => {
    beforeEach(() => {
        connectPlatform(plat)
    })

    test('a GCM subfolder and a CBC subfolder in one response both decrypt, and useGcm records which cipher each uses', async () => {
        const {storage, queryFunction} = await buildFixture()
        const errors: KeeperDecryptionErrorInfo[] = []

        const folders = await getFolders({storage, queryFunction, onDecryptionError: info => errors.push(info)})

        expect(errors).toEqual([])
        expect(folders.length).toBe(3)

        const gcm = folders.find(f => f.folderUid === NESTED_GCM_UID)!
        const cbc = folders.find(f => f.folderUid === NESTED_CBC_UID)!
        expect(gcm.name).toBe('Nested GCM')
        expect(gcm.parentUid).toBe(SHARED_UID)
        expect(gcm.useGcm).toBe(true)
        expect(cbc.name).toBe('Nested CBC')
        expect(cbc.useGcm).toBe(false)
    })

    test('a tampered GCM subfolder key wrap is skipped and classified as integrity', async () => {
        const {storage, queryFunction} = await buildFixture('gcm-key')
        const errors: KeeperDecryptionErrorInfo[] = []

        const folders = await getFolders({storage, queryFunction, onDecryptionError: info => errors.push(info)})

        expect(errors.find(e => e.uid === NESTED_GCM_UID)?.failure).toBe('integrity')
        expect(folders.map(f => f.folderUid).sort()).toEqual([NESTED_CBC_UID, SHARED_UID])
    })

    test('tampered GCM subfolder data is skipped and classified as integrity', async () => {
        const {storage, queryFunction} = await buildFixture('gcm-data')
        const errors: KeeperDecryptionErrorInfo[] = []

        const folders = await getFolders({storage, queryFunction, onDecryptionError: info => errors.push(info)})

        expect(errors.find(e => e.uid === NESTED_GCM_UID)?.failure).toBe('integrity')
        expect(folders.map(f => f.folderUid).sort()).toEqual([NESTED_CBC_UID, SHARED_UID])
    })
})

describe('folder writes (node platform)', () => {
    beforeEach(() => {
        connectPlatform(nodePlatform)
    })

    test('createFolder in a classic shared folder keeps AES-CBC for the key wrap and the data', async () => {
        const {storage, queryFunction, posted} = await buildFixture()
        const options: SecretManagerOptions = {storage, queryFunction}
        await getFolders(options) // caches the shared folder key that createFolder wraps under

        await createFolder(options, {folderUid: SHARED_UID}, 'New Folder')

        const body = posted.find(p => p.path === 'create_folder')!.body
        const wrappedKey = webSafe64ToBytes(body.sharedFolderKey)
        // 16-byte IV + 48 bytes of padded key. A GCM wrap is 60 bytes: the server accepts it for a
        // classic parent, but Commander and 17.x readers cannot unwrap it, so the folder goes blank.
        expect(wrappedKey.length).toBe(64)
        const newFolderKey = await platform.decryptWithKey(wrappedKey, sharedFolderKey, true)
        const folderData = await platform.decryptWithKey(webSafe64ToBytes(body.data), newFolderKey, true)
        expect(JSON.parse(platform.bytesToString(folderData))).toEqual({name: 'New Folder'})
    })

    test('updateFolder takes the cipher from the folder list it is given', async () => {
        const {storage, queryFunction, posted} = await buildFixture()
        const options: SecretManagerOptions = {storage, queryFunction}
        await getFolders(options) // caches the shared folder key; the list below supplies only the cipher
        const asGcm: KeeperFolder[] = [{folderUid: SHARED_UID, name: 'Shared Folder', useGcm: true}]
        const asCbc: KeeperFolder[] = [{folderUid: SHARED_UID, name: 'Shared Folder', useGcm: false}]

        await updateFolder(options, SHARED_UID, 'Renamed GCM', asGcm)
        await updateFolder(options, SHARED_UID, 'Renamed CBC', asCbc)

        const updates = posted.filter(p => p.path === 'update_folder').map(p => webSafe64ToBytes(p.body.data))
        expect(updates.length).toBe(2)
        const gcmPlain = await platform.decryptWithKey(updates[0], sharedFolderKey)
        expect(JSON.parse(platform.bytesToString(gcmPlain))).toEqual({name: 'Renamed GCM'})
        const cbcPlain = await platform.decryptWithKey(updates[1], sharedFolderKey, true)
        expect(JSON.parse(platform.bytesToString(cbcPlain))).toEqual({name: 'Renamed CBC'})
    })

    test('updateFolder without a list looks the folder up with getFolders and uses its real cipher', async () => {
        const {storage, queryFunction, posted, calls} = await buildFixture()
        const options: SecretManagerOptions = {storage, queryFunction}

        await updateFolder(options, NESTED_GCM_UID, 'Renamed Nested')

        expect(calls).toContain('get_folders')
        expect(calls.lastIndexOf('update_folder')).toBeGreaterThan(calls.indexOf('get_folders'))
        const body = posted.find(p => p.path === 'update_folder')!.body
        const plain = await platform.decryptWithKey(webSafe64ToBytes(body.data), nestedGcmKey)
        expect(JSON.parse(platform.bytesToString(plain))).toEqual({name: 'Renamed Nested'})
    })

    test('updateFolder fails and sends nothing when the given folder list does not contain the folder', async () => {
        const {storage, queryFunction, posted} = await buildFixture()
        const options: SecretManagerOptions = {storage, queryFunction}
        await getFolders(options) // the shared folder key is now cached, so only the list can make this call fail
        const otherFolders: KeeperFolder[] = [{folderUid: NESTED_CBC_UID, name: 'Nested CBC', useGcm: false}]

        await expect(updateFolder(options, SHARED_UID, 'x', otherFolders)).rejects.toThrow(new RegExp(SHARED_UID))

        expect(posted.filter(p => p.path === 'update_folder')).toEqual([])
    })
})
