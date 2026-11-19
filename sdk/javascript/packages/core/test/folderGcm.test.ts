// Folder cipher selection for GCM-wrapped subfolders: read dispatch by wrapped-key length,
// create/update writing GCM, and failure classification for tampered GCM folders.
//
// Every read and update scenario runs once per platform. The browser platform binds a CryptoKey
// to one algorithm, so a GCM subfolder needs its parent key cached in GCM form and the
// subfolder's own key cached in GCM form; node's raw-byte keys would not catch a missing cache slot.

import {createFolder, getFolders, getSecrets, initialize, initializeStorage, KeeperFolder, SecretManagerOptions, updateFolder, updateSecret} from '../src/keeper'
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

// Canonical UIDs: 22 base64url characters, 16 bytes.
const SHARED_UID = 'AQEBAQEBAQEBAQEBAQEBAQ'
const RECORD_UID = 'AgICAgICAgICAgICAgICAg'
const NESTED_GCM_UID = 'AwMDAwMDAwMDAwMDAwMDAw'
const NESTED_CBC_UID = 'BAQEBAQEBAQEBAQEBAQEBA'

const transmissionKey = new Uint8Array(32).fill(1)
const appKey = new Uint8Array(32).fill(2)
const sharedFolderKey = new Uint8Array(32).fill(3)
const nestedGcmKey = new Uint8Array(32).fill(4)
const nestedCbcKey = new Uint8Array(32).fill(5)
const recordKey = new Uint8Array(32).fill(6)
const OWNER_PUBLIC_KEY = 'T3duZXJQdWJsaWNLZXk'

type Tamper = 'gcm-key' | 'gcm-data' | undefined

type PostedBody = { path: string, body: any }

const restores: (() => void)[] = []

// Deterministic random bytes of the length asked for, so the fake transmission key is the one the
// fixture encrypts responses with. Restored after each test so no later suite sees the stub.
const stubRandomBytes = (): void => {
    const target = platform
    const original = target.getRandomBytes
    target.getRandomBytes = (length: number) => new Uint8Array(length).fill(1)
    restores.push(() => { target.getRandomBytes = original })
}

afterEach(() => {
    while (restores.length > 0) {
        restores.pop()!()
    }
})

const newStorage = async (bound: boolean = true) => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    if (bound) {
        await storage.saveBytes('appKey', appKey)
    }
    return storage
}

const pathOf = (url: string): string => url.substring(url.lastIndexOf('/') + 1)

// One shared (root) folder wrapped by the app key, plus two subfolders of it: one wrapped and
// encrypted with AES-GCM (60-byte key), one with the legacy AES-CBC (64-byte key). The fake server
// keeps each folder's stored data, so an update_folder request changes what the next get_folders
// returns, and a test can read the stored name back. Create and update requests are captured and
// decrypted so tests can also inspect the exact bytes sent.
//
// With freshBind the client holds only its one-time-token client key, as a new app does. The
// first get_folders reply then carries the app key wrapped with the client key, as the server
// sends it. failSecondGetFolders refuses every later get_folders request.
type FreshBind = { failSecondGetFolders?: boolean }

const buildFixture = async (tamper?: Tamper, gcmFolderKeyOverride?: string, freshBind?: FreshBind): Promise<{
    storage: ReturnType<typeof inMemoryStorage>
    queryFunction: SecretManagerOptions['queryFunction']
    posted: PostedBody[]
    calls: string[]
    getFoldersBodies: any[]
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

    const storedData: Record<string, string> = {
        [SHARED_UID]: platform.bytesToBase64(sharedData),
        [NESTED_GCM_UID]: platform.bytesToBase64(gcmData),
        [NESTED_CBC_UID]: platform.bytesToBase64(cbcData)
    }
    const folderKeys: Record<string, string> = {
        [SHARED_UID]: platform.bytesToBase64(wrappedSharedKey),
        [NESTED_GCM_UID]: gcmFolderKeyOverride ?? platform.bytesToBase64(wrappedGcmKey),
        [NESTED_CBC_UID]: platform.bytesToBase64(wrappedCbcKey)
    }
    const wrappedAppKey = platform.bytesToBase64(await platform.encryptWithKey(appKey, webSafe64ToBytes(FAKE_ONE_TIME_TOKEN)))
    const buildResponse = (withAppKey: boolean) => platform.encryptWithKey(enc(JSON.stringify({
        folders: [
            {folderUid: SHARED_UID, folderKey: folderKeys[SHARED_UID], data: storedData[SHARED_UID]},
            {folderUid: NESTED_GCM_UID, folderKey: folderKeys[NESTED_GCM_UID], data: storedData[NESTED_GCM_UID], parent: SHARED_UID},
            {folderUid: NESTED_CBC_UID, folderKey: folderKeys[NESTED_CBC_UID], data: storedData[NESTED_CBC_UID], parent: SHARED_UID}
        ],
        ...(withAppKey ? {encryptedAppKey: wrappedAppKey, appOwnerPublicKey: OWNER_PUBLIC_KEY} : {}),
        records: [],
        expiresOn: 0,
        warnings: []
    })), transmissionKey)

    stubRandomBytes()

    const posted: PostedBody[] = []
    const calls: string[] = []
    const getFoldersBodies: any[] = []
    const queryFunction: SecretManagerOptions['queryFunction'] = async (url, tk, encryptedPayload): Promise<KeeperHttpResponse> => {
        const path = pathOf(url)
        calls.push(path)
        if (path === 'get_folders') {
            getFoldersBodies.push(JSON.parse(platform.bytesToString(await platform.decryptWithKey(encryptedPayload.payload, tk.key))))
            if (freshBind?.failSecondGetFolders && getFoldersBodies.length > 1) {
                return {data: enc('{"error":"access_denied"}'), statusCode: 400, headers: []}
            }
        }
        if (path === 'create_folder' || path === 'update_folder') {
            const body = JSON.parse(platform.bytesToString(await platform.decryptWithKey(encryptedPayload.payload, tk.key)))
            posted.push({path, body})
            if (path === 'update_folder') {
                storedData[body.folderUid] = platform.bytesToBase64(webSafe64ToBytes(body.data))
            }
        }
        return {data: await buildResponse(!!freshBind && getFoldersBodies.length === 1), statusCode: 200, headers: []}
    }

    return {storage: await newStorage(!freshBind), queryFunction, posted, calls, getFoldersBodies}
}

// A record in the shared folder, to prove updateFolder leaves cached record keys alone. get_secret
// returns the shared folder with its record; get_folders returns the shared folder and an editable
// CBC child, which is the folder the tests rename.
const buildRecordFixture = async (failFolderUpdate: boolean): Promise<{
    storage: ReturnType<typeof inMemoryStorage>
    queryFunction: SecretManagerOptions['queryFunction']
    posted: PostedBody[]
}> => {
    const wrappedSharedKey = platform.bytesToBase64(await platform.encryptWithKey(sharedFolderKey, appKey))
    const sharedData = platform.bytesToBase64(await platform.encryptWithKey(enc(JSON.stringify({name: 'Shared Folder'})), sharedFolderKey, true))
    const wrappedCbcKey = platform.bytesToBase64(await platform.encryptWithKey(nestedCbcKey, sharedFolderKey, true))
    const cbcData = platform.bytesToBase64(await platform.encryptWithKey(enc(JSON.stringify({name: 'Nested CBC'})), nestedCbcKey, true))
    const wrappedRecordKey = platform.bytesToBase64(await platform.encryptWithKey(recordKey, sharedFolderKey))
    const recordData = platform.bytesToBase64(await platform.encryptWithKey(enc(JSON.stringify({title: 'Rec', type: 'login', fields: []})), recordKey))

    const secretResponse = await platform.encryptWithKey(enc(JSON.stringify({
        folders: [{
            folderUid: SHARED_UID, folderKey: wrappedSharedKey, data: sharedData,
            records: [{recordUid: RECORD_UID, recordKey: wrappedRecordKey, data: recordData, revision: 1}]
        }],
        records: [], expiresOn: 0, warnings: []
    })), transmissionKey)
    const foldersResponse = await platform.encryptWithKey(enc(JSON.stringify({
        folders: [
            {folderUid: SHARED_UID, folderKey: wrappedSharedKey, data: sharedData},
            {folderUid: NESTED_CBC_UID, folderKey: wrappedCbcKey, data: cbcData, parent: SHARED_UID}
        ],
        records: [], expiresOn: 0, warnings: []
    })), transmissionKey)

    stubRandomBytes()

    const posted: PostedBody[] = []
    const queryFunction: SecretManagerOptions['queryFunction'] = async (url, tk, encryptedPayload): Promise<KeeperHttpResponse> => {
        const path = pathOf(url)
        if (path === 'update_folder' && failFolderUpdate) {
            return {data: enc('{"error":"access_denied"}'), statusCode: 400, headers: []}
        }
        if (path === 'update_secret') {
            posted.push({path, body: JSON.parse(platform.bytesToString(await platform.decryptWithKey(encryptedPayload.payload, tk.key)))})
        }
        return {data: path === 'get_folders' ? foldersResponse : secretResponse, statusCode: 200, headers: []}
    }

    return {storage: await newStorage(), queryFunction, posted}
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
        expect(folders.map(f => f.folderUid).sort()).toEqual([NESTED_CBC_UID, SHARED_UID].sort())
    })

    test('tampered GCM subfolder data is skipped and classified as integrity', async () => {
        const {storage, queryFunction} = await buildFixture('gcm-data')
        const errors: KeeperDecryptionErrorInfo[] = []

        const folders = await getFolders({storage, queryFunction, onDecryptionError: info => errors.push(info)})

        expect(errors.find(e => e.uid === NESTED_GCM_UID)?.failure).toBe('integrity')
        expect(folders.map(f => f.folderUid).sort()).toEqual([NESTED_CBC_UID, SHARED_UID].sort())
    })

    // atob throws on invalid characters while Buffer.from does not, so only the browser platform
    // fails the decode; 'abc' decodes on both and is rejected later by the unwrap.
    test.each(['!!!not base64!!!', 'abc'])('a subfolder key that is not valid Base64 (%j) is skipped and classified as format', async (badKey) => {
        const {storage, queryFunction} = await buildFixture(undefined, badKey)
        const errors: KeeperDecryptionErrorInfo[] = []

        const folders = await getFolders({storage, queryFunction, onDecryptionError: info => errors.push(info)})

        expect(errors.map(e => ({uid: e.uid, failure: e.failure}))).toEqual([{uid: NESTED_GCM_UID, failure: 'format'}])
        expect(folders.map(f => f.folderUid).sort()).toEqual([NESTED_CBC_UID, SHARED_UID].sort())
    })
})

describe.each(platforms)('getFolders as the first call on a freshly bound client (%s platform)', (_name, plat) => {
    beforeEach(() => {
        connectPlatform(plat)
    })

    test('returns the folders, stores the app key, drops the client key, and the next call works on the same storage', async () => {
        const {storage, queryFunction} = await buildFixture(undefined, undefined, {})

        const folders = await getFolders({storage, queryFunction})

        expect(folders.length).toBe(3)
        expect(await storage.getBytes('appKey')).toEqual(appKey)
        expect(await storage.getBytes('clientKey')).toBeUndefined()
        expect(await storage.getString('appOwnerPublicKey')).toBe(OWNER_PUBLIC_KEY)
        expect((await getFolders({storage, queryFunction})).length).toBe(3)
    })

    test('sends one more get_folders request without the public key to finish the bind', async () => {
        const {storage, queryFunction, getFoldersBodies} = await buildFixture(undefined, undefined, {})

        await getFolders({storage, queryFunction})

        expect(getFoldersBodies.length).toBe(2)
        expect(getFoldersBodies[0].publicKey).toEqual(expect.any(String))
        expect(getFoldersBodies[1].publicKey).toBeUndefined()
    })

    test('still returns the folders when the finishing request is refused', async () => {
        const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
        restores.push(() => errorSpy.mockRestore())
        const {storage, queryFunction, getFoldersBodies} = await buildFixture(undefined, undefined, {failSecondGetFolders: true})

        const folders = await getFolders({storage, queryFunction})

        expect(getFoldersBodies.length).toBe(2)
        expect(folders.length).toBe(3)
    })
})

describe('createFolder (node platform)', () => {
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
})

// The renamed folders are children of the shared root: a classic shared root does not support
// update_folder, so renaming one would test a request the server never accepts.
describe.each(platforms)('updateFolder (%s platform)', (_name, plat) => {
    beforeEach(() => {
        connectPlatform(plat)
    })

    const children: [string, string, boolean][] = [
        ['GCM', NESTED_GCM_UID, true],
        ['CBC', NESTED_CBC_UID, false]
    ]

    test.each(children)('renames a %s child using the folder list it is given, and getFolders reads the new name back', async (_cipher, uid, useGcm) => {
        const {storage, queryFunction} = await buildFixture()
        const options: SecretManagerOptions = {storage, queryFunction}
        const folders = await getFolders(options)

        await updateFolder(options, uid, 'Renamed', folders)

        const after = (await getFolders(options)).find(f => f.folderUid === uid)!
        expect(after.name).toBe('Renamed')
        expect(after.useGcm).toBe(useGcm)
    })

    test.each(children)('renames a %s child without a list, looking the folder up first, and getFolders reads the new name back', async (_cipher, uid, useGcm) => {
        const {storage, queryFunction, calls} = await buildFixture()
        const options: SecretManagerOptions = {storage, queryFunction}

        await updateFolder(options, uid, 'Renamed')

        expect(calls.lastIndexOf('update_folder')).toBeGreaterThan(calls.indexOf('get_folders'))
        const after = (await getFolders(options)).find(f => f.folderUid === uid)!
        expect(after.name).toBe('Renamed')
        expect(after.useGcm).toBe(useGcm)
    })

    test('fails and sends nothing when the given folder list does not contain the folder', async () => {
        const {storage, queryFunction, posted} = await buildFixture()
        const options: SecretManagerOptions = {storage, queryFunction}
        await getFolders(options) // the folder key is now cached, so only the list can make this call fail
        const otherFolders: KeeperFolder[] = [{folderUid: NESTED_CBC_UID, name: 'Nested CBC', useGcm: false}]

        await expect(updateFolder(options, NESTED_GCM_UID, 'x', otherFolders)).rejects.toThrow(new RegExp(NESTED_GCM_UID))

        expect(posted.filter(p => p.path === 'update_folder')).toEqual([])
    })

    // updateFolder without a list looks the folder up on its own. That lookup must not clear the
    // record and file keys the caller cached with getSecrets, whether the rename succeeds or not.
    test('control: updateSecret works when no rename happens', async () => {
        const {storage, queryFunction, posted} = await buildRecordFixture(false)
        const options: SecretManagerOptions = {storage, queryFunction}
        const secrets = await getSecrets(options)

        await updateSecret(options, secrets.records[0])

        expect(posted.find(p => p.path === 'update_secret')).toBeDefined()
    })

    test.each([['succeeds', false], ['fails', true]])('updateSecret still works after a rename that %s', async (_outcome, failFolderUpdate) => {
        const {storage, queryFunction, posted} = await buildRecordFixture(failFolderUpdate)
        const options: SecretManagerOptions = {storage, queryFunction}
        const secrets = await getSecrets(options)
        expect(secrets.records.length).toBe(1)

        const rename = updateFolder(options, NESTED_CBC_UID, 'Renamed')
        if (failFolderUpdate) {
            await expect(rename).rejects.toThrow()
        } else {
            await rename
        }

        await updateSecret(options, secrets.records[0])
        const body = posted.find(p => p.path === 'update_secret')!.body
        const plain = await platform.decryptWithKey(webSafe64ToBytes(body.data), recordKey)
        expect(JSON.parse(platform.bytesToString(plain)).title).toBe('Rec')
    })
})
