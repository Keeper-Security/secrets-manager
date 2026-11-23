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
import {webSafe64FromBytes, webSafe64ToBytes} from '../src/utils'
import {createCipheriv} from 'crypto'

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
const rootKey = new Uint8Array(32).fill(7)

type Tamper = 'gcm-key' | 'gcm-data' | undefined

type PostedBody = { path: string, body: any }

// A top-level folder with no parent, wrapped by the app key, whose data bytes the test supplies.
type RootFolder = { uid: string, data: Uint8Array }

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

const newStorage = async () => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    await storage.saveBytes('appKey', appKey)
    return storage
}

const pathOf = (url: string): string => url.substring(url.lastIndexOf('/') + 1)

// One shared (root) folder wrapped by the app key, plus two subfolders of it: one wrapped and
// encrypted with AES-GCM (60-byte key), one with the legacy AES-CBC (64-byte key). The fake server
// keeps each folder's stored data, so an update_folder request changes what the next get_folders
// returns, and a test can read the stored name back. Create and update requests are captured and
// decrypted so tests can also inspect the exact bytes sent.
const buildFixture = async (tamper?: Tamper, gcmFolderKeyOverride?: string, extraRoots: RootFolder[] = []): Promise<{
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
    const wrappedRootKey = platform.bytesToBase64(await platform.encryptWithKey(rootKey, appKey))
    for (const root of extraRoots) {
        storedData[root.uid] = platform.bytesToBase64(root.data)
        folderKeys[root.uid] = wrappedRootKey
    }
    const buildResponse = () => platform.encryptWithKey(enc(JSON.stringify({
        folders: [
            {folderUid: SHARED_UID, folderKey: folderKeys[SHARED_UID], data: storedData[SHARED_UID]},
            ...extraRoots.map(root => ({folderUid: root.uid, folderKey: folderKeys[root.uid], data: storedData[root.uid]})),
            {folderUid: NESTED_GCM_UID, folderKey: folderKeys[NESTED_GCM_UID], data: storedData[NESTED_GCM_UID], parent: SHARED_UID},
            {folderUid: NESTED_CBC_UID, folderKey: folderKeys[NESTED_CBC_UID], data: storedData[NESTED_CBC_UID], parent: SHARED_UID}
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    })), transmissionKey)

    stubRandomBytes()

    const posted: PostedBody[] = []
    const calls: string[] = []
    const queryFunction: SecretManagerOptions['queryFunction'] = async (url, tk, encryptedPayload): Promise<KeeperHttpResponse> => {
        const path = pathOf(url)
        calls.push(path)
        if (path === 'create_folder' || path === 'update_folder') {
            const body = JSON.parse(platform.bytesToString(await platform.decryptWithKey(encryptedPayload.payload, tk.key)))
            posted.push({path, body})
            if (path === 'update_folder') {
                storedData[body.folderUid] = platform.bytesToBase64(webSafe64ToBytes(body.data))
            }
        }
        return {data: await buildResponse(), statusCode: 200, headers: []}
    }

    return {storage: await newStorage(), queryFunction, posted, calls}
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

// Top-level (root) folder data. A root arrives with no parent, so no wrapped-key size says which
// cipher its data uses. The server also sends an NSF root zero-padded to 255 bytes, so the helpers
// below build exactly the byte layouts the SDK has to tell apart.

const rootUid = (n: number): string => webSafe64FromBytes(new Uint8Array(16).fill(n))

const jsonName = (name: string): Uint8Array => enc(JSON.stringify({name}))

// nonce(12) + ciphertext + tag(16). A tag ends in 0x00 for 1 nonce in 256, and in two zero bytes for
// 1 in 65536, so a counter loop finds a nonce that gives the tag the tail the test asks for.
const gcmBlob = (plaintext: Uint8Array, zeroTailBytes = 0): Uint8Array => {
    for (let counter = 0; counter < 0x1000000; counter++) {
        const iv = Buffer.alloc(12)
        iv.writeUInt32BE(counter, 8)
        const cipher = createCipheriv('aes-256-gcm', rootKey, iv)
        const body = Buffer.concat([cipher.update(plaintext), cipher.final()])
        const tag = cipher.getAuthTag()
        if (tag.subarray(16 - zeroTailBytes).every(b => b === 0)) {
            return new Uint8Array(Buffer.concat([iv, body, tag]))
        }
    }
    throw new Error('no nonce gave the requested tag tail')
}

// iv(16) + ciphertext, the legacy layout. With endsInZeroByte the loop picks an IV whose last
// ciphertext byte is 0x00, the case a zero-trimming reader would damage.
const cbcBlob = (plaintext: Uint8Array, endsInZeroByte = false): Uint8Array => {
    for (let counter = 0; counter < 0x10000; counter++) {
        const iv = Buffer.alloc(16)
        iv.writeUInt32BE(counter, 12)
        const cipher = createCipheriv('aes-256-cbc', rootKey, iv)
        const body = Buffer.concat([cipher.update(plaintext), cipher.final()])
        if (!endsInZeroByte || body[body.length - 1] === 0) {
            return new Uint8Array(Buffer.concat([iv, body]))
        }
    }
    throw new Error('no IV gave a ciphertext ending in a zero byte')
}

const zeroPad = (data: Uint8Array, size = 255): Uint8Array => {
    const padded = new Uint8Array(size)
    padded.set(data)
    return padded
}

// A valid GCM root that rides along in tests whose subject is a skipped or damaged root. Without the
// fix the canary is skipped too, so these tests fail before the fix instead of passing by accident.
const CANARY: RootFolder = {uid: rootUid(30), data: gcmBlob(jsonName('Canary GCM'))}

const readRoots = async (roots: RootFolder[]) => {
    const fixture = await buildFixture(undefined, undefined, roots)
    const errors: KeeperDecryptionErrorInfo[] = []
    const folders = await getFolders({storage: fixture.storage, queryFunction: fixture.queryFunction, onDecryptionError: info => errors.push(info)})
    return {...fixture, folders, errors}
}

const byUid = (folders: KeeperFolder[], uid: string): KeeperFolder | undefined => folders.find(f => f.folderUid === uid)

describe.each(platforms)('root folder data (%s platform)', (_name, plat) => {
    let errorSpy: jest.SpyInstance

    beforeEach(() => {
        connectPlatform(plat)
        errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
    })

    afterEach(() => {
        errorSpy.mockRestore()
    })

    const logged = (): string => JSON.stringify(errorSpy.mock.calls)

    test('a root whose data is AES-GCM reads with useGcm true', async () => {
        const {folders, errors} = await readRoots([{uid: rootUid(10), data: gcmBlob(jsonName('GCM Root'))}])

        expect(errors).toEqual([])
        const root = byUid(folders, rootUid(10))!
        expect(root.name).toBe('GCM Root')
        expect(root.useGcm).toBe(true)
        expect(root.parentUid).toBeUndefined()
    })

    test('a root whose data is zero-padded to 255 bytes reads correctly', async () => {
        const {folders, errors} = await readRoots([{uid: rootUid(10), data: zeroPad(gcmBlob(jsonName('Padded Root')))}])

        expect(errors).toEqual([])
        const root = byUid(folders, rootUid(10))!
        expect(root.name).toBe('Padded Root')
        expect(root.useGcm).toBe(true)
    })

    test.each([
        ['one zero byte, padded to 255 bytes', 1, true],
        ['two zero bytes, padded to 255 bytes', 2, true],
        ['one zero byte, not padded', 1, false]
    ])('a GCM tag ending in %s reads correctly', async (_label, zeroTail, padded) => {
        const blob = gcmBlob(jsonName('Tag Edge'), zeroTail)
        expect(blob.subarray(blob.length - zeroTail).every(b => b === 0)).toBe(true)

        const {folders, errors} = await readRoots([{uid: rootUid(10), data: padded ? zeroPad(blob) : blob}])

        expect(errors).toEqual([])
        expect(byUid(folders, rootUid(10))!.name).toBe('Tag Edge')
        expect(byUid(folders, rootUid(10))!.useGcm).toBe(true)
    })

    // 48 bytes is a whole number of AES blocks, the length a CBC value has. The cipher must come
    // from the authentication result, never from the length.
    test('a GCM root whose length is a multiple of 16 still reads as AES-GCM', async () => {
        const blob = gcmBlob(jsonName('Nine Char'))
        expect(blob.length % 16).toBe(0)

        const {folders, errors} = await readRoots([{uid: rootUid(10), data: blob}])

        expect(errors).toEqual([])
        expect(byUid(folders, rootUid(10))!.name).toBe('Nine Char')
        expect(byUid(folders, rootUid(10))!.useGcm).toBe(true)
    })

    test('a root that authenticates as AES-GCM but is not JSON is returned with an empty name, and none of it is logged', async () => {
        const secret = 'SecretProjectX'
        const data = zeroPad(gcmBlob(enc(secret)))

        const {folders, errors} = await readRoots([{uid: rootUid(11), data}])

        expect(errors).toEqual([])
        const root = byUid(folders, rootUid(11))!
        expect(root.name).toBe('')
        expect(root.useGcm).toBe(true)
        const everything = logged() + JSON.stringify(errors)
        expect(everything).not.toContain(secret)
        expect(everything).not.toContain(platform.bytesToBase64(data))
        expect(everything).not.toContain(platform.bytesToBase64(rootKey))
    })

    test('a root that is neither AES-GCM nor AES-CBC is skipped without throwing, and its data is not logged', async () => {
        const garbage = new Uint8Array(48).fill(9)

        const {folders, errors} = await readRoots([{uid: rootUid(12), data: garbage}, CANARY])

        expect(byUid(folders, rootUid(12))).toBeUndefined()
        expect(errors.map(e => e.uid)).toEqual([rootUid(12)])
        expect(byUid(folders, CANARY.uid)!.name).toBe('Canary GCM')
        expect(logged() + JSON.stringify(errors)).not.toContain(platform.bytesToBase64(garbage))
    })

    test('a GCM root with a tampered tag is skipped and classified as format', async () => {
        const {folders, errors} = await readRoots([{uid: rootUid(12), data: flipLastByte(gcmBlob(jsonName('Tampered')))}, CANARY])

        expect(byUid(folders, rootUid(12))).toBeUndefined()
        expect(errors.find(e => e.uid === rootUid(12))?.failure).toBe('format')
        expect(byUid(folders, CANARY.uid)!.name).toBe('Canary GCM')
    })

    test('classic CBC roots read with useGcm false, also when the ciphertext ends in a zero byte', async () => {
        const blob = cbcBlob(jsonName('CBC Zero'), true)
        expect(blob[blob.length - 1]).toBe(0)

        const {folders, errors} = await readRoots([{uid: rootUid(13), data: blob}, CANARY])

        expect(errors).toEqual([])
        expect(byUid(folders, SHARED_UID)!.name).toBe('Shared Folder')
        expect(byUid(folders, SHARED_UID)!.useGcm).toBe(false)
        expect(byUid(folders, rootUid(13))!.name).toBe('CBC Zero')
        expect(byUid(folders, rootUid(13))!.useGcm).toBe(false)
        expect(byUid(folders, CANARY.uid)!.name).toBe('Canary GCM')
    })

    test('updateFolder writes AES-GCM data for a GCM root and AES-CBC data for a CBC root', async () => {
        const {storage, queryFunction, posted} = await buildFixture(undefined, undefined, [{uid: rootUid(10), data: gcmBlob(jsonName('GCM Root'))}])
        const options = {storage, queryFunction}

        await updateFolder(options, rootUid(10), 'Renamed GCM')
        await updateFolder(options, SHARED_UID, 'Renamed CBC')

        const sent = (uid: string) => webSafe64ToBytes(posted.find(p => p.path === 'update_folder' && p.body.folderUid === uid)!.body.data)
        const gcmName = JSON.parse(platform.bytesToString(await platform.decryptWithKey(sent(rootUid(10)), rootKey))).name
        const cbcName = JSON.parse(platform.bytesToString(await platform.decryptWithKey(sent(SHARED_UID), sharedFolderKey, true))).name
        expect(gcmName).toBe('Renamed GCM')
        expect(cbcName).toBe('Renamed CBC')
    })
})

describe('root folder data too short for AES-GCM (node platform)', () => {
    beforeEach(() => {
        connectPlatform(nodePlatform)
    })

    // Without an explicit tag length Node takes the last 4 bytes of a 12-byte value as the tag, so the
    // forgery check is 32 bits instead of 128. The explicit length makes Node reject the value up front.
    test('the node GCM decrypt rejects a value shorter than nonce plus tag as an invalid tag length', async () => {
        await expect(nodePlatform.decryptWithKey(new Uint8Array(12).fill(7), rootKey)).rejects.toThrow(/Invalid authentication tag length/)
    })

    test('values under the smallest AES-GCM length, and 255 zero bytes, are skipped without throwing', async () => {
        const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
        try {
            const shortRoots: RootFolder[] = [
                {uid: rootUid(14), data: new Uint8Array(12).fill(7)},
                {uid: rootUid(15), data: new Uint8Array(20).fill(7)},
                {uid: rootUid(16), data: new Uint8Array(255)}
            ]

            const {folders, errors} = await readRoots([...shortRoots, CANARY])

            expect(shortRoots.map(r => byUid(folders, r.uid))).toEqual([undefined, undefined, undefined])
            expect(errors.map(e => e.uid).sort()).toEqual(shortRoots.map(r => r.uid).sort())
            expect(byUid(folders, CANARY.uid)!.name).toBe('Canary GCM')
        } finally {
            errorSpy.mockRestore()
        }
    })
})
