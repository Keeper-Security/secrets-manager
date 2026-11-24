// NSF (Keeper Drive) behavior: record writes into an NSF folder, listing NSF folders on request,
// and client-side refusal of NSF folder writes. Each scenario runs once per platform: the browser
// platform binds a CryptoKey to one algorithm, so a wrong cache slot for the NSF folder key would
// only show there.

import {
    createFolder, createSecret, deleteFolder, getFolders, getSecrets, initialize, initializeStorage,
    KeeperFolder, SecretManagerOptions, updateFolder, updateSecret
} from '../src/keeper'
import {connectPlatform, inMemoryStorage, KeeperHttpResponse, Platform, platform} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'
import {browserPlatform} from '../src/browser/browserPlatform'
import {webSafe64ToBytes} from '../src/utils'

const FAKE_ONE_TIME_TOKEN = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

connectPlatform(nodePlatform)
initialize()

const enc = (s: string): Uint8Array => platform.stringToBytes(s)

// Canonical UIDs: 22 base64url characters, 16 bytes.
const NSF_UID = 'AQEBAQEBAQEBAQEBAQEBAQ'
const NSF_RECORD_UID = 'AgICAgICAgICAgICAgICAg'
const SHARED_UID = 'AwMDAwMDAwMDAwMDAwMDAw'
const SUBFOLDER_UID = 'BAQEBAQEBAQEBAQEBAQEBA'
const CLASSIC_RECORD_UID = 'BQUFBQUFBQUFBQUFBQUFBQ'

const transmissionKey = new Uint8Array(32).fill(1)
const appKey = new Uint8Array(32).fill(2)
const nsfFolderKey = new Uint8Array(32).fill(3)
const sharedFolderKey = new Uint8Array(32).fill(4)
const subfolderKey = new Uint8Array(32).fill(5)
const nsfRecordKey = new Uint8Array(32).fill(6)
const classicRecordKey = new Uint8Array(32).fill(7)

const CREATE_REFUSED = 'Unable to create folder - the SDK cannot create a folder in an NSF (Keeper Drive) folder.'
const UPDATE_REFUSED = 'Unable to update folder - the SDK cannot update an NSF (Keeper Drive) folder.'

type PostedBody = { path: string, body: any }

const restores: (() => void)[] = []

// Pins the random bytes so the transmission key is the one the fixture encrypts responses with.
// Restored after each test so no later suite sees the stub.
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

const pathOf = (url: string): string => url.substring(url.lastIndexOf('/') + 1)

const b64 = (data: Uint8Array): string => platform.bytesToBase64(data)

// The application owns one NSF folder (GCM key and GCM name, with one record), one classic shared
// folder with a record and a CBC subfolder. get_secret lists the NSF folder and the shared folder;
// only the NSF entry carries folder `data`, which is the server's NSF signal. get_folders lists the
// classic folders only. The app has no owner public key, so a classic-style create would fail:
// an NSF create must not need one.
const buildFixture = async (): Promise<{
    storage: ReturnType<typeof inMemoryStorage>
    queryFunction: SecretManagerOptions['queryFunction']
    posted: PostedBody[]
    calls: string[]
}> => {
    const nsfRecordData = b64(await platform.encryptWithKey(enc(JSON.stringify({title: 'Drive record', type: 'login', fields: []})), nsfRecordKey))
    const classicRecordData = b64(await platform.encryptWithKey(enc(JSON.stringify({title: 'Classic record', type: 'login', fields: []})), classicRecordKey))

    const secretResponse = await platform.encryptWithKey(enc(JSON.stringify({
        folders: [
            {
                folderUid: NSF_UID,
                folderKey: b64(await platform.encryptWithKey(nsfFolderKey, appKey)),
                data: b64(await platform.encryptWithKey(enc(JSON.stringify({name: 'Drive'})), nsfFolderKey)),
                records: [{
                    recordUid: NSF_RECORD_UID,
                    recordKey: b64(await platform.encryptWithKey(nsfRecordKey, nsfFolderKey)),
                    data: nsfRecordData,
                    revision: 1
                }]
            },
            {
                folderUid: SHARED_UID,
                folderKey: b64(await platform.encryptWithKey(sharedFolderKey, appKey)),
                records: [{
                    recordUid: CLASSIC_RECORD_UID,
                    recordKey: b64(await platform.encryptWithKey(classicRecordKey, sharedFolderKey)),
                    data: classicRecordData,
                    revision: 1
                }]
            }
        ],
        records: [], expiresOn: 0, warnings: []
    })), transmissionKey)

    const foldersResponse = await platform.encryptWithKey(enc(JSON.stringify({
        folders: [
            {
                folderUid: SHARED_UID,
                folderKey: b64(await platform.encryptWithKey(sharedFolderKey, appKey)),
                data: b64(await platform.encryptWithKey(enc(JSON.stringify({name: 'Shared Folder'})), sharedFolderKey, true))
            },
            {
                folderUid: SUBFOLDER_UID,
                folderKey: b64(await platform.encryptWithKey(subfolderKey, sharedFolderKey, true)),
                data: b64(await platform.encryptWithKey(enc(JSON.stringify({name: 'Subfolder'})), subfolderKey, true)),
                parent: SHARED_UID
            }
        ],
        records: [], expiresOn: 0, warnings: []
    })), transmissionKey)

    stubRandomBytes()

    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    await storage.saveBytes('appKey', appKey)

    const posted: PostedBody[] = []
    const calls: string[] = []
    const queryFunction: SecretManagerOptions['queryFunction'] = async (url, tk, encryptedPayload): Promise<KeeperHttpResponse> => {
        const path = pathOf(url)
        calls.push(path)
        const body = JSON.parse(platform.bytesToString(await platform.decryptWithKey(encryptedPayload.payload, tk.key)))
        posted.push({path, body})
        let responseBytes: Uint8Array
        switch (path) {
            case 'get_secret':
                responseBytes = secretResponse
                break
            case 'get_folders':
                responseBytes = foldersResponse
                break
            case 'delete_folder':
                responseBytes = await platform.encryptWithKey(enc(JSON.stringify({
                    folders: body.folderUids.map((folderUid: string) => ({folderUid, responseCode: 'ok', errorMessage: ''}))
                })), transmissionKey)
                break
            default:
                responseBytes = await platform.encryptWithKey(enc('{}'), transmissionKey)
        }
        return {data: responseBytes, statusCode: 200, headers: []}
    }

    return {storage, queryFunction, posted, calls}
}

const platforms: [string, Platform][] = [
    ['node', nodePlatform],
    ['browser', browserPlatform]
]

describe.each(platforms)('NSF (%s platform)', (_name, plat) => {
    beforeEach(() => {
        connectPlatform(plat)
    })

    test('getSecrets marks records in an NSF folder isDrive and leaves classic records unmarked', async () => {
        const {storage, queryFunction} = await buildFixture()

        const secrets = await getSecrets({storage, queryFunction})

        const nsfRecord = secrets.records.find(r => r.recordUid === NSF_RECORD_UID)!
        const classicRecord = secrets.records.find(r => r.recordUid === CLASSIC_RECORD_UID)!
        expect(nsfRecord.isDrive).toBe(true)
        expect(classicRecord.isDrive).toBeFalsy()
    })

    test('getFolders lists NSF folders only with includeNsf, through one unfiltered get_secret', async () => {
        const {storage, queryFunction, posted, calls} = await buildFixture()

        const withoutNsf = await getFolders({storage, queryFunction})
        expect(calls).toEqual(['get_folders'])
        expect(withoutNsf.map(f => f.folderUid).sort()).toEqual([SHARED_UID, SUBFOLDER_UID].sort())
        expect(withoutNsf.some(f => f.isDrive)).toBe(false)

        calls.length = 0
        posted.length = 0
        const withNsf = await getFolders({storage, queryFunction}, true)

        expect(calls).toEqual(['get_folders', 'get_secret'])
        const secretRequest = posted.find(p => p.path === 'get_secret')!.body
        expect(secretRequest.requestedRecords).toBeUndefined()
        expect(secretRequest.requestedFolders).toBeUndefined()
        const nsf = withNsf.find(f => f.folderUid === NSF_UID)!
        expect(nsf.isDrive).toBe(true)
        expect(nsf.name).toBe('Drive')
        expect(nsf.parentUid).toBeUndefined()
        expect(withNsf.filter(f => f.folderUid !== NSF_UID).some(f => f.isDrive)).toBe(false)
    })

    test('createSecret in an NSF folder wraps the record key with the folder key and needs no owner key', async () => {
        const {storage, queryFunction, posted} = await buildFixture()
        const recordData = {title: 'New record', type: 'login', fields: []}

        await createSecret({storage, queryFunction}, NSF_UID, recordData)

        const lookup = posted.find(p => p.path === 'get_secret')!.body
        expect(lookup.requestedFolders).toEqual([NSF_UID])
        expect(lookup.requestedRecords).toBeUndefined()
        const create = posted.find(p => p.path === 'create_secret')!.body
        expect(create.folderUid).toBe(NSF_UID)
        expect(create.folderKey).toBeUndefined()
        const wrappedRecordKey = platform.base64ToBytes(create.recordKey)
        expect(wrappedRecordKey.length).toBe(60)
        const unwrapped = await platform.decryptWithKey(wrappedRecordKey, nsfFolderKey)
        expect(unwrapped.length).toBe(32)
        expect(JSON.stringify(create)).not.toContain(b64(unwrapped))
        const encryptedData = webSafe64ToBytes(create.data)
        expect(encryptedData.length).toBeGreaterThanOrEqual(412)
        const plaintext = platform.bytesToString(await platform.decryptWithKey(encryptedData, unwrapped))
        expect(plaintext.startsWith(JSON.stringify(recordData))).toBe(true)
        expect(plaintext.slice(JSON.stringify(recordData).length).trim()).toBe('')
        expect(JSON.parse(plaintext)).toEqual(recordData)
    })

    test('createFolder in an NSF folder throws and sends no request', async () => {
        const {storage, queryFunction, calls} = await buildFixture()
        const options = {storage, queryFunction}
        const folders: KeeperFolder[] = await getFolders(options, true)
        calls.length = 0

        await expect(createFolder(options, {folderUid: NSF_UID}, 'Child', folders)).rejects.toThrow(CREATE_REFUSED)

        expect(calls).toEqual([])
    })

    test('updateFolder on an NSF folder throws and sends no request', async () => {
        const {storage, queryFunction, calls} = await buildFixture()
        const options = {storage, queryFunction}
        const folders: KeeperFolder[] = await getFolders(options, true)
        calls.length = 0

        await expect(updateFolder(options, NSF_UID, 'Renamed', folders)).rejects.toThrow(UPDATE_REFUSED)

        expect(calls).toEqual([])
    })

    test('deleteFolder sends only classic subfolders, refuses roots and NSF folders, and keeps caller order', async () => {
        const {storage, queryFunction, posted, calls} = await buildFixture()

        const response = await deleteFolder({storage, queryFunction}, [SHARED_UID, NSF_UID, SUBFOLDER_UID])

        expect(calls).toEqual(['get_folders', 'delete_folder'])
        expect(posted.find(p => p.path === 'delete_folder')!.body.folderUids).toEqual([SUBFOLDER_UID])
        expect(response.folders.map(f => [f.folderUid, f.responseCode])).toEqual([
            [SHARED_UID, 'access_denied'],
            [NSF_UID, 'doesnt_exist'],
            [SUBFOLDER_UID, 'ok']
        ])
    })

    test('deleteFolder sends no delete request when every folder is refused', async () => {
        const {storage, queryFunction, calls} = await buildFixture()

        const response = await deleteFolder({storage, queryFunction}, [NSF_UID])

        expect(calls).toEqual(['get_folders'])
        expect(response.folders.map(f => [f.folderUid, f.responseCode])).toEqual([[NSF_UID, 'doesnt_exist']])
    })

    test('deleteFolder leaves the cached record keys in place', async () => {
        const {storage, queryFunction, calls} = await buildFixture()
        const options = {storage, queryFunction}
        const record = (await getSecrets(options)).records.find(r => r.recordUid === CLASSIC_RECORD_UID)!

        await deleteFolder(options, [SUBFOLDER_UID])
        calls.length = 0
        await updateSecret(options, record)

        expect(calls).toEqual(['update_secret'])
    })

    test('deleteFolder returns without throwing when the server gives no result for a sent folder', async () => {
        const {storage, queryFunction} = await buildFixture()
        const emptyDeleteResponse: SecretManagerOptions['queryFunction'] = async (url, tk, encryptedPayload) => {
            const response = await queryFunction!(url, tk, encryptedPayload)
            if (pathOf(url) !== 'delete_folder') {
                return response
            }
            return {...response, data: await platform.encryptWithKey(enc(JSON.stringify({folders: []})), transmissionKey)}
        }

        const response = await deleteFolder({storage, queryFunction: emptyDeleteResponse}, [SUBFOLDER_UID])

        expect(response.folders).toEqual([])
    })
})
