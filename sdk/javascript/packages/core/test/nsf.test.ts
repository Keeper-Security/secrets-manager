// NSF (Keeper Drive) behavior: record writes into an NSF folder, listing NSF folders on request,
// and client-side refusal of NSF folder writes. Each scenario runs once per platform: the browser
// platform binds a CryptoKey to one algorithm, so a wrong cache slot for the NSF folder key would
// only show there.

import {mkdtempSync, rmSync} from 'fs'
import {tmpdir} from 'os'
import {join} from 'path'
import {
    createFolder, createSecret, createSecret2, deleteFolder, getFolders, getSecrets, initialize, initializeStorage,
    KeeperFolder, SecretManagerOptions, updateFolder, updateSecret
} from '../src/keeper'
import {connectPlatform, inMemoryStorage, KeeperHttpResponse, KeyValueStorage, Platform, platform} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'
import {browserPlatform} from '../src/browser/browserPlatform'
import {createCachingFunction as createNodeCachingFunction} from '../src/node/localConfigStorage'
import {createCachingFunction as createBrowserCachingFunction} from '../src/browser/localConfigStorage'
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
// an NSF create must not need one. A test that creates a classic record saves ownerPublicKey.
// With bound false, the client has no app key yet, so its first get_secret request binds it.
const buildFixture = async ({bound = true}: {bound?: boolean} = {}): Promise<{
    storage: ReturnType<typeof inMemoryStorage>
    queryFunction: SecretManagerOptions['queryFunction']
    posted: PostedBody[]
    calls: string[]
    ownerPublicKey: Uint8Array
}> => {
    const nsfRecordData = b64(await platform.encryptWithKey(enc(JSON.stringify({title: 'Drive record', type: 'login', fields: []})), nsfRecordKey))
    const classicRecordData = b64(await platform.encryptWithKey(enc(JSON.stringify({title: 'Classic record', type: 'login', fields: []})), classicRecordKey))

    const ownerStorage = inMemoryStorage({})
    await platform.generatePrivateKey('owner', ownerStorage)
    const ownerPublicKey = await platform.exportPublicKey('owner', ownerStorage)

    const secretFolders = [
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
    ]

    // As on the server, requestedFolders limits the records. Every classic shared folder keeps its entry
    // and its key. The fixture leaves out an NSF folder outside the filter. An empty filter is no filter.
    // A request with a public key comes from a client with no app key yet. The reply then holds the app key.
    const secretReply = async (body: any): Promise<Uint8Array> => {
        const requested: string[] | undefined = body.requestedFolders?.length ? body.requestedFolders : undefined
        const folders = secretFolders.flatMap(f => !requested || requested.includes(f.folderUid) ? [f] : f.data ? [] : [{...f, records: []}])
        const binding = body.publicKey ? {
            encryptedAppKey: b64(await platform.encryptWithKey(appKey, webSafe64ToBytes(FAKE_ONE_TIME_TOKEN))),
            appOwnerPublicKey: b64(ownerPublicKey)
        } : {}
        return platform.encryptWithKey(enc(JSON.stringify({folders, records: [], expiresOn: 0, warnings: [], ...binding})), transmissionKey)
    }

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
    if (bound) {
        await storage.saveBytes('appKey', appKey)
    }

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
                responseBytes = await secretReply(body)
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

    return {storage, queryFunction, posted, calls, ownerPublicKey}
}

// Sends each platform.post call to the fixture server, so the default transport and
// createCachingFunction run as for a real caller. As on the server, a successful create_secret
// gets an empty body. Node reads it as null, and the browser reads it as an empty array.
const stubServer = (plat: Platform, server: NonNullable<SecretManagerOptions['queryFunction']>): {offline: boolean, refuseCreate: boolean} => {
    const state = {offline: false, refuseCreate: false}
    const target = platform
    const original = target.post
    target.post = async (url: string, request: Uint8Array): Promise<KeeperHttpResponse> => {
        if (state.offline) {
            throw new Error('connect ECONNREFUSED')
        }
        const response = await server(url, {publicKeyId: 0, key: transmissionKey, encryptedKey: new Uint8Array()}, {payload: request, signature: new Uint8Array()})
        if (pathOf(url) !== 'create_secret') {
            return response
        }
        if (state.refuseCreate) {
            return {statusCode: 403, headers: [], data: enc(JSON.stringify({error: 'access_denied', message: 'Access denied'}))}
        }
        return {statusCode: 200, headers: [], data: (plat === nodePlatform ? null : new Uint8Array(0)) as Uint8Array}
    }
    restores.push(() => { target.post = original })
    return state
}

// The offline cache that a caller passes as queryFunction. On Node, it keeps the last reply in a
// file in a new temporary folder. In the browser, it keeps the last reply in the config storage.
const cachingFunction = (plat: Platform, storage: KeyValueStorage): SecretManagerOptions['queryFunction'] => {
    if (plat !== nodePlatform) {
        return createBrowserCachingFunction(storage)
    }
    const dir = mkdtempSync(join(tmpdir(), 'ksm-nsf-cache-'))
    restores.push(() => rmSync(dir, {recursive: true, force: true}))
    return createNodeCachingFunction(storage, {cachePath: join(dir, 'ksm-cache.dat')})
}

const newRecord = {title: 'New record', type: 'login', fields: []}

const createFlows: [string, (options: SecretManagerOptions) => Promise<string>][] = [
    ['createSecret in a classic shared folder', options => createSecret(options, SHARED_UID, newRecord)],
    ['createSecret2 in a classic subfolder', options => createSecret2(options, {folderUid: SHARED_UID, subFolderUid: SUBFOLDER_UID}, newRecord)],
    ['createSecret2 in an NSF folder', options => createSecret2(options, {folderUid: NSF_UID}, newRecord)]
]

const recordUids = (records: {recordUid: string}[]): string[] => records.map(r => r.recordUid).sort()
const ALL_RECORD_UIDS = [NSF_RECORD_UID, CLASSIC_RECORD_UID].sort()

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
        expect(lookup.requestedFolders).toBeUndefined()
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

    test('the folder lookup through a custom queryFunction has no folder filter, also when the first request binds the client', async () => {
        const {storage, queryFunction, posted, calls} = await buildFixture({bound: false})

        await createSecret({storage, queryFunction}, NSF_UID, newRecord)

        expect(calls).toEqual(['get_secret', 'get_secret', 'create_secret'])
        const lookups = posted.filter(p => p.path === 'get_secret').map(p => p.body)
        expect(lookups).toHaveLength(2)
        expect(lookups[0].publicKey).toBeDefined()
        expect(lookups.map(body => body.requestedFolders)).toEqual([undefined, undefined])
    })

    test('the folder lookup with no custom queryFunction filters by the target folders, also when the first request binds the client', async () => {
        const {storage, queryFunction, posted} = await buildFixture({bound: false})
        stubServer(plat, queryFunction!)

        await createSecret({storage}, NSF_UID, newRecord)
        await createSecret2({storage}, {folderUid: SHARED_UID, subFolderUid: SUBFOLDER_UID}, newRecord)

        const lookups = posted.filter(p => p.path === 'get_secret').map(p => p.body)
        expect(lookups[0].publicKey).toBeDefined()
        expect(lookups.map(body => body.requestedFolders)).toEqual([[NSF_UID], [NSF_UID], [SHARED_UID, SUBFOLDER_UID]])
    })

    test.each(createFlows)('%s that the server refuses keeps all records for an offline getSecrets', async (_flow, create) => {
        const {storage, queryFunction, ownerPublicKey} = await buildFixture()
        await storage.saveBytes('appOwnerPublicKey', ownerPublicKey)
        const server = stubServer(plat, queryFunction!)
        const options = {storage, queryFunction: cachingFunction(plat, storage)}
        expect(recordUids((await getSecrets(options)).records)).toEqual(ALL_RECORD_UIDS)

        server.refuseCreate = true
        await expect(create(options)).rejects.toThrow('access_denied')
        server.offline = true

        expect(recordUids((await getSecrets(options)).records)).toEqual(ALL_RECORD_UIDS)
    })
})

// The browser cache keeps the empty body of a successful create_secret request, as in version 17.6.0.
// An offline getSecrets call after a successful createSecret call therefore works only on Node.
// Only Node runs these tests.
describe('NSF folder lookup and the Node offline cache', () => {
    beforeEach(() => {
        connectPlatform(nodePlatform)
    })

    test.each(createFlows)('%s keeps all records for an offline getSecrets', async (_flow, create) => {
        const {storage, queryFunction, ownerPublicKey} = await buildFixture()
        await storage.saveBytes('appOwnerPublicKey', ownerPublicKey)
        const server = stubServer(nodePlatform, queryFunction!)
        const options = {storage, queryFunction: cachingFunction(nodePlatform, storage)}
        expect(recordUids((await getSecrets(options)).records)).toEqual(ALL_RECORD_UIDS)

        await create(options)
        server.offline = true

        expect(recordUids((await getSecrets(options)).records)).toEqual(ALL_RECORD_UIDS)
    })

    test('createSecret as the first call keeps all records for an offline getSecrets', async () => {
        const {storage, queryFunction, ownerPublicKey} = await buildFixture()
        await storage.saveBytes('appOwnerPublicKey', ownerPublicKey)
        const server = stubServer(nodePlatform, queryFunction!)
        const options = {storage, queryFunction: cachingFunction(nodePlatform, storage)}

        await createSecret(options, SHARED_UID, newRecord)
        server.offline = true

        expect(recordUids((await getSecrets(options)).records)).toEqual(ALL_RECORD_UIDS)
    })
})
