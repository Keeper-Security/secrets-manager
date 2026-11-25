// updateFolder changes only the folder name and keeps the other fields of the folder JSON.
//
// The fake server keeps the stored data of each folder, so an update_folder request changes the
// next get_folders reply. Each test decrypts the captured update payload with the folder key and
// compares it with the old complete JSON. Every case runs on the node and browser platforms.

import {getFolders, getSecrets, initialize, initializeStorage, KeeperError, KeeperFolder, SecretManagerOptions, updateFolder, updateSecret} from '../src/keeper'
import {connectPlatform, inMemoryStorage, KeeperHttpResponse, Platform, platform} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'
import {browserPlatform} from '../src/browser/browserPlatform'
import {webSafe64FromBytes, webSafe64ToBytes} from '../src/utils'

// Client-key segment decodes to 32 bytes; WebCrypto validates raw AES key length at import time.
const FAKE_ONE_TIME_TOKEN = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

connectPlatform(nodePlatform)
initialize()

const enc = (s: string): Uint8Array => platform.stringToBytes(s)

// Canonical UIDs: 22 base64url characters, 16 bytes.
const uidOf = (n: number): string => webSafe64FromBytes(new Uint8Array(16).fill(n))
const keyOf = (n: number): Uint8Array => new Uint8Array(32).fill(n)

// JSON.parse makes "__proto__" an own property. A literal in source code would set the prototype.
const FOLDER_JSON = '{"name":"Old Name","color":"red","ext":{"a":[1,{"b":null}]},"nothing":null,"flag":false,"zero":0,' +
    '"label":"Dossier été 名前 🎨","__proto__":{"polluted":true}}'

const renamed = (json: string, name: string): Record<string, unknown> => {
    const expected = JSON.parse(json)
    expected.name = name
    return expected
}

const ownProto = (value: unknown): unknown => {
    expect(Object.prototype.hasOwnProperty.call(value, '__proto__')).toBe(true)
    return Object.getOwnPropertyDescriptor(value, '__proto__')!.value
}

const restores: (() => void)[] = []

// Deterministic random bytes, restored after each test so no later suite sees the stub.
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

const deepFreeze = <T>(value: T): T => {
    if (typeof value === 'object' && value !== null) {
        for (const key of Object.getOwnPropertyNames(value)) {
            deepFreeze((value as any)[key])
        }
        Object.freeze(value)
    }
    return value
}

// corrupt changes the last byte of the encrypted data, so the folder does not decrypt.
type FolderState = { parent?: string, key: Uint8Array, gcm: boolean, json: string, corrupt?: boolean }

// One client: a shared root folder wrapped with the app key, and classic subfolders under it.
// A subfolder key is wrapped with the shared folder key in its own cipher (60 bytes for GCM,
// 64 bytes for CBC). Its data uses the same cipher.
class FakeServer {
    readonly calls: string[] = []
    readonly updates: any[] = []
    readonly secretUpdates: any[] = []
    readonly folders = new Map<string, FolderState>()
    // Records of the shared folder, in the wire format, for the get_secret reply.
    readonly sharedRecords: any[] = []
    // Runs before the reply to the nth get_folders request (1-based), so a test can change the
    // server state between two reads.
    readonly beforeGetFolders: Record<number, () => void> = {}
    // Replaces the reply to the nth get_folders request (1-based), so a test can make a read fail.
    readonly getFoldersReply: Record<number, () => Promise<KeeperHttpResponse>> = {}
    private getFoldersCount = 0

    constructor(readonly appKey: Uint8Array, readonly sharedUid: string, readonly sharedKey: Uint8Array) {
        this.folders.set(sharedUid, {key: sharedKey, gcm: false, json: '{"name":"Shared Folder"}'})
    }

    private async wire(uid: string, state: FolderState): Promise<any> {
        if (!state.parent) {
            return {
                folderUid: uid,
                folderKey: platform.bytesToBase64(await platform.encryptWithKey(state.key, this.appKey)),
                data: platform.bytesToBase64(await platform.encryptWithKey(enc(state.json), state.key, true))
            }
        }
        const data = await platform.encryptWithKey(enc(state.json), state.key, !state.gcm)
        if (state.corrupt) {
            data[data.length - 1] ^= 0xff
        }
        return {
            folderUid: uid,
            parent: state.parent,
            folderKey: platform.bytesToBase64(await platform.encryptWithKey(state.key, this.sharedKey, !state.gcm)),
            data: platform.bytesToBase64(data)
        }
    }

    private async reply(path: string): Promise<any> {
        if (path === 'get_secret') {
            return {folders: [{...await this.wire(this.sharedUid, this.folders.get(this.sharedUid)!), records: this.sharedRecords}], records: [], expiresOn: 0, warnings: []}
        }
        const folders: any[] = []
        for (const [uid, state] of this.folders) {
            folders.push(await this.wire(uid, state))
        }
        return {folders, records: [], expiresOn: 0, warnings: []}
    }

    readonly queryFunction: SecretManagerOptions['queryFunction'] = async (url, tk, encryptedPayload): Promise<KeeperHttpResponse> => {
        const path = pathOf(url)
        this.calls.push(path)
        if (path === 'get_folders') {
            this.getFoldersCount++
            this.beforeGetFolders[this.getFoldersCount]?.()
            const replaced = this.getFoldersReply[this.getFoldersCount]
            if (replaced) {
                return replaced()
            }
        }
        if (path === 'update_secret') {
            this.secretUpdates.push(JSON.parse(platform.bytesToString(await platform.decryptWithKey(encryptedPayload.payload, tk.key))))
            return {data: new Uint8Array(0), statusCode: 200, headers: []}
        }
        if (path === 'update_folder') {
            const body = JSON.parse(platform.bytesToString(await platform.decryptWithKey(encryptedPayload.payload, tk.key)))
            this.updates.push(body)
            // The server replaces the whole folder data, as the real server does.
            const state = this.folders.get(body.folderUid)!
            const plain = await platform.decryptWithKey(webSafe64ToBytes(body.data), state.key, !state.gcm)
            state.json = platform.bytesToString(plain)
            return {data: new Uint8Array(0), statusCode: 200, headers: []}
        }
        return {data: await platform.encryptWithKey(enc(JSON.stringify(await this.reply(path))), tk.key), statusCode: 200, headers: []}
    }

    resetCalls(): void {
        this.calls.length = 0
    }

    async options(): Promise<SecretManagerOptions> {
        const storage = inMemoryStorage({})
        await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
        await storage.saveBytes('appKey', this.appKey)
        return {storage, queryFunction: this.queryFunction}
    }
}

// Decrypts update payload data. Returns undefined when the key or cipher does not fit.
const tryDecryptJson = async (data: string, key: Uint8Array, useCBC: boolean): Promise<unknown> => {
    try {
        return JSON.parse(platform.bytesToString(await platform.decryptWithKey(webSafe64ToBytes(data), key, useCBC)))
    } catch {
        return undefined
    }
}

const SHARED_UID = uidOf(1)
const CBC_UID = uidOf(2)
const GCM_UID = uidOf(3)
const NESTED_CBC_UID = uidOf(4)
const NESTED_GCM_UID = uidOf(5)
const sharedKey = keyOf(11)
const cbcKey = keyOf(12)
const gcmKey = keyOf(13)
const nestedCbcKey = keyOf(14)
const nestedGcmKey = keyOf(15)

const buildServer = (json: string = FOLDER_JSON): FakeServer => {
    stubRandomBytes()
    const server = new FakeServer(keyOf(10), SHARED_UID, sharedKey)
    server.folders.set(CBC_UID, {parent: SHARED_UID, key: cbcKey, gcm: false, json})
    server.folders.set(GCM_UID, {parent: SHARED_UID, key: gcmKey, gcm: true, json})
    server.folders.set(NESTED_CBC_UID, {parent: CBC_UID, key: nestedCbcKey, gcm: false, json})
    server.folders.set(NESTED_GCM_UID, {parent: GCM_UID, key: nestedGcmKey, gcm: true, json})
    return server
}

const strip = (folder: KeeperFolder): Omit<KeeperFolder, 'data'> => {
    const {data: _data, ...rest} = folder
    return rest
}

const platforms: [string, Platform][] = [
    ['node', nodePlatform],
    ['browser', browserPlatform]
]

const subfolders: [string, string, Uint8Array, boolean][] = [
    ['direct CBC child', CBC_UID, cbcKey, false],
    ['direct GCM child', GCM_UID, gcmKey, true],
    ['nested CBC subfolder', NESTED_CBC_UID, nestedCbcKey, false],
    ['nested GCM subfolder', NESTED_GCM_UID, nestedGcmKey, true]
]

describe.each(platforms)('updateFolder keeps the folder data (%s platform)', (_name, plat) => {
    beforeEach(() => {
        connectPlatform(plat)
    })

    test.each(subfolders)('%s: the payload changes only the name, in the cipher and key of the folder', async (_label, uid, key, gcm) => {
        const server = buildServer()
        const options = await server.options()
        const folders = await getFolders(options)
        // Fixture check: the wrapped key has the length of its cipher (60 bytes GCM, 64 bytes CBC).
        expect(webSafe64ToBytes((await (server as any).wire(uid, server.folders.get(uid)!)).folderKey).length).toBe(gcm ? 60 : 64)

        await updateFolder(options, uid, 'New Name', folders)

        expect(server.updates.length).toBe(1)
        const payload = await tryDecryptJson(server.updates[0].data, key, !gcm)
        expect(payload).toEqual(renamed(FOLDER_JSON, 'New Name'))
        expect(ownProto(payload)).toEqual({polluted: true})
        // The other cipher does not read the payload.
        expect(await tryDecryptJson(server.updates[0].data, key, gcm)).not.toEqual(renamed(FOLDER_JSON, 'New Name'))

        const after = (await getFolders(options)).find(f => f.folderUid === uid)!
        expect(after.name).toBe('New Name')
        expect(after.useGcm).toBe(gcm)
        expect(after.data).toEqual(renamed(FOLDER_JSON, 'New Name'))
        expect(ownProto(after.data)).toEqual({polluted: true})
    })

    test('folder JSON without a name key: the payload adds the name and keeps the rest', async () => {
        const json = '{"color":"red","ext":{"x":[0,false,null]}}'
        const server = buildServer(json)
        const options = await server.options()
        const folders = await getFolders(options)
        expect(folders.find(f => f.folderUid === CBC_UID)!.name).toBeUndefined()

        await updateFolder(options, CBC_UID, 'Named', folders)

        expect(await tryDecryptJson(server.updates[0].data, cbcKey, true)).toEqual({color: 'red', ext: {x: [0, false, null]}, name: 'Named'})
    })

    test('a complete supplied list: one request, update_folder only, and the list does not change', async () => {
        const server = buildServer()
        const options = await server.options()
        const folders = deepFreeze(await getFolders(options))
        const snapshot = JSON.parse(JSON.stringify(folders))
        server.resetCalls()

        await updateFolder(options, GCM_UID, 'New Name', folders)

        expect(server.calls).toEqual(['update_folder'])
        expect(JSON.parse(JSON.stringify(folders))).toEqual(snapshot)
        expect(folders.find(f => f.folderUid === GCM_UID)!.data!.name).toBe('Old Name')
        expect(ownProto(folders.find(f => f.folderUid === GCM_UID)!.data)).toEqual({polluted: true})
    })

    test('a saved list (a JSON copy of the getFolders result) keeps its data: one request, update_folder only', async () => {
        const server = buildServer()
        const options = await server.options()
        const saved: KeeperFolder[] = JSON.parse(JSON.stringify(await getFolders(options)))
        server.resetCalls()

        await updateFolder(options, CBC_UID, 'New Name', saved)

        expect(server.calls).toEqual(['update_folder'])
        const payload = await tryDecryptJson(server.updates[0].data, cbcKey, true)
        expect(payload).toEqual(renamed(FOLDER_JSON, 'New Name'))
        expect(ownProto(payload)).toEqual({polluted: true})
    })

    test('a supplied entry with data but no useGcm: one more get_folders, then the GCM cipher of the folder', async () => {
        const server = buildServer()
        const options = await server.options()
        const folders = await getFolders(options)
        const entry = folders.find(f => f.folderUid === GCM_UID)!
        const {useGcm: _unused, ...withoutCipher} = entry
        server.resetCalls()

        await updateFolder(options, GCM_UID, 'New Name', [withoutCipher])

        expect(server.calls).toEqual(['get_folders', 'update_folder'])
        expect(await tryDecryptJson(server.updates[0].data, gcmKey, false)).toEqual(renamed(FOLDER_JSON, 'New Name'))
    })

    // The projection says the wrong cipher, and the server changes the key and the data after the
    // first read. The payload must use the refreshed data, cipher, and key.
    test.each([
        ['GCM folder, projection says CBC', GCM_UID, true],
        ['CBC folder, projection says GCM', CBC_UID, false]
    ])('a supplied object without data (%s): one more get_folders, then the refreshed data, key, and cipher', async (_label, uid, gcm) => {
        const server = buildServer()
        const options = await server.options()
        await getFolders(options)
        const oldKey = server.folders.get(uid)!.key
        const newKey = keyOf(99)
        const newJson = FOLDER_JSON.replace('"red"', '"blue"').replace('Old Name', 'Server Name')
        server.folders.get(uid)!.key = newKey
        server.folders.get(uid)!.json = newJson
        server.resetCalls()
        const projection: KeeperFolder[] = [{folderUid: uid, parentUid: SHARED_UID, name: 'Old Name', useGcm: !gcm}]

        await updateFolder(options, uid, 'New Name', projection)

        expect(server.calls).toEqual(['get_folders', 'update_folder'])
        const data = server.updates[0].data
        expect(await tryDecryptJson(data, newKey, !gcm)).toEqual(renamed(newJson, 'New Name'))
        expect(await tryDecryptJson(data, newKey, gcm)).toBeUndefined()
        expect(await tryDecryptJson(data, oldKey, !gcm)).toBeUndefined()
        expect(projection).toEqual([{folderUid: uid, parentUid: SHARED_UID, name: 'Old Name', useGcm: !gcm}])
    })

    test('a supplied object without data, and the new read does not list the folder: KeeperError, no update', async () => {
        const server = buildServer()
        const options = await server.options()
        await getFolders(options)
        server.folders.delete(NESTED_CBC_UID)
        server.folders.delete(CBC_UID)
        server.resetCalls()

        const error = await updateFolder(options, CBC_UID, 'x', [{folderUid: CBC_UID, parentUid: SHARED_UID, useGcm: false}]).catch(e => e)

        expect(error).toBeInstanceOf(KeeperError)
        expect(error.message).toBe(`Unable to update folder - folder ${CBC_UID} was not found in the folder list`)
        expect(server.calls).toEqual(['get_folders'])
        expect(server.updates).toEqual([])
    })

    // A failed new read must stop the call before it sends the update. A folder that does not
    // decrypt is left out of the list, so the call gives the not-found error.
    test.each([
        ['the request throws', (server: FakeServer) => { server.getFoldersReply[2] = () => Promise.reject(new Error('read failed')) }, 'read failed'],
        ['the server answers with status 500', (server: FakeServer) => { server.getFoldersReply[2] = async () => ({data: new Uint8Array(0), statusCode: 500, headers: []}) }, ''],
        ['the folder does not decrypt', (server: FakeServer) => { server.folders.get(CBC_UID)!.corrupt = true }, `Unable to update folder - folder ${CBC_UID} was not found in the folder list`]
    ])('a supplied object without data, and the new read fails because %s: an error, no update', async (_label, fail, message) => {
        jest.spyOn(console, 'error').mockImplementation(() => {})
        restores.push(() => jest.restoreAllMocks())
        const server = buildServer()
        const options = await server.options()
        await getFolders(options)
        fail(server)
        server.resetCalls()

        const error = await updateFolder(options, CBC_UID, 'x', [{folderUid: CBC_UID, parentUid: SHARED_UID, useGcm: false}]).catch(e => e)

        expect(error).toBeInstanceOf(Error)
        if (message) {
            expect(error.message).toBe(message)
        }
        expect(server.calls).toEqual(['get_folders'])
        expect(server.updates).toEqual([])
    })

    // JSON null is not in this list: getFolders skips such a folder, so the "not found" check applies.
    test.each([['an array', '[1,2]'], ['a string', '"text"'], ['a number', '0']])(
        'a supplied object without data, and the new read gives JSON that is %s: KeeperError, no update', async (_label, json) => {
            const server = buildServer()
            const options = await server.options()
            await getFolders(options)
            server.folders.get(CBC_UID)!.json = json
            server.resetCalls()

            const error = await updateFolder(options, CBC_UID, 'x', [{folderUid: CBC_UID, parentUid: SHARED_UID, useGcm: false}]).catch(e => e)

            expect(error).toBeInstanceOf(KeeperError)
            expect(error.message).toBe(`Unable to update folder - complete folder data for ${CBC_UID} not found`)
            expect(server.calls).toEqual(['get_folders'])
            expect(server.updates).toEqual([])
        })

    test.each([['an array', '[1,2]'], ['a string', '"text"']])('no list, and the folder JSON is %s: KeeperError after exactly one get_folders', async (_label, json) => {
        const server = buildServer()
        server.folders.get(GCM_UID)!.json = json
        const options = await server.options()
        await getFolders(options)
        server.resetCalls()

        const error = await updateFolder(options, GCM_UID, 'x').catch(e => e)

        expect(error).toBeInstanceOf(KeeperError)
        expect(error.message).toBe(`Unable to update folder - complete folder data for ${GCM_UID} not found`)
        expect(server.calls).toEqual(['get_folders'])
        expect(server.updates).toEqual([])
    })

    test.each([['null', null], ['an array', ['x']], ['a string', 'text']])('supplied data that is %s counts as missing: one more read, then the refreshed data', async (_label, bad) => {
        const server = buildServer()
        const options = await server.options()
        const folders = (await getFolders(options)).map(f => f.folderUid === GCM_UID ? {...f, data: bad as any} : f)
        const refreshed = FOLDER_JSON.replace('"red"', '"green"')
        server.folders.get(GCM_UID)!.json = refreshed
        server.resetCalls()

        await updateFolder(options, GCM_UID, 'New Name', folders)

        expect(server.calls).toEqual(['get_folders', 'update_folder'])
        expect(await tryDecryptJson(server.updates[0].data, gcmKey, false)).toEqual(renamed(refreshed, 'New Name'))
        expect(folders.find(f => f.folderUid === GCM_UID)!.data).toEqual(bad)
    })

    test('getFolders exposes the decrypted JSON as data and keeps name, parentUid, and useGcm', async () => {
        const server = buildServer()
        const options = await server.options()

        const folders = await getFolders(options)

        // The cipher flag of a top-level folder is not part of this change, so the root check
        // leaves out useGcm.
        const {useGcm: _rootUseGcm, ...root} = strip(folders[0])
        expect(root).toEqual({folderUid: SHARED_UID, name: 'Shared Folder'})
        expect(folders.slice(1).map(strip)).toEqual([
            {folderUid: CBC_UID, parentUid: SHARED_UID, name: 'Old Name', useGcm: false},
            {folderUid: GCM_UID, parentUid: SHARED_UID, name: 'Old Name', useGcm: true},
            {folderUid: NESTED_CBC_UID, parentUid: CBC_UID, name: 'Old Name', useGcm: false},
            {folderUid: NESTED_GCM_UID, parentUid: GCM_UID, name: 'Old Name', useGcm: true}
        ])
        expect(folders[0].data).toEqual({name: 'Shared Folder'})
        for (const folder of folders.slice(1)) {
            expect(folder.data).toEqual(JSON.parse(FOLDER_JSON))
            expect(ownProto(folder.data)).toEqual({polluted: true})
        }
    })

    test('getFolders sets no data when the folder JSON is not an object', async () => {
        const server = buildServer()
        server.folders.get(CBC_UID)!.json = '["a"]'
        const options = await server.options()

        const folder = (await getFolders(options)).find(f => f.folderUid === CBC_UID)!

        expect(folder.data).toBeUndefined()
        expect('data' in folder).toBe(false)
    })
})

describe.each(platforms)('updateFolder with an empty and a populated key cache (%s platform)', (_name, plat) => {
    beforeEach(() => {
        connectPlatform(plat)
    })

    const expectRenamed = async (server: FakeServer) => {
        expect(server.updates.length).toBe(1)
        expect(await tryDecryptJson(server.updates[0].data, nestedGcmKey, false)).toEqual(renamed(FOLDER_JSON, 'New Name'))
    }

    test('populated cache, no list', async () => {
        const server = buildServer()
        const options = await server.options()
        await getFolders(options)
        server.resetCalls()

        await updateFolder(options, NESTED_GCM_UID, 'New Name')

        expect(server.calls).toEqual(['get_folders', 'update_folder'])
        await expectRenamed(server)
    })

    test('populated cache, an empty list counts as no list', async () => {
        const server = buildServer()
        const options = await server.options()
        await getFolders(options)
        server.resetCalls()

        await updateFolder(options, NESTED_GCM_UID, 'New Name', [])

        expect(server.calls).toEqual(['get_folders', 'update_folder'])
        await expectRenamed(server)
    })

    // The new read must not clear the record keys that getSecrets cached.
    test('a supplied object without data: the record keys from getSecrets stay usable after the rename', async () => {
        const server = buildServer()
        const recordUid = uidOf(40)
        const recordKey = keyOf(40)
        server.sharedRecords.push({
            recordUid,
            recordKey: platform.bytesToBase64(await platform.encryptWithKey(recordKey, sharedKey)),
            data: platform.bytesToBase64(await platform.encryptWithKey(enc('{"title":"Rec","type":"login","fields":[]}'), recordKey)),
            revision: 1,
            files: []
        })
        const options = await server.options()
        const secrets = await getSecrets(options)
        expect(secrets.records.map(r => r.recordUid)).toEqual([recordUid])
        server.resetCalls()

        await updateFolder(options, CBC_UID, 'New Name', [{folderUid: CBC_UID, parentUid: SHARED_UID, useGcm: false}])
        await updateSecret(options, secrets.records[0])

        expect(server.calls).toEqual(['get_folders', 'update_folder', 'update_secret'])
        const sent = await platform.decryptWithKey(webSafe64ToBytes(server.secretUpdates[0].data), recordKey)
        expect(JSON.parse(platform.bytesToString(sent)).title).toBe('Rec')
    })

    test('empty cache, no list', async () => {
        const server = buildServer()
        const options = await server.options()
        platform.cleanKeyCache()

        await updateFolder(options, NESTED_GCM_UID, 'New Name')

        expect(server.calls).toEqual(['get_secret', 'get_folders', 'update_folder'])
        await expectRenamed(server)
    })

    test('empty cache, a supplied object without data', async () => {
        const server = buildServer()
        const options = await server.options()
        platform.cleanKeyCache()

        await updateFolder(options, NESTED_GCM_UID, 'New Name', [{folderUid: NESTED_GCM_UID, parentUid: GCM_UID, useGcm: true}])

        expect(server.calls).toEqual(['get_secret', 'get_folders', 'update_folder'])
        await expectRenamed(server)
    })

    // A complete list does not cause a folder read, and the get_secret warm-up does not give the
    // subfolder key. The call fails before it sends a request. getSecrets also clears the key cache,
    // so getFolders, then getSecrets, then a rename with that list fails the same way.
    test('empty cache, a supplied complete list: the call fails and sends no update', async () => {
        const server = buildServer()
        const options = await server.options()
        const folders = await getFolders(options)
        platform.cleanKeyCache()
        server.resetCalls()

        await expect(updateFolder(options, NESTED_GCM_UID, 'New Name', folders)).rejects.toThrow(`Unable to load the key ${NESTED_GCM_UID}`)

        expect(server.calls).toEqual(['get_secret'])
        expect(server.updates).toEqual([])
    })
})

describe.each(platforms)('two clients keep their folder data and keys separate (%s platform)', (_name, plat) => {
    beforeEach(() => {
        connectPlatform(plat)
    })

    test('each payload holds only the data of its own client and decrypts only with its own folder key', async () => {
        const jsonA = '{"name":"A","color":"red","owner":"client A"}'
        const jsonB = '{"name":"B","color":"blue","owner":"client B","extra":[1]}'
        stubRandomBytes()
        const serverA = new FakeServer(keyOf(20), uidOf(21), keyOf(21))
        serverA.folders.set(uidOf(22), {parent: uidOf(21), key: keyOf(22), gcm: true, json: jsonA})
        const serverB = new FakeServer(keyOf(30), uidOf(31), keyOf(31))
        serverB.folders.set(uidOf(32), {parent: uidOf(31), key: keyOf(32), gcm: true, json: jsonB})
        const optionsA = await serverA.options()
        const optionsB = await serverB.options()

        // Interleaved reads: each list holds the data of its own client.
        const listA = await getFolders(optionsA)
        const listB = await getFolders(optionsB)
        expect(listA.find(f => f.folderUid === uidOf(22))!.data).toEqual(JSON.parse(jsonA))
        expect(listB.find(f => f.folderUid === uidOf(32))!.data).toEqual(JSON.parse(jsonB))

        // The key cache is not scoped per client, so read each client again before its rename.
        await getFolders(optionsA)
        await updateFolder(optionsA, uidOf(22), 'A2', listA)
        await getFolders(optionsB)
        await updateFolder(optionsB, uidOf(32), 'B2')

        expect(serverA.updates.length).toBe(1)
        expect(serverB.updates.length).toBe(1)
        const payloadA = serverA.updates[0].data
        const payloadB = serverB.updates[0].data
        expect(await tryDecryptJson(payloadA, keyOf(22), false)).toEqual(renamed(jsonA, 'A2'))
        expect(await tryDecryptJson(payloadB, keyOf(32), false)).toEqual(renamed(jsonB, 'B2'))
        expect(await tryDecryptJson(payloadA, keyOf(32), false)).toBeUndefined()
        expect(await tryDecryptJson(payloadB, keyOf(22), false)).toBeUndefined()
        expect(listA.find(f => f.folderUid === uidOf(22))!.data).toEqual(JSON.parse(jsonA))
        expect(listB.find(f => f.folderUid === uidOf(32))!.data).toEqual(JSON.parse(jsonB))
    })
})
