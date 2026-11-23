import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import * as https from 'https'
import {createECDH} from 'crypto'
import {EventEmitter} from 'events'
import {createSecret, createSecret2, deleteSecret, getFolders, getSecrets2, initialize, initializeStorage, QueryOptions, SecretManagerOptions} from '../src/keeper'
import {connectPlatform, inMemoryStorage, KeyValueStorage, platform} from '../src/platform'
import {browserPlatform} from '../src/browser/browserPlatform'
import {nodePlatform} from '../src/node/nodePlatform'
import {createCachingFunction as browserCache} from '../src/browser/localConfigStorage'
import {createCachingFunction as nodeCache} from '../src/node/localConfigStorage'

jest.mock('https', () => ({request: jest.fn()}))

const APP_KEY = new Uint8Array(32).fill(1)
const CLIENT_KEY = new Uint8Array(32).fill(2)
const READ_REPLY = {records: [], warnings: ['Saved read reply']}
const FOLDERS = [{folderUid: 'folder-a', name: 'Folder A'}]
const SCOPE: QueryOptions = {
    recordsFilter: ['record-a'],
    foldersFilter: ['folder-a'],
    requestLinks: true
}

type RequestBody = {publicKey?: string}
type Reply = {status?: number, body: unknown}

const makeServerPublicKey = () => {
    const keyPair = createECDH('prime256v1')
    keyPair.generateKeys()
    return keyPair.getPublicKey().toString('base64url')
}

describe.each([
    ['Node', nodePlatform],
    ['browser', browserPlatform]
] as const)('read cache scope (%s)', (_name, implementation) => {
    const browser = implementation === browserPlatform
    let storage: KeyValueStorage
    let options: SecretManagerOptions
    let tempDir: string | undefined
    let cachePath: string
    let transmissionKey: Uint8Array
    let offline: Error
    const reply = jest.fn<Promise<Reply>, [string, RequestBody]>()
    const nodeRequest = https.request as unknown as jest.Mock

    const respond = async (url: string, payload: Uint8Array) => {
        const key = transmissionKey
        const request = JSON.parse(platform.bytesToString(await platform.decryptWithKey(payload, key))) as RequestBody
        const {status = 200, body} = await reply(url, request)
        const plaintext = platform.stringToBytes(JSON.stringify(body))
        const data = status === 200 ? await platform.encryptWithKey(plaintext, key) : plaintext
        return {status, data}
    }

    const readCache = async () => browser ? storage.getBytes('cache') : fs.readFileSync(cachePath)
    const setCache = async (blob: Uint8Array) => {
        if (browser) {
            await storage.saveBytes('cache', blob)
        } else {
            fs.writeFileSync(cachePath, blob)
        }
    }

    const trackCacheReads = () => {
        if (browser) {
            const getBytes = jest.spyOn(storage, 'getBytes')
            return () => expect(getBytes).not.toHaveBeenCalledWith('cache')
        }
        const open = jest.spyOn(fs, 'openSync')
        return () => expect(open.mock.calls.some(([file]) => file === cachePath)).toBe(false)
    }

    const saveRead = async (scope?: QueryOptions) => {
        reply.mockResolvedValueOnce({body: {...READ_REPLY, encryptedAppKey: null, folders: null}})
        await expect(getSecrets2(options, scope)).resolves.toMatchObject(READ_REPLY)
    }

    const makeFolderReply = async (name: string) => {
        const folderKey = new Uint8Array(32).fill(4)
        const folderKeyBytes = await platform.encryptWithKey(folderKey, APP_KEY)
        const folderData = await platform.encryptWithKey(platform.stringToBytes(JSON.stringify({name})), folderKey, true)
        return {encryptedAppKey: null, folders: [{
            folderUid: FOLDERS[0].folderUid,
            folderKey: platform.bytesToBase64(folderKeyBytes),
            data: platform.bytesToBase64(folderData),
            records: []
        }]}
    }

    const saveFolderRead = async () => {
        reply.mockResolvedValueOnce({body: await makeFolderReply(FOLDERS[0].name)})
        await expect(getFolders(options)).resolves.toEqual(FOLDERS)
    }

    beforeEach(async () => {
        connectPlatform(implementation)
        initialize()
        jest.spyOn(console, 'error').mockImplementation(() => {})
        const publicEncrypt = platform.publicEncrypt
        jest.spyOn(platform, 'publicEncrypt').mockImplementation((data, key) => {
            transmissionKey = data
            return publicEncrypt(data, key)
        })
        offline = browser
            ? new TypeError('Network request failed')
            : Object.assign(new Error('Network request failed'), {code: 'ECONNRESET'})
        reply.mockReset().mockRejectedValue(offline)
        if (browser) {
            jest.spyOn(globalThis, 'fetch').mockImplementation(async (url, request) => {
                const {status, data} = await respond(String(url), request!.body as Uint8Array)
                return new Response(Uint8Array.from(data), {status})
            })
        } else {
            nodeRequest.mockImplementation((url, _options, onResponse) => {
                const request = new EventEmitter()
                let payload: Uint8Array
                return Object.assign(request, {
                    write: (data: Uint8Array) => { payload = data },
                    end: () => {
                        void respond(url, payload).then(({status, data}) => {
                            const response = Object.assign(new EventEmitter(), {headers: {}, statusCode: status})
                            onResponse(response)
                            response.emit('data', Buffer.from(data))
                            response.emit('end')
                        }, error => request.emit('error', error))
                    }
                })
            })
            tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ksm-cache-scope-'))
            cachePath = path.join(tempDir, 'cache.dat')
        }
        storage = inMemoryStorage({})
        await initializeStorage(storage, platform.bytesToBase64(CLIENT_KEY), 'vault.example.com')
        await storage.saveBytes('appKey', APP_KEY)
        options = {storage, queryFunction: browser ? browserCache(storage) : nodeCache(storage, {cachePath})}
    })

    afterEach(() => {
        jest.restoreAllMocks()
        nodeRequest.mockReset()
        if (tempDir) fs.rmSync(tempDir, {recursive: true, force: true})
    })

    test('returns a saved reply for the same read request', async () => {
        await saveRead(SCOPE)
        expect(console.error).not.toHaveBeenCalled()
        await expect(getSecrets2(options, {...SCOPE})).resolves.toMatchObject(READ_REPLY)
        expect(console.error).toHaveBeenCalledWith(expect.stringContaining('serving cached response'))
        expect(reply).toHaveBeenCalledTimes(2)
    })

    test.each<[string, QueryOptions | undefined]>([
        ['record filter', {...SCOPE, recordsFilter: ['record-b']}],
        ['folder filter', {...SCOPE, foldersFilter: ['folder-b']}],
        ['link filter', {...SCOPE, requestLinks: false}],
        ['unfiltered request', undefined]
    ])('requires a live reply for a different %s', async (_label, scope) => {
        await saveRead(SCOPE)
        await expect(getSecrets2(options, scope)).rejects.toBe(offline)
    })

    test.each([
        ['server', 'hostname', 'other.example.com'],
        ['client ID', 'clientId', 'other-client'],
        ['server key ID', 'serverPublicKeyId', '8']
    ])('requires a live reply after the %s changes', async (_label, key, value) => {
        await saveRead()
        await storage.saveString(key, value)
        await expect(getSecrets2(options)).rejects.toBe(offline)
    })

    test('requires a live reply after the app key changes', async () => {
        await saveRead()
        await storage.saveBytes('appKey', new Uint8Array(32).fill(3))
        await expect(getSecrets2(options)).rejects.toBe(offline)
    })

    test('requires a live reply after the signing key changes', async () => {
        await saveRead()
        await platform.generatePrivateKey('privateKey', storage)
        await expect(getSecrets2(options)).rejects.toBe(offline)
    })

    test('matches the signing key used for the read', async () => {
        const originalKey = (await storage.getBytes('privateKey'))!
        const sign = platform.sign
        jest.spyOn(platform, 'sign').mockImplementationOnce(async (...args) => {
            const signature = await sign(...args)
            await platform.generatePrivateKey('privateKey', storage)
            return signature
        })

        await saveRead()
        const rotatedKey = (await storage.getBytes('privateKey'))!
        await storage.saveBytes('privateKey', originalKey)
        await expect(getSecrets2(options)).resolves.toMatchObject(READ_REPLY)
        await storage.saveBytes('privateKey', rotatedKey)
        await expect(getSecrets2(options)).rejects.toBe(offline)
    })

    test('requires a live reply after the server key changes but keeps the same ID', async () => {
        await storage.saveString('serverPublicKeyId', '20')
        await storage.saveString('serverPublicKey', makeServerPublicKey())
        await saveRead()
        await storage.saveString('serverPublicKey', makeServerPublicKey())
        await expect(getSecrets2(options)).rejects.toBe(offline)
    })

    test('requires a live reply after the certificate verification policy changes', async () => {
        await saveRead()
        await expect(getSecrets2({...options, allowUnverifiedCertificate: true})).rejects.toBe(offline)
    })

    test('matches the endpoint for folder reads', async () => {
        await saveRead()
        await expect(getFolders(options)).rejects.toBe(offline)
        await saveFolderRead()
        await expect(getSecrets2(options)).rejects.toBe(offline)
        await expect(getFolders(options)).resolves.toEqual(FOLDERS)
    })

    test('does not use the cache for an HTTP error or a non-transport error', async () => {
        await saveRead()
        reply.mockResolvedValueOnce({status: 503, body: {error: 'Service unavailable'}})
        await expect(getSecrets2(options)).rejects.toThrow('Service unavailable')
        const error = new Error('Local request error')
        reply.mockRejectedValueOnce(error)
        await expect(getSecrets2(options)).rejects.toBe(error)
    })

    test('does not read or replace the cache for a write', async () => {
        await saveRead()
        const before = await readCache()
        const expectNoCacheRead = trackCacheReads()

        const deletionReply = {records: [{recordUid: 'record-a', responseCode: 'ok'}]}
        reply.mockResolvedValueOnce({body: deletionReply})
        await expect(deleteSecret(options, ['record-a'])).resolves.toEqual(deletionReply)
        await expect(deleteSecret(options, ['record-a'])).rejects.toBe(offline)
        expectNoCacheRead()
        expect(await readCache()).toEqual(before)
        await expect(getSecrets2(options)).resolves.toMatchObject(READ_REPLY)
    })

    describe.each([
        ['createSecret', 'get_secret',
            (options: SecretManagerOptions) => createSecret(options, FOLDERS[0].folderUid, {title: 'Record A'})],
        ['createSecret2', 'get_folders',
            (options: SecretManagerOptions) => createSecret2(options, {folderUid: FOLDERS[0].folderUid}, {title: 'Record A'})]
    ] as const)('%s warm-up', (_name, readRoute, create) => {
        test.each(['read failure', 'write success', 'write failure'])('keeps the read cache on %s', async outcome => {
            await storage.saveBytes('appOwnerPublicKey', await platform.exportPublicKey('privateKey', storage))
            const read = readRoute === 'get_secret' ? getSecrets2 : getFolders
            const saved = readRoute === 'get_secret' ? READ_REPLY : FOLDERS
            reply.mockResolvedValueOnce({body: {...READ_REPLY, ...await makeFolderReply(FOLDERS[0].name)}})
            await expect(read(options)).resolves.toMatchObject(saved)
            const before = await readCache()
            expect(before).toBeDefined()

            const routes: string[] = [readRoute]
            if (outcome !== 'read failure') {
                reply.mockResolvedValueOnce({body: await makeFolderReply('Updated Folder A')})
                routes.push('create_secret')
            }
            if (outcome === 'write success') {
                reply.mockResolvedValueOnce({body: {}})
            }

            platform.cleanKeyCache()
            const expectNoCacheRead = trackCacheReads()
            const pending = create(options)
            if (outcome === 'write success') {
                await expect(pending).resolves.toEqual(expect.any(String))
            } else {
                await expect(pending).rejects.toBe(offline)
            }

            expect(reply.mock.calls.slice(1).map(([url]) => new URL(url).pathname))
                .toEqual(routes.map(route => `/api/rest/sm/v1/${route}`))
            expectNoCacheRead()
            expect(await readCache()).toEqual(before)
            await expect(read(options)).resolves.toMatchObject(saved)
        })
    })

    test.each([
        ['secret read', getSecrets2],
        ['folder read', getFolders]
    ] as const)('does not read the cache when a %s starts a bind', async (_label, read) => {
        await saveRead()
        const before = await readCache()
        await storage.delete('appKey')
        const expectNoCacheRead = trackCacheReads()
        await expect(read(options)).rejects.toBe(offline)
        expect(reply.mock.calls[1][1].publicKey).toBeDefined()
        expectNoCacheRead()
        expect(await readCache()).toEqual(before)
    })

    test.each(['successful', 'failed'])('keeps the cache unchanged during a %s bind confirmation', async result => {
        await saveRead()
        const before = await readCache()
        await storage.delete('appKey')
        const expectNoCacheRead = trackCacheReads()

        const encryptedAppKey = await platform.encryptWithKey(APP_KEY, CLIENT_KEY)
        const bindReply = {records: [], warnings: ['Bind reply']}
        reply.mockResolvedValueOnce({body: {
            ...bindReply,
            encryptedAppKey: platform.bytesToBase64(encryptedAppKey),
            appOwnerPublicKey: 'owner-public-key'
        }})
        if (result === 'successful') {
            reply.mockResolvedValueOnce({body: {records: [], warnings: ['Confirmation reply']}})
            await expect(getSecrets2(options)).resolves.toMatchObject(bindReply)
        } else {
            await expect(getSecrets2(options)).rejects.toBe(offline)
        }

        expect(reply).toHaveBeenCalledTimes(3)
        expect(reply.mock.calls[1][1].publicKey).toBeDefined()
        expect(reply.mock.calls[2][1].publicKey).toBeUndefined()
        expectNoCacheRead()
        expect(await readCache()).toEqual(before)
        await expect(getSecrets2(options)).resolves.toMatchObject(READ_REPLY)
    })

    test('keeps the last valid cached reply after an invalid live reply', async () => {
        await saveRead()
        const before = await readCache()
        reply.mockResolvedValueOnce({body: null})
        await expect(getSecrets2(options)).rejects.toBeInstanceOf(TypeError)
        expect(await readCache()).toEqual(before)
        await expect(getSecrets2(options)).resolves.toMatchObject(READ_REPLY)
    })

    test('keeps the last valid cached reply when the app data is invalid', async () => {
        await saveRead()
        const before = await readCache()
        const appData = await platform.encryptWithKey(platform.stringToBytes('Not JSON'), APP_KEY)
        reply.mockResolvedValueOnce({body: {records: [], appData: platform.bytesToBase64(appData)}})
        await expect(getSecrets2(options)).rejects.toBeInstanceOf(SyntaxError)
        expect(await readCache()).toEqual(before)
        await expect(getSecrets2(options)).resolves.toMatchObject(READ_REPLY)
    })

    test('keeps the last valid cached reply when a live reply reports an error', async () => {
        await saveRead()
        const before = await readCache()
        for (const field of ['error', 'result_code']) {
            reply.mockResolvedValueOnce({body: {records: [], [field]: 'request_failed'}})
            await Promise.allSettled([getSecrets2(options)])
            expect(await readCache()).toEqual(before)
        }
        expect(reply).toHaveBeenCalledTimes(3)
        await expect(getSecrets2(options)).resolves.toMatchObject(READ_REPLY)
    })

    test('keeps the last complete cached reply when record decryption fails', async () => {
        const makeRecord = async (recordUid: string) => {
            const key = platform.getRandomBytes(32)
            const data = platform.stringToBytes(JSON.stringify({title: recordUid}))
            return {
                recordUid,
                recordKey: platform.bytesToBase64(await platform.encryptWithKey(key, APP_KEY)),
                data: platform.bytesToBase64(await platform.encryptWithKey(data, key))
            }
        }
        const first = await makeRecord('record-a')
        const second = await makeRecord('record-b')
        const readUids = async () => (await getSecrets2(options)).records.map(record => record.recordUid)

        reply.mockResolvedValueOnce({body: {records: [first, second]}})
        await expect(readUids()).resolves.toEqual(['record-a', 'record-b'])
        const before = await readCache()
        reply.mockResolvedValueOnce({body: {records: [first, {...second, recordKey: undefined}]}})
        await expect(readUids()).resolves.toEqual(['record-a'])
        expect(await readCache()).toEqual(before)
        await expect(readUids()).resolves.toEqual(['record-a', 'record-b'])
    })

    test.each(['default handling', 'a failing callback'])('keeps the last valid folder reply with %s', async handling => {
        await saveFolderRead()
        const before = await readCache()
        reply.mockResolvedValueOnce({body: {folders: [{folderUid: FOLDERS[0].folderUid}]}})

        if (handling === 'default handling') {
            await expect(getFolders(options)).resolves.toEqual([])
        } else {
            const error = new Error('Folder callback failed')
            const onDecryptionError = jest.fn(() => { throw error })
            await expect(getFolders({...options, onDecryptionError})).rejects.toBe(error)
            expect(onDecryptionError).toHaveBeenCalledWith(expect.objectContaining({
                uid: FOLDERS[0].folderUid,
                failure: 'missing-key'
            }))
        }

        expect(await readCache()).toEqual(before)
        await expect(getFolders(options)).resolves.toEqual(FOLDERS)
    })

    test.each(['damaged', 'truncated', 'previous format'])('ignores a %s cache entry', async kind => {
        await saveRead()
        const blob = Uint8Array.from((await readCache())!)
        switch (kind) {
            case 'damaged':
                blob[blob.length - 1] ^= 0xff
                await setCache(blob)
                break
            case 'truncated':
                await setCache(blob.subarray(0, 10))
                break
            default:
                await setCache(new Uint8Array([2, ...blob.subarray(1)]))
                break
        }
        await expect(getSecrets2(options)).rejects.toBe(offline)
    })
})
