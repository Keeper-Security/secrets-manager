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
import {
    downloadFile,
    downloadThumbnail,
    getNotationResults,
    getSecrets,
    KeeperError,
    KeeperFile,
    KeeperRecord,
    uploadFile
} from '../src/browser'

// initializeStorage imports this as an AES key via the browser platform's importKey, which goes
// through crypto.subtle and therefore (unlike the node platform) requires a real 16/24/32 byte
// key once base64 decoded; a short placeholder string is not valid key material under WebCrypto.
const FAKE_CLIENT_KEY = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'
const originalGetRandomBytes = platform.getRandomBytes

afterEach(() => {
    jest.restoreAllMocks()
    platform.getRandomBytes = originalGetRandomBytes
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
            {folderUid: selfCycleUid, folderKey: 'unused-folder-key', data: '', parent: selfCycleUid},
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
            {folderUid: 'folder-a', folderKey: 'unused-folder-key', data: '', parent: 'folder-b'},
            {folderUid: 'folder-b', folderKey: 'unused-folder-key', data: '', parent: 'folder-a'}
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
    // 2 per-folder skip lines plus the KSM-1267 summary line naming both skipped UIDs.
    expect(errorSpy).toHaveBeenCalledTimes(3)
    // folder-a resolves its shared-folder lookup starting at folder-b: the walk visits folder-b
    // then folder-a again, so the cycle closes back at folder-b. The cycle error is a plain
    // Error (not a KeeperCryptoError), so KSM-1267's classifier labels it "unknown".
    expect(errorSpy.mock.calls[0][0]).toBe(
        'Folder folder-a skipped due to error (unknown): Error, Folder data inconsistent - parent cycle detected at folder UID folder-b'
    )
    // folder-b's lookup starts at folder-a and symmetrically closes back at folder-a.
    expect(errorSpy.mock.calls[1][0]).toBe(
        'Folder folder-b skipped due to error (unknown): Error, Folder data inconsistent - parent cycle detected at folder UID folder-a'
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
        ringFolders.push({folderUid: `folder-${i}`, folderKey: 'unused-folder-key', data: '', parent: `folder-${(i + 1) % ringSize}`})
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

describe('public SDK request deadlines with the browser transport', () => {
    const originalFetch = global.fetch
    const fetchMock = jest.fn()
    const transmissionKey = new Uint8Array(32).fill(1)
    const appKey = new Uint8Array(32).fill(2)
    const recordKey = new Uint8Array(32).fill(3)
    const fileKey = new Uint8Array(32).fill(4)
    const recordUid = 'AAAAAAAAAAAAAAAAAAAAAA'
    const file: KeeperFile = {
        fileUid: 'browser-timeout-file',
        data: {name: 'attachment.txt'},
        url: 'https://files.example.com/attachment',
        thumbnailUrl: 'https://files.example.com/thumbnail'
    }
    const contents = new TextEncoder().encode('complete attachment response')

    beforeEach(() => {
        platform.cleanKeyCache()
        jest.spyOn(platform, 'getRandomBytes').mockImplementation(length => new Uint8Array(length).fill(1))
        fetchMock.mockReset()
        fetchMock.mockImplementation(() => { throw new Error('Unexpected fetch') })
        global.fetch = fetchMock as unknown as typeof fetch
    })

    afterEach(() => {
        global.fetch = originalFetch
        jest.useRealTimers()
        platform.cleanKeyCache()
    })

    const makeOptions = async (requestTimeoutMs?: number, host = 'fake.keepersecurity.com'): Promise<SecretManagerOptions> => {
        const storage = inMemoryStorage({})
        await initializeStorage(storage, FAKE_CLIENT_KEY, host)
        await storage.saveBytes('appKey', appKey)
        return {storage, requestTimeoutMs}
    }

    const encryptResponse = (response: unknown) => platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(response)), transmissionKey)

    const recordResponse = async () => encryptResponse({
        records: [{
            recordUid,
            recordKey: platform.bytesToBase64(await platform.encryptWithKey(recordKey, appKey)),
            data: platform.bytesToBase64(await platform.encryptWithKey(
                platform.stringToBytes(JSON.stringify({
                    title: 'Browser Deadline Record',
                    type: 'login',
                    fields: [{type: 'password', value: ['complete-secret']}]
                })), recordKey)),
            revision: 1,
            files: [{
                fileUid: file.fileUid,
                fileKey: platform.bytesToBase64(await platform.encryptWithKey(fileKey, recordKey)),
                data: platform.bytesToBase64(await platform.encryptWithKey(
                    platform.stringToBytes(JSON.stringify(file.data)), fileKey)),
                url: file.url,
                thumbnailUrl: file.thumbnailUrl
            }]
        }],
        folders: [],
        expiresOn: 0
    })

    const controlledFetch = (data: Uint8Array, status = 200) => {
        let signal: AbortSignal
        let resolveHeaders: (response: unknown) => void
        let resolveBody: (body: ArrayBuffer) => void
        let rejectCurrent: (error: unknown) => void
        let resolveStarted: (signal: AbortSignal) => void
        const started = new Promise<AbortSignal>(resolve => { resolveStarted = resolve })
        const abort = () => rejectCurrent(new DOMException('This operation was aborted', 'AbortError'))
        const cleanup = () => signal.removeEventListener('abort', abort)
        const arrayBuffer = jest.fn(() => new Promise<ArrayBuffer>((resolve, reject) => {
            resolveBody = resolve
            rejectCurrent = reject
            if (signal.aborted) abort()
        }).finally(cleanup))
        fetchMock.mockImplementationOnce((_url: string, init: RequestInit) => {
            signal = init.signal as AbortSignal
            signal.addEventListener('abort', abort, {once: true})
            const headers = new Promise((resolve, reject) => {
                resolveHeaders = resolve
                rejectCurrent = reject
            }).catch(error => {
                cleanup()
                throw error
            })
            resolveStarted(signal)
            return headers
        })
        return {
            started,
            get signal() { return signal },
            arrayBuffer,
            headers: () => resolveHeaders({
                status, statusText: status === 201 ? 'Created' : 'OK',
                headers: new Headers(), arrayBuffer
            }),
            body: () => resolveBody(data.slice().buffer as ArrayBuffer)
        }
    }

    const observe = (operation: Promise<unknown>) => {
        const fulfilled = jest.fn()
        const rejected = jest.fn()
        return {fulfilled, rejected, completion: operation.then(fulfilled, rejected)}
    }

    test.each(['getSecrets', 'getFolders'])('%s accepts delayed API headers and the complete delayed encrypted body by default', async name => {
        const options = await makeOptions()
        const responseData = name === 'getSecrets'
            ? await recordResponse()
            : await encryptResponse({
                records: [],
                folders: [{
                    folderUid: 'browser-timeout-folder',
                    folderKey: platform.bytesToBase64(await platform.encryptWithKey(recordKey, appKey)),
                    data: platform.bytesToBase64(await platform.encryptWithKey(
                        platform.stringToBytes('{"name":"Browser Deadline Folder"}'), recordKey, true))
                }],
                expiresOn: 0
            })
        const response = controlledFetch(responseData)
        jest.useFakeTimers()
        const operation = observe(name === 'getSecrets' ? getSecrets(options) : getFolders(options))
        await response.started

        await jest.advanceTimersByTimeAsync(31000)
        response.headers()
        await jest.advanceTimersByTimeAsync(31000)
        expect(response.arrayBuffer).toHaveBeenCalledTimes(1)
        expect(response.signal.aborted).toBe(false)
        expect(operation.fulfilled).not.toHaveBeenCalled()
        expect(operation.rejected).not.toHaveBeenCalled()
        response.body()
        await operation.completion

        const result = operation.fulfilled.mock.calls[0]?.[0]
        if (name === 'getSecrets') {
            expect(result.records[0].data.fields[0].value).toEqual(['complete-secret'])
            expect(result.records[0].files[0]).toEqual(file)
        } else {
            expect(result).toEqual([{folderUid: 'browser-timeout-folder', name: 'Browser Deadline Folder'}])
        }
        expect(operation.rejected).not.toHaveBeenCalled()
        expect(fetchMock).toHaveBeenCalledTimes(1)
        expect(fetchMock.mock.calls[0][0]).toContain(name === 'getSecrets' ? '/get_secret' : '/get_folders')
        expect(jest.getTimerCount()).toBe(0)
    })

    test.each([
        ['downloadFile', downloadFile, file.url],
        ['downloadThumbnail', downloadThumbnail, file.thumbnailUrl]
    ] as const)('%s waits for the complete attachment after the former default has elapsed', async (_name, download, url) => {
        await platform.importKey(file.fileUid, fileKey)
        const response = controlledFetch(await platform.encryptWithKey(contents, fileKey))
        jest.useFakeTimers()
        const operation = observe(download(file))
        await response.started

        await jest.advanceTimersByTimeAsync(31000)
        response.headers()
        await jest.advanceTimersByTimeAsync(31000)
        expect(response.signal.aborted).toBe(false)
        expect(operation.fulfilled).not.toHaveBeenCalled()
        expect(operation.rejected).not.toHaveBeenCalled()
        response.body()
        await operation.completion
        expect(operation.fulfilled).toHaveBeenCalledWith(contents)
        expect(operation.rejected).not.toHaveBeenCalled()
        expect(fetchMock).toHaveBeenCalledWith(url, expect.objectContaining({method: 'GET'}))
        expect(jest.getTimerCount()).toBe(0)
    })

    const makeUpload = async (requestTimeoutMs?: number) => {
        const options = await makeOptions(requestTimeoutMs)
        await options.storage.saveBytes('appOwnerPublicKey', await platform.exportPublicKey('privateKey', options.storage))
        await platform.importKey(recordUid, recordKey)
        const ownerRecord: KeeperRecord = {recordUid, data: {fields: []}, revision: 1}
        const fileToUpload = {name: 'attachment.txt', title: 'Attachment', data: contents}
        const responseData = await encryptResponse({
            url: 'https://files.example.com/upload',
            parameters: '{}',
            successStatusCode: 201
        })
        return {options, ownerRecord, fileToUpload, responseData}
    }

    test('uploadFile applies the default to both add_file and the complete multipart upload response', async () => {
        const {options, ownerRecord, fileToUpload, responseData} = await makeUpload()
        const api = controlledFetch(responseData)
        const upload = controlledFetch(new Uint8Array([1, 2, 3]), 201)
        jest.useFakeTimers()
        const operation = observe(uploadFile(options, ownerRecord, fileToUpload))
        await api.started

        await jest.advanceTimersByTimeAsync(31000)
        api.headers()
        await jest.advanceTimersByTimeAsync(31000)
        expect(operation.fulfilled).not.toHaveBeenCalled()
        expect(api.arrayBuffer).toHaveBeenCalledTimes(1)
        api.body()
        await upload.started
        expect(api.signal.aborted).toBe(false)
        await jest.advanceTimersByTimeAsync(31000)
        upload.headers()
        await jest.advanceTimersByTimeAsync(31000)
        expect(upload.arrayBuffer).toHaveBeenCalledTimes(1)
        expect(upload.signal.aborted).toBe(false)
        expect(operation.fulfilled).not.toHaveBeenCalled()
        expect(operation.rejected).not.toHaveBeenCalled()
        upload.body()
        await operation.completion

        expect(operation.fulfilled).toHaveBeenCalledWith(ownerRecord.data.fields[0].value[0])
        expect(operation.rejected).not.toHaveBeenCalled()
        expect(fetchMock.mock.calls[0][0]).toContain('/add_file')
        expect(fetchMock.mock.calls[1][0]).toBe('https://files.example.com/upload')
        expect(fetchMock.mock.calls[1][1].body).toBeInstanceOf(FormData)
        expect(fetchMock).toHaveBeenCalledTimes(2)
        expect(jest.getTimerCount()).toBe(0)
    })

    test('file notation gives each API and download exchange its own five-minute default', async () => {
        const options = await makeOptions()
        const api = controlledFetch(await recordResponse())
        const attachment = controlledFetch(await platform.encryptWithKey(contents, fileKey))
        jest.useFakeTimers()
        const operation = observe(getNotationResults(options, `${recordUid}/file/attachment.txt`))
        await api.started

        await jest.advanceTimersByTimeAsync(50000)
        api.headers()
        await jest.advanceTimersByTimeAsync(160000)
        expect(api.signal.aborted).toBe(false)
        api.body()
        await attachment.started
        await jest.advanceTimersByTimeAsync(50000)
        attachment.headers()
        await jest.advanceTimersByTimeAsync(160000)
        expect(attachment.signal.aborted).toBe(false)
        expect(operation.fulfilled).not.toHaveBeenCalled()
        expect(operation.rejected).not.toHaveBeenCalled()
        attachment.body()
        await operation.completion

        expect(operation.fulfilled).toHaveBeenCalledWith([platform.bytesToBase64(contents).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')])
        expect(operation.rejected).not.toHaveBeenCalled()
        expect(fetchMock).toHaveBeenCalledTimes(2)
        expect(jest.getTimerCount()).toBe(0)
    })

    test('getSecrets rejects an incomplete response at five minutes without partial records or a retry', async () => {
        const options = await makeOptions()
        const response = controlledFetch(await recordResponse())
        jest.useFakeTimers()
        const operation = observe(getSecrets(options))
        await response.started
        await jest.advanceTimersByTimeAsync(10000)
        response.headers()
        await jest.advanceTimersByTimeAsync(289999)
        expect(response.signal.aborted).toBe(false)
        expect(operation.fulfilled).not.toHaveBeenCalled()
        expect(operation.rejected).not.toHaveBeenCalled()
        await jest.advanceTimersByTimeAsync(1)
        await operation.completion
        expect(operation.rejected).toHaveBeenCalledWith(expect.any(KeeperError))
        expect(operation.rejected.mock.calls[0][0].message).toContain('timed out after 300000ms')
        response.body()
        await jest.advanceTimersByTimeAsync(300000)
        expect(operation.fulfilled).not.toHaveBeenCalled()
        expect(operation.rejected).toHaveBeenCalledTimes(1)
        expect(fetchMock).toHaveBeenCalledTimes(1)
        expect(jest.getTimerCount()).toBe(0)
    })

    test('one client override cannot shorten a different client\'s omitted timeout', async () => {
        const shortOptions = await makeOptions(1000, 'short.example.com')
        const defaultOptions = await makeOptions(undefined, 'default.example.com')
        const responseData = await recordResponse()
        const shortResponse = controlledFetch(responseData)
        const defaultResponse = controlledFetch(responseData)
        jest.useFakeTimers()
        const shortOperation = observe(getSecrets(shortOptions))
        await shortResponse.started
        const defaultOperation = observe(getSecrets(defaultOptions))
        await defaultResponse.started
        expect(shortResponse.signal).not.toBe(defaultResponse.signal)

        await jest.advanceTimersByTimeAsync(1000)
        await shortOperation.completion
        expect(shortOperation.rejected).toHaveBeenCalledWith(expect.any(KeeperError))
        expect(shortOperation.rejected.mock.calls[0][0].message).toContain('timed out after 1000ms')
        expect(defaultResponse.signal.aborted).toBe(false)
        await jest.advanceTimersByTimeAsync(30000)
        defaultResponse.headers()
        await jest.advanceTimersByTimeAsync(0)
        expect(defaultResponse.arrayBuffer).toHaveBeenCalledTimes(1)
        defaultResponse.body()
        await defaultOperation.completion
        expect(defaultOperation.fulfilled.mock.calls[0]?.[0].records).toHaveLength(1)
        expect(defaultOperation.rejected).not.toHaveBeenCalled()
        expect(shortOptions.requestTimeoutMs).toBe(1000)
        expect(defaultOptions.requestTimeoutMs).toBeUndefined()
        expect(fetchMock.mock.calls.map(call => new URL(call[0]).hostname)).toEqual(['short.example.com', 'default.example.com'])
        expect(jest.getTimerCount()).toBe(0)
    })

    test.each([
        [1000, 360000, 300001, true],
        [360000, 1000, 1000, false]
    ])('downloadFile overrides configured %ims with explicit %ims', async (configured, explicit, elapsed, succeeds) => {
        await platform.importKey(file.fileUid, fileKey)
        const response = controlledFetch(await platform.encryptWithKey(contents, fileKey))
        const getSpy = jest.spyOn(platform, 'get')
        jest.useFakeTimers()
        const operation = observe(downloadFile(file, explicit, {storage: inMemoryStorage({}), requestTimeoutMs: configured}))
        await response.started
        response.headers()
        await jest.advanceTimersByTimeAsync(elapsed)
        expect(getSpy).toHaveBeenCalledWith(file.url, {}, explicit)
        if (succeeds) {
            expect(response.signal.aborted).toBe(false)
            expect(operation.fulfilled).not.toHaveBeenCalled()
            response.body()
            await operation.completion
            expect(operation.fulfilled).toHaveBeenCalledWith(contents)
            expect(operation.rejected).not.toHaveBeenCalled()
        } else {
            await operation.completion
            expect(operation.fulfilled).not.toHaveBeenCalled()
            expect(operation.rejected).toHaveBeenCalledWith(expect.any(KeeperError))
            expect(operation.rejected.mock.calls[0][0].message).toContain(`timed out after ${explicit}ms`)
        }
        expect(jest.getTimerCount()).toBe(0)
    })

    test('an explicit longer upload timeout leaves the configured add_file timeout unchanged', async () => {
        const {options, ownerRecord, fileToUpload, responseData} = await makeUpload(5000)
        const api = controlledFetch(responseData)
        const upload = controlledFetch(new Uint8Array(), 201)
        const postSpy = jest.spyOn(platform, 'post')
        const uploadSpy = jest.spyOn(platform, 'fileUpload')
        jest.useFakeTimers()
        const operation = observe(uploadFile(options, ownerRecord, fileToUpload, 360000))
        await api.started
        api.headers()
        await jest.advanceTimersByTimeAsync(0)
        api.body()
        await upload.started
        upload.headers()
        await jest.advanceTimersByTimeAsync(300001)
        expect(upload.signal.aborted).toBe(false)
        expect(operation.fulfilled).not.toHaveBeenCalled()
        expect(operation.rejected).not.toHaveBeenCalled()
        upload.body()
        await operation.completion
        expect(operation.fulfilled).toHaveBeenCalledWith(expect.any(String))
        expect(operation.rejected).not.toHaveBeenCalled()
        expect(postSpy.mock.calls[0][4]).toBe(5000)
        expect(uploadSpy.mock.calls[0][3]).toBe(360000)
        expect(options.requestTimeoutMs).toBe(5000)
        expect(jest.getTimerCount()).toBe(0)
    })
})
