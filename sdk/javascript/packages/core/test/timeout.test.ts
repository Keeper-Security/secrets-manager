import {
    downloadFile,
    downloadThumbnail,
    getNotationResults,
    getSecrets,
    initializeStorage,
    inMemoryStorage,
    KeeperError,
    KeeperFile,
    KeeperRecord,
    KeeperHttpResponse,
    platform,
    postFunction,
    SecretManagerOptions,
    uploadFile,
} from '../'
import {MAX_REQUEST_TIMEOUT_MS} from '../src/deadline'
import {TransmissionKey, EncryptedPayload} from '../src/platform'
import * as https from 'https'
import {EventEmitter} from 'events'

jest.mock('https', () => ({
    request: jest.fn()
}))

const FAKE_TOKEN = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'
const enc = new TextEncoder()

// Same pattern as throttle.test.ts: a real initializeStorage() call so postQuery has a valid
// client id/hostname, with the actual network path replaced by a mocked queryFunction.
const makeOptions = async (
    queryFunction: SecretManagerOptions['queryFunction'],
    requestTimeoutMs?: number
): Promise<SecretManagerOptions> => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_TOKEN, 'fake.keepersecurity.com')
    return {storage, queryFunction, requestTimeoutMs}
}

describe('requestTimeoutMs validation and propagation through postQuery', () => {
    // Every unusable value (0, negatives, NaN, Infinity, -Infinity) is already unit-tested at the
    // resolveTimeoutMs level in deadline.test.ts; one representative value here is enough to prove
    // the wiring at this integration layer without re-asserting the same thing five times.
    test('rejects an unusable requestTimeoutMs before any request is attempted, with no side effects', async () => {
        const storage = inMemoryStorage({})
        await initializeStorage(storage, FAKE_TOKEN, 'fake.keepersecurity.com')
        const queryFunction = jest.fn()
        const options: SecretManagerOptions = {
            storage,
            requestTimeoutMs: 0,
            serverPublicKey: 'fake-server-public-key',
            serverPublicKeyId: '20',
            queryFunction
        }
        let error: any
        try {
            await getSecrets(options)
        } catch (e) {
            error = e
        }
        expect(error).toBeInstanceOf(Error)
        expect(error).not.toBeInstanceOf(KeeperError)
        expect(error.message).toContain('Request timeout must be')
        expect(queryFunction).not.toHaveBeenCalled()
        // fetchAndDecryptSecrets/postQuery write serverPublicKey/serverPublicKeyId to storage
        // right after validating requestTimeoutMs - the early-validation ordering has to guard
        // both, not just the network call above.
        expect(await storage.getString('serverPublicKey')).toBeUndefined()
        expect(await storage.getString('serverPublicKeyId')).toBeUndefined()
    })

    test('forwards a clamped requestTimeoutMs to queryFunction, not the raw oversized value', async () => {
        const received: (number | undefined)[] = []
        const queryFunction: SecretManagerOptions['queryFunction'] = async (url, transmissionKey, payload, allowUnverifiedCertificate, timeoutMs) => {
            received.push(timeoutMs)
            return {statusCode: 500, data: enc.encode('{}'), headers: []}
        }
        const options = await makeOptions(queryFunction, MAX_REQUEST_TIMEOUT_MS + 1000)
        await getSecrets(options).catch(() => {})
        expect(received[0]).toBe(MAX_REQUEST_TIMEOUT_MS)
    })

    test('a valid requestTimeoutMs reaches queryFunction', async () => {
        const received: (number | undefined)[] = []
        const queryFunction: SecretManagerOptions['queryFunction'] = async (url, transmissionKey, payload, allowUnverifiedCertificate, timeoutMs) => {
            received.push(timeoutMs)
            return {statusCode: 500, data: enc.encode('{}'), headers: []}
        }
        const options = await makeOptions(queryFunction, 12345)
        await getSecrets(options).catch(() => {})
        expect(received[0]).toBe(12345)
    })

    test('omitting requestTimeoutMs passes undefined through, not a resolved default', async () => {
        const received: (number | undefined)[] = []
        const queryFunction: SecretManagerOptions['queryFunction'] = async (url, transmissionKey, payload, allowUnverifiedCertificate, timeoutMs) => {
            received.push(timeoutMs)
            return {statusCode: 500, data: enc.encode('{}'), headers: []}
        }
        const options = await makeOptions(queryFunction)
        await getSecrets(options).catch(() => {})
        expect(received[0]).toBeUndefined()
    })

    test('a rejection from queryFunction is never retried', async () => {
        const queryFunction = jest.fn(async () => {
            throw new KeeperError('Request to https://example.com timed out after 300000ms')
        })
        const options = await makeOptions(queryFunction)
        await expect(getSecrets(options)).rejects.toBeInstanceOf(KeeperError)
        expect(queryFunction).toHaveBeenCalledTimes(1)
    })
})

// postFunction is the default queryFunction: the one hop that carries the timeout for every
// consumer who supplies no custom queryFunction, which is the overwhelming majority. The request
// itself would still be bounded without this forwarding (resolveTimeoutMs falls back to
// DEFAULT_REQUEST_TIMEOUT_MS), but options.requestTimeoutMs would become a silent no-op on the
// default path in both directions - a caller raising it for a large payload, or lowering it for a
// fast-fail policy, would still get the default deadline either way.
describe('postFunction forwards its timeoutMs argument to platform.post', () => {
    const originalPost = platform.post
    afterEach(() => {
        platform.post = originalPost
    })

    test.each([7777, 600000])('forwards timeoutMs %i as platform.post\'s fifth argument', async timeoutMs => {
        const seen: any[] = []
        platform.post = (async (...args: any[]) => {
            seen.push(...args)
            return {statusCode: 500, headers: [], data: new Uint8Array()}
        }) as typeof platform.post

        const transmissionKey: TransmissionKey = {
            publicKeyId: 7,
            key: new Uint8Array(32),
            encryptedKey: new Uint8Array([9, 9, 9])
        }
        const payload: EncryptedPayload = {
            payload: new Uint8Array([1, 2, 3]),
            signature: new Uint8Array([4, 5, 6])
        }
        await postFunction('https://example.com', transmissionKey, payload, false, timeoutMs).catch(() => {})
        expect(seen[4]).toBe(timeoutMs)
    })
})

describe('downloadFile / downloadThumbnail requestTimeoutMs precedence', () => {
    const originalGet = platform.get
    const originalDecrypt = platform.decrypt

    afterEach(() => {
        platform.get = originalGet
        platform.decrypt = originalDecrypt
    })

    const fakeFile = (): KeeperFile => ({
        fileUid: 'fileUid123',
        data: {},
        url: 'https://example.com/file',
        thumbnailUrl: 'https://example.com/thumb',
    })

    beforeEach(() => {
        platform.get = jest.fn(async (): Promise<KeeperHttpResponse> => ({statusCode: 200, data: new Uint8Array(), headers: []}))
        platform.decrypt = jest.fn(async () => new Uint8Array())
    })

    // downloadFile and downloadThumbnail are two hand-copied expressions of the identical
    // precedence rule, five lines apart in keeper.ts, with no shared helper - so they can drift
    // independently. describe.each runs every case against both, against their own URL field, so
    // a regression in either one is caught without duplicating the test bodies.
    describe.each([
        ['downloadFile', downloadFile, (file: KeeperFile) => file.url],
        ['downloadThumbnail', downloadThumbnail, (file: KeeperFile) => file.thumbnailUrl],
    ])('%s', (_name, download, urlOf) => {
        test('an explicit timeoutMs argument wins over options.requestTimeoutMs', async () => {
            const file = fakeFile()
            await download(file, 111, {storage: inMemoryStorage({}), requestTimeoutMs: 999})
            expect(platform.get).toHaveBeenCalledWith(urlOf(file), {}, 111)
        })

        test('falls back to options.requestTimeoutMs when timeoutMs is omitted', async () => {
            const file = fakeFile()
            await download(file, undefined, {storage: inMemoryStorage({}), requestTimeoutMs: 222})
            expect(platform.get).toHaveBeenCalledWith(urlOf(file), {}, 222)
        })

        test('passes undefined through (platform default applies) when neither is set', async () => {
            const file = fakeFile()
            await download(file)
            expect(platform.get).toHaveBeenCalledWith(urlOf(file), {}, undefined)
        })

        test('a value above MAX_REQUEST_TIMEOUT_MS reaches platform.get already clamped', async () => {
            const file = fakeFile()
            await download(file, MAX_REQUEST_TIMEOUT_MS + 1000)
            expect(platform.get).toHaveBeenCalledWith(urlOf(file), {}, MAX_REQUEST_TIMEOUT_MS)
        })

        test('rejects an invalid resolved timeoutMs before calling platform.get', async () => {
            const file = fakeFile()
            await expect(download(file, -1)).rejects.toThrow(/Request timeout must be/)
            expect(platform.get).not.toHaveBeenCalled()
        })
    })
})

describe('uploadFile requestTimeoutMs propagation', () => {
    const originalEncrypt = platform.encrypt
    const originalPublicEncrypt = platform.publicEncrypt
    const originalFileUpload = platform.fileUpload

    afterEach(() => {
        platform.encrypt = originalEncrypt
        platform.publicEncrypt = originalPublicEncrypt
        platform.fileUpload = originalFileUpload
    })

    // appOwnerPublicKey/clientId literals duplicated from keeper.ts's private KEY_OWNER_PUBLIC_KEY/
    // KEY_CLIENT_ID - not exported there, so the strings are repeated here (same approach already
    // used in localConfigStorage.test.ts for KEY_APP_KEY).
    const setup = async (requestTimeoutMs?: number) => {
        const storage = inMemoryStorage({})
        await initializeStorage(storage, FAKE_TOKEN, 'fake.keepersecurity.com')
        await storage.saveBytes('appOwnerPublicKey', new Uint8Array(65))

        // encrypt/publicEncrypt need pre-existing key material (a per-record data key, a real EC
        // point) this synthetic test has no reason to fake; stubbed so prepareFileUploadPayload
        // completes without it. encryptWithKey/decryptWithKey stay real since they're
        // self-contained given just a key, which is all that's under test here.
        platform.encrypt = async () => new Uint8Array([1])
        platform.publicEncrypt = async () => new Uint8Array([2])

        const ownerRecord: KeeperRecord = {recordUid: 'ownerUid', data: {fields: []}, revision: 1}
        const file = {name: 'f.txt', title: 'f', data: new Uint8Array([9])}

        const queryFunction: SecretManagerOptions['queryFunction'] = async (url, transmissionKey) => {
            const body = JSON.stringify({url: 'https://bucket.example.com/', parameters: '{}', successStatusCode: 201})
            const encrypted = await platform.encryptWithKey(enc.encode(body), transmissionKey.key)
            return {statusCode: 200, data: encrypted, headers: []}
        }
        const options: SecretManagerOptions = {storage, queryFunction, requestTimeoutMs}
        return {options, ownerRecord, file}
    }

    test.each([4567, 600000])('threads options.requestTimeoutMs %i through to platform.fileUpload', async requestTimeoutMs => {
        const fileUploadMock = jest.fn(async (_url?: string, _params?: any, _data?: any, _timeoutMs?: number) => ({statusCode: 201, statusMessage: 'Created'}))
        platform.fileUpload = fileUploadMock
        const {options, ownerRecord, file} = await setup(requestTimeoutMs)
        await uploadFile(options, ownerRecord, file)
        expect(fileUploadMock.mock.calls[0][3]).toBe(requestTimeoutMs)
    })

    test('an explicit timeoutMs argument wins over options.requestTimeoutMs', async () => {
        const fileUploadMock = jest.fn(async (_url?: string, _params?: any, _data?: any, _timeoutMs?: number) => ({statusCode: 201, statusMessage: 'Created'}))
        platform.fileUpload = fileUploadMock
        const {options, ownerRecord, file} = await setup(9000)
        await uploadFile(options, ownerRecord, file, 111)
        expect(fileUploadMock.mock.calls[0][3]).toBe(111)
    })

    test('rejects an invalid explicit timeoutMs before calling platform.fileUpload or add_file', async () => {
        const fileUploadMock = jest.fn()
        platform.fileUpload = fileUploadMock
        // options.requestTimeoutMs is valid here (9000) so postQuery's own, separate validation
        // of that value can't be what blocks add_file below - only an invalid *explicit*
        // timeoutMs argument to uploadFile itself is under test.
        const {options, ownerRecord, file} = await setup(9000)
        // add_file (reached via postQuery, through this queryFunction) allocates an upload
        // placeholder URL on the backend - checking only that platform.fileUpload was never
        // called doesn't actually prove the timeout is validated before that side effect, since
        // fileUpload is the very last call in uploadFile regardless of ordering.
        const queryFunctionSpy = jest.fn(options.queryFunction)
        options.queryFunction = queryFunctionSpy
        await expect(uploadFile(options, ownerRecord, file, 0)).rejects.toThrow(/Request timeout must be/)
        expect(fileUploadMock).not.toHaveBeenCalled()
        expect(queryFunctionSpy).not.toHaveBeenCalled()
    })
})

describe('public SDK calls with Node request deadlines', () => {
    class MockRequest extends EventEmitter {
        write = jest.fn()
        end = jest.fn()
        destroy = jest.fn()
    }

    class MockResponse extends EventEmitter {
        statusCode = 200
        statusMessage = 'OK'
        headers = {'content-type': 'application/octet-stream'}
        resume = jest.fn()
        push(data: Uint8Array) { this.emit('data', Buffer.from(data)) }
        finish() { this.emit('end') }
    }

    type Exchange = {
        url: string
        method: string
        signal: AbortSignal
        request: MockRequest
        callback?: (response: MockResponse) => void
    }
    type QueryFunction = NonNullable<SecretManagerOptions['queryFunction']>

    let exchanges: Exchange[]
    const fileUrl = 'https://files.example.com/attachment'
    const thumbnailUrl = 'https://files.example.com/thumbnail'
    const plaintext = enc.encode('complete attachment data')
    const fileKey = new Uint8Array(32).fill(3)

    const observe = <T>(promise: Promise<T>) => {
        const settled = jest.fn()
        void promise.then(settled, settled)
        return {promise, settled}
    }

    const respond = (index = 0, statusCode = 200): MockResponse => {
        const exchange = exchanges[index]
        const response = new MockResponse()
        response.statusCode = statusCode
        if (exchange.callback) {
            exchange.callback(response)
        } else {
            exchange.request.emit('response', response)
        }
        return response
    }

    beforeEach(() => {
        exchanges = []
        ;(https.request as unknown as jest.Mock).mockReset().mockImplementation((url, options, callback) => {
            const request = new MockRequest()
            exchanges.push({url, method: options.method, signal: options.signal, request, callback})
            options.signal?.addEventListener('abort', () => {
                request.destroy()
                request.emit('error', Object.assign(new Error('The operation was aborted'), {name: 'AbortError', code: 'ABORT_ERR'}))
            })
            return request
        })
    })

    afterEach(() => {
        jest.restoreAllMocks()
        jest.useRealTimers()
    })

    test.each([
        ['downloadFile', downloadFile, fileUrl],
        ['downloadThumbnail', downloadThumbnail, thumbnailUrl]
    ])('%s completes a chunked download after 60 seconds without an override', async (_name, download, url) => {
        const file: KeeperFile = {fileUid: 'default-download', data: {}, url: fileUrl, thumbnailUrl}
        await platform.importKey(file.fileUid, fileKey)
        const encrypted = await platform.encryptWithKey(plaintext, fileKey)
        jest.useFakeTimers()
        const {promise, settled} = observe(download(file))
        expect(exchanges[0].url).toBe(url)
        const response = respond()
        await jest.advanceTimersByTimeAsync(45000)
        expect(settled).not.toHaveBeenCalled()
        response.push(encrypted.subarray(0, 16))
        await jest.advanceTimersByTimeAsync(15000)
        expect(settled).not.toHaveBeenCalled()
        expect(exchanges[0].signal.aborted).toBe(false)
        response.push(encrypted.subarray(16))
        response.finish()
        await expect(promise).resolves.toEqual(plaintext)
        expect(jest.getTimerCount()).toBe(0)
        expect(exchanges[0].request.destroy).not.toHaveBeenCalled()
    })

    test('downloadFile never decrypts or returns a partial body after the default expires', async () => {
        const decryptSpy = jest.spyOn(platform, 'decrypt')
        jest.useFakeTimers()
        const file: KeeperFile = {fileUid: 'expired-download', data: {}, url: fileUrl}
        const {promise} = observe(downloadFile(file))
        const response = respond()
        response.push(enc.encode('partial'))
        await jest.advanceTimersByTimeAsync(300000)
        await expect(promise).rejects.toBeInstanceOf(KeeperError)
        await expect(promise).rejects.toThrow(/timed out after 300000ms/)
        expect(decryptSpy).not.toHaveBeenCalled()
        response.finish()
        await expect(promise).rejects.toBeInstanceOf(KeeperError)
        expect(decryptSpy).not.toHaveBeenCalled()
        expect(jest.getTimerCount()).toBe(0)
    })

    test('getSecrets uses the default Node POST deadline through the complete encrypted body', async () => {
        const options = await makeOptions(undefined)
        const transmissionKey = new Uint8Array(32).fill(7)
        const originalRandomBytes = platform.getRandomBytes
        jest.spyOn(platform, 'getRandomBytes').mockImplementation(length =>
            length === 32 ? transmissionKey : originalRandomBytes(length))
        const encrypted = await platform.encryptWithKey(enc.encode(JSON.stringify({records: []})), transmissionKey)
        jest.useFakeTimers()
        const {promise, settled} = observe(getSecrets(options))
        await jest.advanceTimersByTimeAsync(0)
        expect(exchanges).toHaveLength(1)
        expect(exchanges[0].method).toBe('post')
        expect(exchanges[0].url).toBe('https://fake.keepersecurity.com/api/rest/sm/v1/get_secret')
        const response = respond()
        response.push(encrypted.subarray(0, 16))
        await jest.advanceTimersByTimeAsync(45000)
        expect(settled).not.toHaveBeenCalled()
        expect(exchanges[0].signal.aborted).toBe(false)
        response.push(encrypted.subarray(16))
        response.finish()
        await expect(promise).resolves.toMatchObject({records: []})
        expect(exchanges).toHaveLength(1)
        expect(jest.getTimerCount()).toBe(0)
    })

    const notationFixture = async (requestTimeoutMs?: number) => {
        const recordUid = 'AAAAAAAAAAAAAAAAAAAAAA'
        const fileUid = 'BBBBBBBBBBBBBBBBBBBBBB'
        const appKey = new Uint8Array(32).fill(1)
        const recordKey = new Uint8Array(32).fill(2)
        const encryptedBase64 = async (data: Uint8Array, key: Uint8Array) =>
            platform.bytesToBase64(await platform.encryptWithKey(data, key))
        const record = {
            recordUid,
            recordKey: await encryptedBase64(recordKey, appKey),
            revision: 1,
            data: await encryptedBase64(enc.encode(JSON.stringify({title: 'Record', fields: []})), recordKey),
            files: [{
                fileUid,
                fileKey: await encryptedBase64(fileKey, recordKey),
                data: await encryptedBase64(enc.encode(JSON.stringify({name: 'notes.txt'})), fileKey),
                url: fileUrl
            }]
        }
        const queryFunction = jest.fn<ReturnType<QueryFunction>, Parameters<QueryFunction>>(async (_url, transmissionKey) => ({
            statusCode: 200,
            headers: [],
            data: await platform.encryptWithKey(enc.encode(JSON.stringify({records: [record]})), transmissionKey.key)
        }))
        const options = await makeOptions(queryFunction, requestTimeoutMs)
        await platform.importKey('appKey', appKey, options.storage)
        return {
            options,
            queryFunction,
            notation: `keeper://${recordUid}/file/notes.txt`,
            encrypted: await platform.encryptWithKey(plaintext, fileKey)
        }
    }

    test.each([
        ['default', undefined, 60000],
        ['long override', 600000, 300001]
    ])('file notation honors the %s deadline through the Node download', async (_name, requestTimeoutMs, duration) => {
        const {options, queryFunction, notation, encrypted} = await notationFixture(requestTimeoutMs)
        jest.useFakeTimers()
        const {promise, settled} = observe(getNotationResults(options, notation))
        await jest.advanceTimersByTimeAsync(0)
        expect(exchanges).toHaveLength(1)
        expect(exchanges[0].url).toBe(fileUrl)
        const response = respond()
        response.push(encrypted.subarray(0, 16))
        await jest.advanceTimersByTimeAsync(duration)
        expect(settled).not.toHaveBeenCalled()
        response.push(encrypted.subarray(16))
        response.finish()
        await expect(promise).resolves.toEqual([Buffer.from(plaintext).toString('base64url')])
        expect(queryFunction.mock.calls[0][4]).toBe(requestTimeoutMs)
        expect(jest.getTimerCount()).toBe(0)
    })

    test('file notation preserves a shorter configured deadline without returning partial data', async () => {
        const {options, queryFunction, notation, encrypted} = await notationFixture(5000)
        jest.useFakeTimers()
        const {promise, settled} = observe(getNotationResults(options, notation))
        await jest.advanceTimersByTimeAsync(0)
        const response = respond()
        response.push(encrypted.subarray(0, 16))
        await jest.advanceTimersByTimeAsync(4999)
        expect(settled).not.toHaveBeenCalled()
        await jest.advanceTimersByTimeAsync(1)
        await expect(promise).rejects.toBeInstanceOf(KeeperError)
        await expect(promise).rejects.toThrow(/timed out after 5000ms/)
        response.push(encrypted.subarray(16))
        response.finish()
        await expect(promise).rejects.toBeInstanceOf(KeeperError)
        expect(queryFunction.mock.calls[0][4]).toBe(5000)
        expect(jest.getTimerCount()).toBe(0)
    })

    test('concurrent clients keep default, shorter and longer deadlines independent', async () => {
        const file: KeeperFile = {fileUid: 'isolated-download', data: {}, url: fileUrl}
        await platform.importKey(file.fileUid, fileKey)
        const encrypted = await platform.encryptWithKey(plaintext, fileKey)
        const options = [undefined, 5000, 600000].map(requestTimeoutMs => ({
            storage: inMemoryStorage({}), requestTimeoutMs
        }))
        jest.useFakeTimers()
        const downloads = options.map(option => observe(downloadFile(file, undefined, option)))
        const responses = downloads.map((_download, index) => {
            const response = respond(index)
            response.push(encrypted.subarray(0, 16))
            return response
        })
        expect(new Set(exchanges.map(exchange => exchange.signal)).size).toBe(3)
        await jest.advanceTimersByTimeAsync(5000)
        await expect(downloads[1].promise).rejects.toThrow(/timed out after 5000ms/)
        expect(downloads[0].settled).not.toHaveBeenCalled()
        expect(downloads[2].settled).not.toHaveBeenCalled()
        expect(jest.getTimerCount()).toBe(2)
        await jest.advanceTimersByTimeAsync(40000)
        responses[0].push(encrypted.subarray(16))
        responses[0].finish()
        await expect(downloads[0].promise).resolves.toEqual(plaintext)
        expect(jest.getTimerCount()).toBe(1)
        await jest.advanceTimersByTimeAsync(255001)
        expect(downloads[2].settled).not.toHaveBeenCalled()
        responses[2].push(encrypted.subarray(16))
        responses[2].finish()
        await expect(downloads[2].promise).resolves.toEqual(plaintext)
        expect(exchanges[0].request.destroy).not.toHaveBeenCalled()
        expect(exchanges[1].request.destroy).toHaveBeenCalled()
        expect(exchanges[2].request.destroy).not.toHaveBeenCalled()
        expect(jest.getTimerCount()).toBe(0)
    })

    test.each(['complete', 'stalled'])('uploadFile keeps its default deadline through a %s response body', async mode => {
        const queryFunction = jest.fn<ReturnType<QueryFunction>, Parameters<QueryFunction>>(async (_url, transmissionKey) => ({
            statusCode: 200,
            headers: [],
            data: await platform.encryptWithKey(enc.encode(JSON.stringify({
                url: fileUrl, parameters: '{}', successStatusCode: 201
            })), transmissionKey.key)
        }))
        const options = await makeOptions(queryFunction)
        await platform.generatePrivateKey('upload-owner-public', options.storage)
        await options.storage.saveBytes('appOwnerPublicKey', await platform.exportPublicKey('upload-owner-public', options.storage))
        const ownerRecord: KeeperRecord = {recordUid: 'upload-owner-record', revision: 1, data: {fields: []}}
        await platform.importKey(ownerRecord.recordUid, new Uint8Array(32).fill(4))
        jest.useFakeTimers()
        const {promise, settled} = observe(uploadFile(options, ownerRecord, {
            name: 'notes.txt', title: 'Notes', data: plaintext
        }))
        await jest.advanceTimersByTimeAsync(0)
        expect(exchanges).toHaveLength(1)
        expect(exchanges[0].url).toBe(fileUrl)
        const response = respond(0, 201)
        response.push(enc.encode('first'))
        await jest.advanceTimersByTimeAsync(45000)
        expect(settled).not.toHaveBeenCalled()
        expect(response.resume).toHaveBeenCalled()
        if (mode === 'complete') {
            await jest.advanceTimersByTimeAsync(15000)
            response.push(enc.encode('last'))
            response.finish()
            await expect(promise).resolves.toMatch(/^[A-Za-z0-9_-]{22}$/)
            expect(exchanges[0].request.destroy).not.toHaveBeenCalled()
        } else {
            await jest.advanceTimersByTimeAsync(255000)
            await expect(promise).rejects.toBeInstanceOf(KeeperError)
            await expect(promise).rejects.toThrow(/timed out after 300000ms/)
            response.finish()
            await expect(promise).rejects.toBeInstanceOf(KeeperError)
            expect(exchanges[0].request.destroy).toHaveBeenCalled()
        }
        expect(queryFunction).toHaveBeenCalledTimes(1)
        expect(queryFunction.mock.calls[0][4]).toBeUndefined()
        expect(jest.getTimerCount()).toBe(0)
    })
})
