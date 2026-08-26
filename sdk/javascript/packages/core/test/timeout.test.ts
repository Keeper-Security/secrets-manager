import {
    downloadFile,
    downloadThumbnail,
    getSecrets,
    initializeStorage,
    inMemoryStorage,
    KeeperError,
    KeeperFile,
    KeeperRecord,
    KeeperHttpResponse,
    platform,
    SecretManagerOptions,
    uploadFile,
} from '../'

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
    test.each([0, -1, NaN, Infinity, -Infinity])('rejects requestTimeoutMs=%p before any request is attempted', async (invalid) => {
        const queryFunction = jest.fn()
        const options = await makeOptions(queryFunction, invalid)
        let error: any
        try {
            await getSecrets(options)
        } catch (e) {
            error = e
        }
        expect(error).toBeInstanceOf(Error)
        expect(error).not.toBeInstanceOf(KeeperError)
        expect(error.message).toContain('requestTimeoutMs')
        expect(queryFunction).not.toHaveBeenCalled()
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
            throw new KeeperError('Request to https://example.com timed out after 30000ms')
        })
        const options = await makeOptions(queryFunction)
        await expect(getSecrets(options)).rejects.toBeInstanceOf(KeeperError)
        expect(queryFunction).toHaveBeenCalledTimes(1)
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

    test('an explicit timeoutMs argument wins over options.requestTimeoutMs', async () => {
        const file = fakeFile()
        await downloadFile(file, 111, {storage: inMemoryStorage({}), requestTimeoutMs: 999})
        expect(platform.get).toHaveBeenCalledWith(file.url, {}, 111)
    })

    test('falls back to options.requestTimeoutMs when timeoutMs is omitted', async () => {
        const file = fakeFile()
        await downloadFile(file, undefined, {storage: inMemoryStorage({}), requestTimeoutMs: 222})
        expect(platform.get).toHaveBeenCalledWith(file.url, {}, 222)
    })

    test('passes undefined through (platform default applies) when neither is set', async () => {
        const file = fakeFile()
        await downloadFile(file)
        expect(platform.get).toHaveBeenCalledWith(file.url, {}, undefined)
    })

    test('rejects an invalid resolved timeoutMs before calling platform.get', async () => {
        const file = fakeFile()
        await expect(downloadFile(file, -1)).rejects.toThrow(/requestTimeoutMs/)
        expect(platform.get).not.toHaveBeenCalled()
    })

    test('downloadThumbnail applies the same precedence against thumbnailUrl', async () => {
        const file = fakeFile()
        await downloadThumbnail(file, undefined, {storage: inMemoryStorage({}), requestTimeoutMs: 333})
        expect(platform.get).toHaveBeenCalledWith(file.thumbnailUrl, {}, 333)
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

    test('threads options.requestTimeoutMs through to platform.fileUpload', async () => {
        const fileUploadMock = jest.fn(async (_url?: string, _params?: any, _data?: any, _timeoutMs?: number) => ({statusCode: 201, statusMessage: 'Created'}))
        platform.fileUpload = fileUploadMock
        const {options, ownerRecord, file} = await setup(4567)
        await uploadFile(options, ownerRecord, file)
        expect(fileUploadMock.mock.calls[0][3]).toBe(4567)
    })

    test('rejects an invalid requestTimeoutMs before calling platform.fileUpload', async () => {
        const fileUploadMock = jest.fn()
        platform.fileUpload = fileUploadMock
        const {options, ownerRecord, file} = await setup(0)
        await expect(uploadFile(options, ownerRecord, file)).rejects.toThrow(/requestTimeoutMs/)
        expect(fileUploadMock).not.toHaveBeenCalled()
    })
})
