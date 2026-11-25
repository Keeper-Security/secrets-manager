// Tests for the log lines that getSecrets writes when it skips a record or a file.
//
// The parser puts a slice of its input into a SyntaxError message. For a record or a file, the
// input is decrypted vault data. Each test below puts a canary text that is not JSON where the
// SDK expects JSON, captures every console line, and checks two things: the exact skip line, and
// that no line holds a slice of 5 or more characters of the canary. The exact-line check also
// catches a parser message that holds a shorter slice of the input.
//
// Every test runs on the node platform and on the browser platform. The server reply is scripted
// with queryFunction, so no test uses the network.
import {getSecrets, initialize, initializeStorage, KeeperCryptoError, KeeperError, SecretManagerOptions, tryGetNotationResults} from '../src/keeper'
import {connectPlatform, inMemoryStorage, KeeperHttpResponse, Platform, platform} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'
import {browserPlatform} from '../src/browser/browserPlatform'
import {webSafe64FromBytes} from '../src/utils'

// The browser platform imports the client key with WebCrypto, so it must decode to 32 bytes.
const FAKE_CLIENT_KEY = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

const TRANSMISSION_KEY = new Uint8Array(32).fill(1)
const APP_KEY = new Uint8Array(32).fill(2)
const FOLDER_KEY = new Uint8Array(32).fill(3)
const RECORD_KEY = new Uint8Array(32).fill(4)
const FILE_KEY = new Uint8Array(32).fill(5)

const LONG_CANARY = 'HARMLESS-MARKER-0123456789-abcdefghijklmnopqrstuvwxyz-ZZZ'
const LINE_BREAK_CANARY = 'HARMS\nLESS-MARKER-0123456789-abcdefghijklmnop'
const SHORT_CANARY = 'HARMLESS-SHORT-7531'

const VALID_RECORD_DATA = JSON.stringify({title: 'Valid Record', type: 'login', fields: [], custom: []})
const VALID_FILE_DATA = JSON.stringify({name: 'valid.txt', title: 'valid.txt', size: 1, type: 'text/plain'})

const SKIP_PHRASE = 'skipped due to error'

const bytes = (text: string): Uint8Array => platform.stringToBytes(text)
const b64 = (data: Uint8Array): string => platform.bytesToBase64(data)

// Every slice of 5 or more characters of the canary holds a slice of exactly 5 characters, so a
// check of all 5-character slices covers all longer slices too.
const expectNoCanarySlice = (texts: string[], canary: string) => {
    for (const text of texts) {
        for (let i = 0; i + 5 <= canary.length; i++) {
            const slice = canary.slice(i, i + 5)
            if (text.includes(slice)) {
                throw new Error(`Captured text holds the canary slice ${JSON.stringify(slice)}: ${JSON.stringify(text)}`)
            }
        }
    }
}

type Captured = { error: string[], warn: string[], log: string[], all: () => string[] }

const captureConsole = (): Captured => {
    const captured: Captured = {
        error: [],
        warn: [],
        log: [],
        all: () => [...captured.error, ...captured.warn, ...captured.log]
    }
    const toLine = (args: any[]) => args.map(a => a instanceof Error || typeof a?.message === 'string' ? `${a.name}: ${a.message}\n${a.stack}` : String(a)).join(' ')
    jest.spyOn(console, 'error').mockImplementation((...args: any[]) => { captured.error.push(toLine(args)) })
    jest.spyOn(console, 'warn').mockImplementation((...args: any[]) => { captured.warn.push(toLine(args)) })
    jest.spyOn(console, 'log').mockImplementation((...args: any[]) => { captured.log.push(toLine(args)) })
    return captured
}

const encryptRecord = async (recordUid: string, data: string, extra: any = {}) => ({
    recordUid,
    recordKey: b64(await platform.encryptWithKey(RECORD_KEY, APP_KEY)),
    data: b64(await platform.encryptWithKey(bytes(data), RECORD_KEY)),
    revision: 1,
    files: [],
    ...extra
})

const encryptFile = async (fileUid: string, data: string) => ({
    fileUid,
    fileKey: b64(await platform.encryptWithKey(FILE_KEY, RECORD_KEY)),
    data: b64(await platform.encryptWithKey(bytes(data), FILE_KEY)),
    url: 'https://fake.keepersecurity.com/file',
    thumbnailUrl: undefined
})

// Pins the transmission key, encrypts the reply with it, and returns options whose queryFunction
// returns that reply. The app key goes into storage directly, as if the client is already bound.
const setup = async (reply: any): Promise<SecretManagerOptions> => {
    const serverResponse = {expiresOn: 0, warnings: [], folders: [], records: [], ...reply}
    const encryptedResponse = await platform.encryptWithKey(bytes(JSON.stringify(serverResponse)), TRANSMISSION_KEY)
    platform.getRandomBytes = () => TRANSMISSION_KEY
    const queryFunction = (): Promise<KeeperHttpResponse> =>
        Promise.resolve({data: encryptedResponse, statusCode: 200, headers: []})
    const storage = inMemoryStorage({})
    await initializeStorage(storage, `US:${FAKE_CLIENT_KEY}`)
    await storage.saveBytes('appKey', APP_KEY)
    return {storage, queryFunction}
}

describe.each([
    ['node', nodePlatform],
    ['browser', browserPlatform],
] as [string, Platform][])('skip line text (%s platform)', (_name, plat) => {
    const originalGetRandomBytes = plat.getRandomBytes

    beforeEach(() => {
        // The platform entry points call initialize() to load the server public keys. This file
        // imports the source modules directly, so it calls initialize() itself.
        connectPlatform(plat)
        initialize()
        plat.cleanKeyCache()
    })

    afterEach(() => {
        plat.getRandomBytes = originalGetRandomBytes
        plat.cleanKeyCache()
        jest.restoreAllMocks()
    })

    const recordLine = (uid: string, rest: string) => `Record ${uid} ${SKIP_PHRASE}: ${rest}`
    const notJson = (kind: string, uid: string) => `KeeperCryptoError, ${kind} ${uid} decrypted data is not valid JSON`

    test.each([
        ['a long canary', LONG_CANARY],
        ['a canary with a raw line break', LINE_BREAK_CANARY],
        ['a canary of 20 characters or fewer', SHORT_CANARY],
    ])('a flat record with %s is skipped with a fixed line, and a valid record is still returned', async (_label, canary) => {
        expect(canary.length > 20).toBe(canary !== SHORT_CANARY)
        const options = await setup({
            records: [
                await encryptRecord('rec-uid-nonjson', canary),
                await encryptRecord('rec-uid-valid', VALID_RECORD_DATA),
            ]
        })
        const captured = captureConsole()

        const secrets = await getSecrets(options)

        expect(secrets.records.map(r => r.recordUid)).toEqual(['rec-uid-valid'])
        expect(secrets.records[0].data.title).toBe('Valid Record')
        expect(captured.error).toEqual([recordLine('rec-uid-nonjson', notJson('Record', 'rec-uid-nonjson'))])
        expect(captured.warn).toEqual([])
        expect(captured.log).toEqual([])
        expectNoCanarySlice(captured.all(), canary)
    })

    test('a flat record with innerFolderUid and a folder-wrapped record key is skipped with a fixed line', async () => {
        const folderUid = 'shared-folder-uid'
        const recordUid = 'rec-uid-nonjson-in-shared-folder'
        const options = await setup({
            folders: [{folderUid, folderKey: b64(await platform.encryptWithKey(FOLDER_KEY, APP_KEY)), data: '', records: []}],
            records: [{
                recordUid,
                recordKey: b64(await platform.encryptWithKey(RECORD_KEY, FOLDER_KEY)),
                data: b64(await platform.encryptWithKey(bytes(LONG_CANARY), RECORD_KEY)),
                revision: 1,
                files: [],
                innerFolderUid: folderUid
            }]
        })
        const captured = captureConsole()

        const secrets = await getSecrets(options)

        expect(secrets.records).toEqual([])
        expect(captured.error).toEqual([recordLine(recordUid, notJson('Record', recordUid))])
        expect(captured.all()).toHaveLength(1)
        expectNoCanarySlice(captured.all(), LONG_CANARY)
    })

    test('a record in a folder is skipped with a fixed line', async () => {
        const folderUid = 'folder-uid'
        const recordUid = 'rec-uid-nonjson-folder-record'
        const options = await setup({
            folders: [{
                folderUid,
                folderKey: b64(await platform.encryptWithKey(FOLDER_KEY, APP_KEY)),
                data: '',
                records: [
                    {
                        recordUid,
                        recordKey: b64(await platform.encryptWithKey(RECORD_KEY, FOLDER_KEY)),
                        data: b64(await platform.encryptWithKey(bytes(LONG_CANARY), RECORD_KEY)),
                        revision: 1,
                        files: []
                    },
                    {
                        recordUid: 'rec-uid-valid-folder-record',
                        recordKey: b64(await platform.encryptWithKey(RECORD_KEY, FOLDER_KEY)),
                        data: b64(await platform.encryptWithKey(bytes(VALID_RECORD_DATA), RECORD_KEY)),
                        revision: 1,
                        files: []
                    }
                ]
            }]
        })
        const captured = captureConsole()

        const secrets = await getSecrets(options)

        expect(secrets.records.map(r => [r.recordUid, r.folderUid])).toEqual([['rec-uid-valid-folder-record', folderUid]])
        expect(captured.error).toEqual([`Record ${recordUid} in folder ${folderUid} ${SKIP_PHRASE}: ${notJson('Record', recordUid)}`])
        expect(captured.all()).toHaveLength(1)
        expectNoCanarySlice(captured.all(), LONG_CANARY)
    })

    test.each([
        ['a long canary', LONG_CANARY],
        ['a canary with a raw line break', LINE_BREAK_CANARY],
        ['a canary of 20 characters or fewer', SHORT_CANARY],
    ])('file metadata with %s is skipped with a fixed line, and the record and its valid file stay', async (_label, canary) => {
        const recordUid = 'rec-uid-with-files'
        const options = await setup({
            records: [await encryptRecord(recordUid, VALID_RECORD_DATA, {
                files: [await encryptFile('file-uid-nonjson', canary), await encryptFile('file-uid-valid', VALID_FILE_DATA)]
            })]
        })
        const captured = captureConsole()

        const secrets = await getSecrets(options)

        expect(secrets.records.map(r => r.recordUid)).toEqual([recordUid])
        expect(secrets.records[0].files!.map(f => f.fileUid)).toEqual(['file-uid-valid'])
        expect(captured.error).toEqual([`File file-uid-nonjson ${SKIP_PHRASE}: ${notJson('File', 'file-uid-nonjson')}`])
        expect(captured.all()).toHaveLength(1)
        expectNoCanarySlice(captured.all(), canary)
    })

    test('a record whose ciphertext fails authentication gives a line with the UID and the class only', async () => {
        const recordUid = 'rec-uid-tampered'
        const record = await encryptRecord(recordUid, VALID_RECORD_DATA)
        const data = platform.base64ToBytes(record.data)
        // The last byte is in the AES-GCM tag, so this change always fails authentication.
        data[data.length - 1] ^= 0xff
        record.data = b64(data)
        const options = await setup({records: [record]})
        const captured = captureConsole()

        const secrets = await getSecrets(options)

        expect(secrets.records).toEqual([])
        expect(captured.error).toHaveLength(1)
        expect(captured.all()).toHaveLength(1)
        // A crypto library error is not a KeeperError, so the line shows only its class name.
        // The class name differs by platform (Error on node, DOMException in WebCrypto).
        expect(captured.error[0]).toMatch(new RegExp(`^Record ${recordUid} ${SKIP_PHRASE}: [A-Za-z]+$`))
    })

    test.each([
        ['null', () => null, 'null'],
        ['undefined', () => undefined, 'undefined'],
        ['a string', () => `text ${LONG_CANARY}`, 'String'],
        ['a number', () => 42, 'Number'],
        ['an object with no prototype', () => Object.assign(Object.create(null), {message: LONG_CANARY}), 'object'],
        ['an error that is not a KeeperError', () => new TypeError(LONG_CANARY), 'TypeError'],
    ])('a record decrypt that throws %s gives a line with no message', async (_label, makeThrown, expectedText) => {
        const recordUid = 'rec-uid-odd-throw'
        const options = await setup({records: [await encryptRecord(recordUid, VALID_RECORD_DATA)]})
        const originalDecrypt = plat.decrypt
        jest.spyOn(plat, 'decrypt').mockImplementation((data, keyId, storage, useCBC) => {
            if (keyId === recordUid) return Promise.reject(makeThrown())
            return originalDecrypt(data, keyId, storage, useCBC)
        })
        const captured = captureConsole()

        const secrets = await getSecrets(options)

        expect(secrets.records).toEqual([])
        expect(captured.error).toEqual([recordLine(recordUid, expectedText)])
        expect(captured.all()).toHaveLength(1)
        expectNoCanarySlice(captured.all(), LONG_CANARY)
    })

    test('app data that is not valid JSON rejects with a fixed KeeperError and logs no canary text', async () => {
        const options = await setup({
            appData: webSafe64FromBytes(await platform.encryptWithKey(bytes(LONG_CANARY), APP_KEY)),
            records: [await encryptRecord('rec-uid-valid', VALID_RECORD_DATA)]
        })
        const captured = captureConsole()

        let thrown: any
        try {
            await getSecrets(options)
        } catch (e) {
            thrown = e
        }

        expect(thrown).toBeInstanceOf(KeeperError)
        expect(thrown).not.toBeInstanceOf(KeeperCryptoError)
        expect(thrown.message).toBe('Application data is not valid JSON')
        expect(thrown.cause).toBeUndefined()
        expectNoCanarySlice([thrown.message, String(thrown.stack), ...captured.all()], LONG_CANARY)
    })

    // tryGetNotationResults catches the error and writes the whole error object to the log.
    test('tryGetNotationResults with app data that is not valid JSON logs only the fixed error text', async () => {
        const options = await setup({
            appData: webSafe64FromBytes(await platform.encryptWithKey(bytes(LONG_CANARY), APP_KEY)),
            records: [await encryptRecord('rec-uid-valid', VALID_RECORD_DATA)]
        })
        const captured = captureConsole()

        const values = await tryGetNotationResults(options, 'keeper://rec-uid-valid/field/login')

        expect(values).toEqual([])
        expect(captured.error).toHaveLength(1)
        expect(captured.error[0].startsWith('KeeperError: Application data is not valid JSON')).toBe(true)
        expect(captured.all()).toHaveLength(1)
        expectNoCanarySlice(captured.all(), LONG_CANARY)
    })

    // The platform makes this KeeperCryptoError, so its fixed text stays in the line.
    test('a flat record whose key is not in the key cache keeps the SDK message in its line', async () => {
        const recordUid = 'rec-uid-no-cached-key'
        const record = await encryptRecord(recordUid, VALID_RECORD_DATA)
        delete record.recordKey
        const options = await setup({records: [record]})
        const captured = captureConsole()

        const secrets = await getSecrets(options)

        expect(secrets.records).toEqual([])
        expect(captured.error).toEqual([recordLine(recordUid, `KeeperCryptoError, Unable to load the key ${recordUid}`)])
        expect(captured.all()).toHaveLength(1)
    })

    test('a record in a folder with no record key keeps the SDK message in its line', async () => {
        const folderUid = 'folder-uid'
        const recordUid = 'rec-uid-no-key'
        const options = await setup({
            folders: [{
                folderUid,
                folderKey: b64(await platform.encryptWithKey(FOLDER_KEY, APP_KEY)),
                data: '',
                records: [{recordUid, data: b64(await platform.encryptWithKey(bytes(VALID_RECORD_DATA), RECORD_KEY)), revision: 1, files: []}]
            }]
        })
        const captured = captureConsole()

        const secrets = await getSecrets(options)

        expect(secrets.records).toEqual([])
        expect(captured.error).toEqual([
            `Record ${recordUid} in folder ${folderUid} ${SKIP_PHRASE}: KeeperError, Record key missing for UID ${recordUid} in folder ${folderUid}`
        ])
        expect(captured.all()).toHaveLength(1)
    })

    test('a fully valid response logs nothing', async () => {
        const folderUid = 'folder-uid'
        const options = await setup({
            folders: [{
                folderUid,
                folderKey: b64(await platform.encryptWithKey(FOLDER_KEY, APP_KEY)),
                data: '',
                records: [{
                    recordUid: 'rec-uid-valid-folder-record',
                    recordKey: b64(await platform.encryptWithKey(RECORD_KEY, FOLDER_KEY)),
                    data: b64(await platform.encryptWithKey(bytes(VALID_RECORD_DATA), RECORD_KEY)),
                    revision: 1,
                    files: []
                }]
            }],
            records: [await encryptRecord('rec-uid-valid', VALID_RECORD_DATA, {files: [await encryptFile('file-uid-valid', VALID_FILE_DATA)]})],
            appData: webSafe64FromBytes(await platform.encryptWithKey(bytes(JSON.stringify({title: 'App'})), APP_KEY))
        })
        const captured = captureConsole()

        const secrets = await getSecrets(options)

        expect(secrets.records.map(r => r.recordUid).sort()).toEqual(['rec-uid-valid', 'rec-uid-valid-folder-record'])
        expect(secrets.records.find(r => r.recordUid === 'rec-uid-valid')!.files!.map(f => f.fileUid)).toEqual(['file-uid-valid'])
        expect(secrets.appData).toEqual({title: 'App'})
        expect(captured.all()).toEqual([])
    })

    test('the folder skip line in getSecrets keeps its present text', async () => {
        const folderUid = 'folder-uid-no-key'
        const options = await setup({folders: [{folderUid, data: '', records: []}]})
        const captured = captureConsole()

        await getSecrets(options)

        expect(captured.error).toEqual([
            `Folder ${folderUid} ${SKIP_PHRASE}: Error, Folder key missing for UID ${folderUid}; reinitialize with a fresh One-Time Token`
        ])
        expect(captured.all()).toHaveLength(1)
    })
})
