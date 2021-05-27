import {KeeperHttpResponse, KeyValueStorage, platform} from './platform'
import {webSafe64FromBytes, webSafe64ToBytes} from './utils'

export {KeyValueStorage} from './platform'

const KEY_URL = 'url' // base url for the Secrets Manager service
const KEY_TRANSMISSION_KEY = 'transmissionKey'
const KEY_CLIENT_ID = 'clientId'
const KEY_CLIENT_KEY = 'clientKey' // The key that is used to identify the client before public key
const KEY_APP_KEY = 'appKey' // The application key with which all secrets are encrypted
const KEY_PRIVATE_KEY = 'privateKey' // The client's private key

export const initialize = () => {
    keeperPublicKeys = [
        webSafe64ToBytes('BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'),
        webSafe64ToBytes('BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'),
        webSafe64ToBytes('BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'),
        webSafe64ToBytes('BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'),
        webSafe64ToBytes('BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'),
        webSafe64ToBytes('BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'),
    ]
}

let keeperPublicKeys: Uint8Array[]

type TransmissionKey = {
    publicKeyId: number
    encryptedKey: Uint8Array
}

type ExecutionContext = {
    transmissionKey: TransmissionKey
    clientId: string
}

type GetPayload = {
    clientVersion: string
    clientId: string
    publicKey?: string   // passed once when binding
    requestedRecords?: string[] // only return these records
}

type UpdatePayload = {
    clientVersion: string
    clientId: string
    recordUid?: string   // for update, uid of the record
    data?: string        // for update, the record data
}

type SecretsManagerResponseFolder = {
    folderUid: string
    folderKey: string
    records: SecretsManagerResponseRecord[]
}

type SecretsManagerResponseRecord = {
    recordUid: string
    recordKey: string
    data: string
    files: SecretsManagerResponseFile[]
}

type SecretsManagerResponseFile = {
    fileUid: string
    fileKey: string
    data: string
    url: string
    thumbnailUrl: string
}

type SecretsManagerResponse = {
    encryptedAppKey: string
    folders: SecretsManagerResponseFolder[]
    records: SecretsManagerResponseRecord[]
}

export type KeeperSecrets = {
    records: KeeperRecord[]
}

export type KeeperRecord = {
    recordUid: string
    folderUid?: string
    data: any
    files?: KeeperFile[]
}

export type KeeperFile = {
    fileUid: string
    data: any
    url?: string
    thumbnailUrl?: string
}

export const generateTransmissionKey = async (keyNumber: number): Promise<TransmissionKey> => {
    const transmissionKey = platform.getRandomBytes(32)
    await platform.importKey(KEY_TRANSMISSION_KEY, transmissionKey)
    const encryptedKey = await platform.publicEncrypt(transmissionKey, keeperPublicKeys[keyNumber - 1])
    return {
        publicKeyId: keyNumber,
        encryptedKey: encryptedKey
    }
}

const prepareContext = async (storage: KeyValueStorage): Promise<ExecutionContext> => {
    const transmissionKey = await generateTransmissionKey(1)
    const clientId = await storage.getString(KEY_CLIENT_ID)
    if (!clientId) {
        throw new Error('Client Id is missing from the configuration')
    }
    return {
        transmissionKey: transmissionKey,
        clientId: clientId
    }
}

const encryptAndSignPayload = async (storage: KeyValueStorage, context: ExecutionContext, payload: GetPayload | UpdatePayload): Promise<{ payload: Uint8Array, signature: Uint8Array }> => {
    const payloadBytes = platform.stringToBytes(JSON.stringify(payload))
    const encryptedPayload = await platform.encrypt(payloadBytes, KEY_TRANSMISSION_KEY, storage)
    const signatureBase = Uint8Array.of(...context.transmissionKey.encryptedKey, ...encryptedPayload)
    const signature = await platform.sign(signatureBase, KEY_PRIVATE_KEY, storage)
    return {payload: encryptedPayload, signature}
}

const prepareGetPayload = async (storage: KeyValueStorage, context: ExecutionContext, recordsFilter?: string[]): Promise<{ payload: Uint8Array, signature: Uint8Array }> => {
    const payload: GetPayload = {
        clientVersion: 'w15.0.0', // TODO generate client version for SM
        clientId: context.clientId
    }
    const appKey = await storage.getBytes(KEY_APP_KEY)
    if (!appKey) {
        const publicKey = await platform.exportPublicKey(KEY_PRIVATE_KEY, storage)
        payload.publicKey = platform.bytesToBase64(publicKey)
    }
    if (recordsFilter) {
        payload.requestedRecords = recordsFilter
    }
    return encryptAndSignPayload(storage, context, payload)
}

const prepareUpdatePayload = async (storage: KeyValueStorage, context: ExecutionContext, record: KeeperRecord): Promise<{ payload: Uint8Array, signature: Uint8Array }> => {
    const payload: UpdatePayload = {
        clientVersion: 'w15.0.0', // TODO generate client version for SM
        clientId: context.clientId
    }
    payload.recordUid = record.recordUid
    const recordBytes = platform.stringToBytes(JSON.stringify(record.data))
    const encryptedRecord = await platform.encrypt(recordBytes, record.recordUid)
    payload.data = webSafe64FromBytes(encryptedRecord)
    return encryptAndSignPayload(storage, context, payload)
}

const postQuery = async (storage: KeyValueStorage, path: string, transmissionKey: TransmissionKey,
                         payload: Uint8Array, signature: Uint8Array): Promise<KeeperHttpResponse> => {
    const url = await storage.getString(KEY_URL)
    if (!url) {
        throw new Error('url is missing from the configuration')
    }
    const httpResponse = await platform.post(`${url}/${path}`, payload, {
        PublicKeyId: transmissionKey.publicKeyId.toString(),
        TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
        Authorization: `Signature ${platform.bytesToBase64(signature)}`
    })
    if (httpResponse.statusCode !== 200) {
        throw new Error(platform.bytesToString(httpResponse.data))
    }
    return httpResponse
}

const decryptRecord = async (record: SecretsManagerResponseRecord): Promise<KeeperRecord> => {
    const decryptedRecord = await platform.decrypt(platform.base64ToBytes(record.data), record.recordUid)
    const keeperRecord: KeeperRecord = {
        recordUid: record.recordUid,
        data: JSON.parse(platform.bytesToString(decryptedRecord))
    }
    if (record.files) {
        keeperRecord.files = []
        for (const file of record.files) {
            await platform.unwrap(platform.base64ToBytes(file.fileKey), file.fileUid, record.recordUid)
            const decryptedFile = await platform.decrypt(platform.base64ToBytes(file.data), file.fileUid)
            keeperRecord.files.push({
                fileUid: file.fileUid,
                data: JSON.parse(platform.bytesToString(decryptedFile)),
                url: file.url,
                thumbnailUrl: file.thumbnailUrl
            })
        }
    }
    return keeperRecord
}

const fetchAndDecryptSecrets = async (storage: KeyValueStorage, recordsFilter?: string[]): Promise<{ secrets: KeeperSecrets, justBound: boolean }> => {
    const context = await prepareContext(storage)
    const { payload, signature } = await prepareGetPayload(storage, context, recordsFilter)
    const httpResponse = await postQuery(storage, 'get_secret', context.transmissionKey, payload, signature)
    const decryptedResponse = await platform.decrypt(httpResponse.data, KEY_TRANSMISSION_KEY)
    const response = JSON.parse(platform.bytesToString(decryptedResponse)) as SecretsManagerResponse

    const records: KeeperRecord[] = []
    let justBound = false
    if (response.encryptedAppKey) {
        justBound = true
        await platform.unwrap(platform.base64ToBytes(response.encryptedAppKey), KEY_APP_KEY, KEY_CLIENT_KEY, storage)
        await storage.delete(KEY_CLIENT_KEY)
    }
    if (response.records) {
        for (const record of response.records) {
            await platform.unwrap(platform.base64ToBytes(record.recordKey), record.recordUid, KEY_APP_KEY, storage, true)
            const decryptedRecord = await decryptRecord(record)
            records.push(decryptedRecord)
        }
    }
    if (response.folders) {
        for (const folder of response.folders) {
            await platform.unwrap(platform.base64ToBytes(folder.folderKey), folder.folderUid, KEY_APP_KEY, storage, true)
            for (const record of folder.records) {
                await platform.unwrap(platform.base64ToBytes(record.recordKey), record.recordUid, folder.folderUid)
                const decryptedRecord = await decryptRecord(record)
                decryptedRecord.folderUid = folder.folderUid
                records.push(decryptedRecord)
            }
        }
    }
    const secrets: KeeperSecrets = {
        records: records
    }
    return { secrets, justBound }
}

export const getClientId = async (clientKey: string): Promise<string> => {
    const clientKeyHash = await platform.hash(webSafe64ToBytes(clientKey))
    return platform.bytesToBase64(clientKeyHash)
}

export const initializeStorage = async (storage: KeyValueStorage, clientKey: string, domain: string | 'keepersecurity.com' | 'keepersecurity.eu' | 'keepersecurity.au') => {
    const clientKeyBytes = webSafe64ToBytes(clientKey)
    const clientKeyHash = await platform.hash(clientKeyBytes)
    const clientId = platform.bytesToBase64(clientKeyHash)
    const existingClientId = await storage.getString(KEY_CLIENT_ID)
    if (existingClientId && existingClientId === clientId) {
        return  // the storage is already initialised
    }
    if (existingClientId) {
        throw new Error(`The storage is already initialized with a different client Id (${existingClientId})`)
    }
    await storage.saveString(KEY_URL, `https://${domain}/api/rest/sm/v1`)
    await storage.saveString(KEY_CLIENT_ID, clientId)
    await platform.importKey(KEY_CLIENT_KEY, clientKeyBytes, storage)
    await platform.generatePrivateKey(KEY_PRIVATE_KEY, storage)
}

export const getSecrets = async (storage: KeyValueStorage, recordsFilter?: string[]): Promise<KeeperSecrets> => {
    const { secrets, justBound } = await fetchAndDecryptSecrets(storage, recordsFilter)
    if (justBound) {
        try {
            await fetchAndDecryptSecrets(storage, recordsFilter)
        }
        catch (e) {
            console.error(e)
        }
    }
    return secrets
}

export const updateSecret = async (storage: KeyValueStorage, record: KeeperRecord): Promise<void> => {
    const context = await prepareContext(storage)
    const { payload, signature } = await prepareUpdatePayload(storage, context, record)
    await postQuery(storage, 'update_secret', context.transmissionKey, payload, signature)
}

export const downloadFile = async (file: KeeperFile): Promise<Uint8Array> => {
    const fileResponse = await platform.get(file.url!, {})
    return platform.decrypt(fileResponse.data, file.fileUid)
}

export const downloadThumbnail = async (file: KeeperFile): Promise<Uint8Array> => {
    const fileResponse = await platform.get(file.thumbnailUrl!, {})
    return platform.decrypt(fileResponse.data, file.fileUid)
}
