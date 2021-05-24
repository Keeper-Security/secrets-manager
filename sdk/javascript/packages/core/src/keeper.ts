import {KeeperHttpResponse, KeyValueStorage, platform} from './platform'
import {webSafe64FromBytes, webSafe64ToBytes} from './utils';
export {KeyValueStorage} from './platform'

const KEY_URL = 'url' // base url for the Secrets Manager service
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
};

let keeperPublicKeys: Uint8Array[]

type TransmissionKey = {
    key: Uint8Array
    publicKeyId: number
    encryptedKey: Uint8Array
}

type ExecutionContext = {
    transmissionKey: TransmissionKey
    clientId: string
    clientKey: Uint8Array
    isBound: boolean
}

type GetPayload = {
    clientVersion: string
    clientId: string
    publicKey?: string   // passed once when binding
    requestedRecords?: string[]; // only return these records
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
    folders: KeeperFolder[]
}

export type KeeperRecord = {
    recordUid: string
    folderUid?: string
    recordKey: Uint8Array
    data: any
    files?: KeeperFile[]
}

export type KeeperFolder = {
    folderUid: string
    folderKey: Uint8Array
}

export type KeeperFile = {
    fileKey: Uint8Array
    data: any
    url?: string
    thumbnailUrl?: string
}

export const generateTransmissionKey = async (keyNumber: number): Promise<TransmissionKey> => {
    const transmissionKey = platform.getRandomBytes(32)
    const encryptedKey = await platform.publicEncrypt(transmissionKey, keeperPublicKeys[keyNumber - 1])
    return {
        publicKeyId: keyNumber,
        key: transmissionKey,
        encryptedKey: encryptedKey
    }
};

const prepareContext = async (storage: KeyValueStorage): Promise<ExecutionContext> => {
    const transmissionKey = await generateTransmissionKey(1)
    const clientId = await storage.getValue<string>(KEY_CLIENT_ID)
    if (!clientId) {
        throw new Error('Client Token is missing from the configuration')
    }
    let secretKey
    let isBound = false
    const appKeyString = await storage.getValue<string>(KEY_APP_KEY)
    if (appKeyString) {
        secretKey = platform.base64ToBytes(appKeyString)
        isBound = true
    }
    else {
        const secretKeyString = await storage.getValue<string>(KEY_CLIENT_KEY)
        if (secretKeyString) {
            secretKey = webSafe64ToBytes(secretKeyString)
        } else {
            throw new Error("No decrypt keys are present")
        }
    }
    const privateKey = await storage.getValue(KEY_PRIVATE_KEY)
    if (!privateKey) {
        await platform.generatePrivateKey(KEY_PRIVATE_KEY, storage)
    }
    return {
        transmissionKey: transmissionKey,
        clientId: clientId,
        clientKey: secretKey,
        isBound: isBound,
    }
};

const encryptAndSignPayload = async (storage: KeyValueStorage, context: ExecutionContext, payload: GetPayload | UpdatePayload): Promise<{ payload: Uint8Array, signature: Uint8Array }> => {
    const payloadBytes = platform.stringToBytes(JSON.stringify(payload))
    const encryptedPayload = await platform.encrypt(payloadBytes, context.transmissionKey.key)
    const signatureBase = Uint8Array.of(...context.transmissionKey.encryptedKey, ...encryptedPayload)
    const signature = await platform.sign(signatureBase, KEY_PRIVATE_KEY, storage)
    return {payload: encryptedPayload, signature}
};

const prepareGetPayload = async (storage: KeyValueStorage, context: ExecutionContext, recordsFilter?: string[]): Promise<{ payload: Uint8Array; signature: Uint8Array }> => {
    const payload: GetPayload = {
        clientVersion: 'w15.0.0', // TODO generate client version for SM
        clientId: context.clientId
    }
    if (!context.isBound) {
        const publicKey = await platform.exportPublicKey(KEY_PRIVATE_KEY, storage)
        payload.publicKey = platform.bytesToBase64(publicKey)
    }
    if (recordsFilter) {
        payload.requestedRecords = recordsFilter
    }
    return encryptAndSignPayload(storage, context, payload)
};

const prepareUpdatePayload = async (storage: KeyValueStorage, context: ExecutionContext, record: KeeperRecord): Promise<{ payload: Uint8Array, signature: Uint8Array }> => {
    const payload: UpdatePayload = {
        clientVersion: 'w15.0.0', // TODO generate client version for SM
        clientId: context.clientId
    }
    if (!context.clientKey) {
        throw new Error('For creates and updates, client must be authenticated by device token only')
    }
    payload.recordUid = record.recordUid
    const recordBytes = platform.stringToBytes(JSON.stringify(record.data))
    const encryptedRecord = await platform.encrypt(recordBytes, record.recordKey)
    payload.data = webSafe64FromBytes(encryptedRecord)
    return encryptAndSignPayload(storage, context, payload)
};

const postQuery = async (storage: KeyValueStorage, path: string, transmissionKey: TransmissionKey,
                         payload: Uint8Array, signature: Uint8Array): Promise<KeeperHttpResponse> => {
    const url = await storage.getValue(KEY_URL)
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
};

const decryptRecord = async (record: SecretsManagerResponseRecord, recordKey: Uint8Array): Promise<KeeperRecord> => {
    const decryptedRecord = await platform.decrypt(platform.base64ToBytes(record.data), recordKey)
    const keeperRecord: KeeperRecord = {
        recordUid: record.recordUid,
        recordKey: recordKey,
        data: JSON.parse(platform.bytesToString(decryptedRecord))
    }
    if (record.files) {
        keeperRecord.files = []
        for (const file of record.files) {
            const fileKey = await platform.decrypt(platform.base64ToBytes(file.fileKey), recordKey)
            const decryptedFile = await platform.decrypt(platform.base64ToBytes(file.data), fileKey)
            keeperRecord.files.push({
                fileKey: fileKey,
                data: JSON.parse(platform.bytesToString(decryptedFile)),
                url: file.url,
                thumbnailUrl: file.thumbnailUrl
            })
        }
    }
    return keeperRecord
};

const fetchAndDecryptSecrets = async (storage: KeyValueStorage, recordsFilter?: string[]): Promise<{ secrets: KeeperSecrets; justBound: boolean }> => {
    const context = await prepareContext(storage)
    const { payload, signature } = await prepareGetPayload(storage, context, recordsFilter)
    const httpResponse = await postQuery(storage, 'get_secret', context.transmissionKey, payload, signature)
    const decryptedResponse = await platform.decrypt(httpResponse.data, context.transmissionKey.key)
    const response = JSON.parse(platform.bytesToString(decryptedResponse)) as SecretsManagerResponse

    let secretKey: Uint8Array
    const records: KeeperRecord[] = []
    const folders: KeeperFolder[] = []
    let justBound = false
    if (response.encryptedAppKey) {
        justBound = true
        secretKey = await platform.decrypt(platform.base64ToBytes(response.encryptedAppKey), context.clientKey)
        await storage.saveValue(KEY_APP_KEY, platform.bytesToBase64(secretKey))
    }
    else {
        secretKey = context.clientKey
    }
    if (response.records) {
        for (const record of response.records) {
            const recordKey = await platform.decrypt(platform.base64ToBytes(record.recordKey), secretKey)
            const decryptedRecord = await decryptRecord(record, recordKey)
            records.push(decryptedRecord)
        }
    }
    if (response.folders) {
        for (const folder of response.folders) {
            const folderKey = await platform.decrypt(platform.base64ToBytes(folder.folderKey), secretKey)
            folders.push({
                folderUid: folder.folderUid,
                folderKey: folderKey
            })
            for (const record of folder.records) {
                const recordKey = await platform.decrypt(platform.base64ToBytes(record.recordKey), folderKey)
                const decryptedRecord = await decryptRecord(record, recordKey)
                decryptedRecord.folderUid = folder.folderUid
                records.push(decryptedRecord)
            }
        }
    }
    const secrets: KeeperSecrets = {
        records: records,
        folders: folders
    }
    return { secrets, justBound }
}

export const initializeStorage = async (storage: KeyValueStorage, clientKey: string, domain: string | 'keepersecurity.com' | 'keepersecurity.eu' | 'keepersecurity.au') => {
    const url = await storage.getValue(KEY_URL)
    if (!url) {
        await storage.saveValue(KEY_URL, `https://${domain}/api/rest/sm/v1`)
    }
    const existingClientKey = await storage.getValue(KEY_CLIENT_KEY)
    if (existingClientKey !== clientKey) {
        if (existingClientKey) {  // client id has changed, need to reset the rest of keys
            console.log('Client Key has changed, resetting the keys...')
            await storage.clearValues([KEY_CLIENT_KEY, KEY_APP_KEY, KEY_PRIVATE_KEY])
        }
        await storage.saveValue(KEY_CLIENT_KEY, clientKey)
        const clientId = await platform.hash(webSafe64ToBytes(clientKey))
        await storage.saveValue(KEY_CLIENT_ID, platform.bytesToBase64(clientId))
    }
};

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
    return platform.decrypt(fileResponse.data, file.fileKey);
};

export const downloadThumbnail = async (file: KeeperFile): Promise<Uint8Array> => {
    const fileResponse = await platform.get(file.thumbnailUrl!, {})
    return platform.decrypt(fileResponse.data, file.fileKey);
};
