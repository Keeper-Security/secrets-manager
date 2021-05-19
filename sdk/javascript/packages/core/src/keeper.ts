import {KeeperHttpResponse, platform} from './platform'
import {privateKeyToRaw, webSafe64FromBytes, webSafe64ToBytes} from './utils';

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

export type KeyValueStorage = {
    getValue(key: string): Promise<string | undefined>;
    saveValue(key: string, value: string): Promise<void>;
    clearValues(keys: string[]): Promise<void>;
}

type TransmissionKey = {
    key: Uint8Array
    publicKeyId: number
    encryptedKey: Uint8Array
}

type ExecutionContext = {
    transmissionKey: TransmissionKey
    clientId: Uint8Array
    clientKey: Uint8Array
    isBound: boolean
    privateKey: Uint8Array
}

type Payload = {
    clientVersion: string
    clientId: string
    publicKey?: string   // passed once when binding
    recordUid?: string   // for update, uid of the record
    data?: string        // for create and update, the record data
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

type KeeperRecord = {
    recordUid: string
    folderUid?: string
    recordKey: Uint8Array
    data: any
    files?: KeeperFile[]
}

type KeeperFolder = {
    folderUid: string
    folderKey: Uint8Array
}

type KeeperSecrets = {
    records: KeeperRecord[]
    folders: KeeperFolder[]
}

type KeeperFile = {
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
    const clientId = await storage.getValue(KEY_CLIENT_ID)
    if (!clientId) {
        throw new Error('Client Token is missing from the configuration')
    }
    const clientIdBytes = platform.base64ToBytes(clientId)
    let secretKey
    let isBound = false
    const appKeyString = await storage.getValue(KEY_APP_KEY)
    if (appKeyString) {
        secretKey = platform.base64ToBytes(appKeyString)
        isBound = true
    }
    else {
        const secretKeyString = await storage.getValue(KEY_CLIENT_KEY)
        if (secretKeyString) {
            secretKey = platform.base64ToBytes(secretKeyString)
        } else {
            throw new Error("No decrypt keys are present")
        }
    }
    const privateKeyString = await storage.getValue(KEY_PRIVATE_KEY)
    let privateKeyDer
    if (privateKeyString) {
        privateKeyDer = platform.base64ToBytes(privateKeyString)
    } else {
        privateKeyDer = await platform.generateKeyPair()
        await storage.saveValue(KEY_PRIVATE_KEY, platform.bytesToBase64(privateKeyDer))
    }
    return {
        transmissionKey: transmissionKey,
        clientId: clientIdBytes,
        clientKey: secretKey,
        isBound: isBound,
        privateKey: privateKeyDer
    }
};

const encryptAndSignPayload = async (context: ExecutionContext, payload: Payload): Promise<{ payload: Uint8Array, signature: Uint8Array }> => {
    const payloadBytes = platform.stringToBytes(JSON.stringify(payload))
    const encryptedPayload = await platform.encrypt(payloadBytes, context.transmissionKey.key)
    const signatureBase = Uint8Array.of(...context.transmissionKey.encryptedKey, ...encryptedPayload)
    const signature = await platform.sign(signatureBase, context.privateKey)
    return {payload: encryptedPayload, signature}
};

const preparePayload = async (context: ExecutionContext): Promise<{ payload: Uint8Array, signature: Uint8Array }> => {
    const payload: Payload = {
        clientVersion: 'w15.0.0', // TODO generate client version for SM
        clientId: platform.bytesToBase64(context.clientId)
    }
    if (!context.isBound) {
        const rawKeys = privateKeyToRaw(context.privateKey)
        payload.publicKey = platform.bytesToBase64(rawKeys.publicKey)
    }
    return encryptAndSignPayload(context, payload)
};

const prepareUpdatePayload = async (context: ExecutionContext, record: KeeperRecord): Promise<{ payload: Uint8Array, signature: Uint8Array }> => {
    const payload: Payload = {
        clientVersion: 'w15.0.0', // TODO generate client version for SM
        clientId: platform.bytesToBase64(context.clientId)
    }
    if (!context.clientKey) {
        throw new Error('For creates and updates, client must be authenticated by device token only')
    }
    payload.recordUid = record.recordUid
    const recordBytes = platform.stringToBytes(JSON.stringify(record.data))
    const encryptedRecord = await platform.encrypt(recordBytes, record.recordKey)
    payload.data = webSafe64FromBytes(encryptedRecord)
    return encryptAndSignPayload(context, payload)
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

export const fetchAndDecryptSecrets = async (storage: KeyValueStorage): Promise<{ secrets: KeeperSecrets, justBound: boolean }> => {
    const context = await prepareContext(storage)
    const { payload, signature } = await preparePayload(context)
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

async function decryptRecord(record: SecretsManagerResponseRecord, recordKey: Uint8Array): Promise<KeeperRecord> {
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
}

export const initializeStorage = async (storage: KeyValueStorage, secretKey: string, domain: string | 'keepersecurity.com' | 'keepersecurity.eu' | 'keepersecurity.au') => {
    const url = await storage.getValue(KEY_URL)
    if (!url) {
        await storage.saveValue(KEY_URL, `https://${domain}/api/rest/sm/v1`)
    }
    const existingSecretKey = await storage.getValue(KEY_CLIENT_KEY)
    if (existingSecretKey !== secretKey) {
        if (existingSecretKey) {  // client id has changed, need to reset the rest of keys
            console.log('Secret Key has changed, resetting the keys...')
            await storage.clearValues([KEY_CLIENT_KEY, KEY_APP_KEY, KEY_PRIVATE_KEY])
        }
        await storage.saveValue(KEY_CLIENT_KEY, secretKey)
        const clientId = await platform.hash(webSafe64ToBytes(secretKey))
        await storage.saveValue(KEY_CLIENT_ID, platform.bytesToBase64(clientId))
    }
};

export const getSecrets = async (storage: KeyValueStorage, ): Promise<KeeperSecrets> => {
    const { secrets, justBound } = await fetchAndDecryptSecrets(storage)
    if (justBound) {
        try {
            await fetchAndDecryptSecrets(storage)
        }
        catch (e) {
            console.error(e)
        }
    }
    return secrets
}

export const updateSecret = async (storage: KeyValueStorage, record: KeeperRecord): Promise<void> => {
    const context = await prepareContext(storage)
    const { payload, signature } = await prepareUpdatePayload(context, record)
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

