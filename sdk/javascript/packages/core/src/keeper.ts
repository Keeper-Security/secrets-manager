import {platform} from './platform'
import {privateKeyToRaw, webSafe64FromBytes, webSafe64ToBytes} from './utils';
import {inspect} from 'util';

const KEY_URL = 'url'
const KEY_CLIENT_ID = 'clientId'
const KEY_SECRET_KEY = 'secretKey'
const KEY_MASTER_KEY = 'masterKey'
const KEY_PRIVATE_KEY = 'privateKey'

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
    secretKey: Uint8Array
    isBound: boolean
    privateKey: Uint8Array
}

type Payload = {
    clientVersion: string
    clientId: string
    publicKey?: string
    recordUid?: string
    data?: string
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
    encryptedMasterKey: string
    folders: SecretsManagerResponseFolder[]
    records: SecretsManagerResponseRecord[]
}

type KeeperRecord = {
    recordUid: string
    recordKey: Uint8Array
    data: any
    files?: KeeperFile[]
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
    const masterKeyString = await storage.getValue(KEY_MASTER_KEY)
    if (masterKeyString) {
        secretKey = platform.base64ToBytes(masterKeyString)
        isBound = true
    }
    else {
        const secretKeyString = await storage.getValue(KEY_SECRET_KEY)
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
        secretKey: secretKey,
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
    if (!context.secretKey) { // BAT
        throw new Error('For updates, client must be authenticated by device token only')
    }
    payload.recordUid = record.recordUid
    const recordBytes = platform.stringToBytes(JSON.stringify(record.data))
    const encryptedRecord = await platform.encrypt(recordBytes, record.recordKey)
    payload.data = webSafe64FromBytes(encryptedRecord)
    return encryptAndSignPayload(context, payload)
};

export const fetchAndDecryptSecrets = async (storage: KeyValueStorage): Promise<{ secrets: any[], justBound: boolean }> => {
    const context = await prepareContext(storage)
    const { payload, signature } = await preparePayload(context)
    const url = await storage.getValue(KEY_URL)
    if (!url) {
        throw new Error('url is missing from the configuration')
    }
    const httpResponse = await platform.post(url + '/get_secret', payload, {
        PublicKeyId: context.transmissionKey.publicKeyId.toString(),
        TransmissionKey: platform.bytesToBase64(context.transmissionKey.encryptedKey),
        Authorization: `Signature ${platform.bytesToBase64(signature)}`
    })
    if (httpResponse.statusCode !== 200) {
        throw new Error(platform.bytesToString(httpResponse.data))
    }
    const decryptedResponse = await platform.decrypt(httpResponse.data, context.transmissionKey.key)
    const response = JSON.parse(platform.bytesToString(decryptedResponse)) as SecretsManagerResponse

    let secretKey: Uint8Array
    const secrets: any[] = []
    let justBound = false
    if (response.encryptedMasterKey) {
        justBound = true
        secretKey = await platform.decrypt(platform.base64ToBytes(response.encryptedMasterKey), context.secretKey)
        await storage.saveValue(KEY_MASTER_KEY, platform.bytesToBase64(secretKey))
    }
    else {
        secretKey = context.secretKey
    }
    if (response.records) {
        for (const record of response.records) {
            const recordKey = await platform.decrypt(platform.base64ToBytes(record.recordKey), secretKey)
            const decryptedRecord = await decryptRecord(record, recordKey)
            secrets.push(decryptedRecord)
        }
    }
    if (response.folders) {
        for (const folder of response.folders) {
            const folderKey = await platform.decrypt(platform.base64ToBytes(folder.folderKey), secretKey)
            for (const record of folder.records) {
                const recordKey = await platform.decrypt(platform.base64ToBytes(record.recordKey), folderKey)
                const decryptedRecord = await decryptRecord(record, recordKey)
                secrets.push(decryptedRecord)
            }
        }
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
    const existingSecretKey = await storage.getValue(KEY_SECRET_KEY)
    if (existingSecretKey !== secretKey) {
        if (existingSecretKey) {  // client id has changed, need to reset the rest of keys
            console.log('Secret Key has changed, resetting the keys...')
            await storage.clearValues([KEY_SECRET_KEY, KEY_MASTER_KEY, KEY_PRIVATE_KEY])
        }
        await storage.saveValue(KEY_SECRET_KEY, secretKey)
        const clientId = await platform.hash(webSafe64ToBytes(secretKey))
        await storage.saveValue(KEY_CLIENT_ID, platform.bytesToBase64(clientId))
    }
};

export const getSecrets = async (storage: KeyValueStorage): Promise<KeeperRecord[]> => {
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
    const url = await storage.getValue(KEY_URL)
    if (!url) {
        throw new Error('url is missing from the configuration')
    }
    const httpResponse = await platform.post(url + '/update_secret', payload, {
        PublicKeyId: context.transmissionKey.publicKeyId.toString(),
        TransmissionKey: platform.bytesToBase64(context.transmissionKey.encryptedKey),
        Authorization: `Signature ${platform.bytesToBase64(signature)}`
    })
    if (httpResponse.statusCode !== 200) {
        throw new Error(platform.bytesToString(httpResponse.data))
    }
}

export const downloadFile = async (file: KeeperFile): Promise<Uint8Array> => {
    const fileResponse = await platform.get(file.url!, {})
    return platform.decrypt(fileResponse.data, file.fileKey);
};

export const downloadThumbnail = async (file: KeeperFile): Promise<Uint8Array> => {
    const fileResponse = await platform.get(file.thumbnailUrl!, {})
    return platform.decrypt(fileResponse.data, file.fileKey);
};

