import {platform} from './platform'
import {privateKeyToRaw, webSafe64ToBytes} from './utils';

const KEY_URL = 'url'
const KEY_ID = 'id'
const KEY_BINDING_KEY = 'bindingKey'
const KEY_SECRET_KEY = 'secretKey'
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
    id: Uint8Array
    bindingKey: Uint8Array
    secretKey: Uint8Array
    privateKey: Uint8Array
}

type Payload = {
    clientVersion: string
    id?: string
    publicKey?: string
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
}

type SecretsManagerResponse = {
    applicationToken: string
    folder: SecretsManagerResponseFolder
    record: SecretsManagerResponseRecord
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

// export type KeeperHost = 'keepersecurity.com' | 'keepersecurity.eu' | 'keepersecurity.au'

// export const createClientConfiguration = (host: KeeperHost): ClientConfiguration => ({
//     url: `https://${host}/api/v2/`
// });

const prepareContext = async (storage: KeyValueStorage): Promise<ExecutionContext> => {
    const transmissionKey = await generateTransmissionKey(1)
    const id = await storage.getValue(KEY_ID)
    if (!id) {
        throw new Error('Client ID is missing from the configuration')
    }
    const clientId = platform.base64ToBytes(id)
    let secretKey
    let bindingKey
    const secretKeyString = await storage.getValue(KEY_SECRET_KEY)
    if (secretKeyString) {
        secretKey = platform.base64ToBytes(secretKeyString)
    } else {
        const bindingKeyString = await storage.getValue(KEY_BINDING_KEY)
        if (!bindingKeyString) {
            throw new Error('Binding key is missing from the configuration')
        }
        bindingKey = platform.base64ToBytes(bindingKeyString)
    }
    const privateKeyString = await storage.getValue(KEY_PRIVATE_KEY)
    let privateKeyDer
    if (clientId.length === 32) { // BAT
        if (privateKeyString) {
            privateKeyDer = platform.base64ToBytes(privateKeyString)
        } else {
            privateKeyDer = await platform.generateKeyPair()
            await storage.saveValue(KEY_PRIVATE_KEY, platform.bytesToBase64(privateKeyDer))
        }
    } else { // EDK, must have private key
        if (!privateKeyString) {
            throw new Error('Private key is missing from the configuration')
        }
        privateKeyDer = platform.base64ToBytes(privateKeyString)
    }
    return {
        transmissionKey: transmissionKey,
        id: clientId,
        bindingKey: bindingKey,
        secretKey: secretKey,
        privateKey: privateKeyDer
    }
};

const preparePayload = async (context: ExecutionContext): Promise<{ payload: Uint8Array, signature: Uint8Array }> => {
    const payload: Payload = {
        clientVersion: 'w15.0.0', // TODO generate client version for SM
    }
    if (context.id.length === 32) { // BAT
        payload.id = platform.bytesToBase64(context.id)
        const rawKeys = privateKeyToRaw(context.privateKey)
        payload.publicKey = platform.bytesToBase64(rawKeys.publicKey)
    } else { // EDK
        payload.id = platform.bytesToBase64(context.id)
    }
    const payloadBytes = platform.stringToBytes(JSON.stringify(payload))
    const encryptedPayload = await platform.encrypt(payloadBytes, context.transmissionKey.key)
    const signatureBase = Uint8Array.of(...context.transmissionKey.encryptedKey, ...encryptedPayload)
    const signature = await platform.sign(signatureBase, context.privateKey)
    return { payload: encryptedPayload, signature }
};

export const fetchAndDecryptSecrets = async (storage: KeyValueStorage): Promise<{ secrets: any[], justBound: boolean }> => {
    const context = await prepareContext(storage)
    const { payload, signature } = await preparePayload(context)
    const url = await storage.getValue(KEY_URL)
    if (!url) {
        throw new Error('url is missing from the configuration')
    }
    const httpResponse = await platform.post(url, payload, {
        PublicKeyId: context.transmissionKey.publicKeyId.toString(),
        TransmissionKey: platform.bytesToBase64(context.transmissionKey.encryptedKey),
        Authorization: `Signature ${platform.bytesToBase64(signature)}`
    })
    if (httpResponse.statusCode !== 200) {
        throw new Error(platform.bytesToString(httpResponse.data))
    }
    const decryptedResponse = await platform.decrypt(httpResponse.data, context.transmissionKey.key)
    const response = JSON.parse(platform.bytesToString(decryptedResponse)) as SecretsManagerResponse
    if (response.applicationToken) {
        await storage.saveValue(KEY_ID, response.applicationToken)
    }

    let secretKey: Uint8Array
    const secrets: any[] = []
    let justBound = false
    if (context.secretKey) {
        secretKey = context.secretKey
    }
    else {
        justBound = true
        const encryptedSecretKey = response.record
            ? response.record.recordKey
            : response.folder
                ? response.folder.folderKey
                : undefined
        if (!encryptedSecretKey) {
            throw new Error('Invalid response from Keeper')
        }
        secretKey = await platform.decrypt(platform.base64ToBytes(encryptedSecretKey), context.bindingKey)
        await storage.saveValue(KEY_SECRET_KEY, platform.bytesToBase64(secretKey))
    }
    if (response.record) {
        const secretBytes = platform.base64ToBytes(response.record.data)
        const secret = await platform.decrypt(secretBytes, secretKey)
        secrets.push(JSON.parse(platform.bytesToString(secret)))
    } else if (response.folder) {
        for (const record of response.folder.records) {
            const encryptedRecordKey = platform.base64ToBytes(record.recordKey)
            const recordKey = await platform.decrypt(encryptedRecordKey, secretKey)
            const secretBytes = platform.base64ToBytes(record.data)
            const secret = await platform.decrypt(secretBytes, recordKey)
            secrets.push(JSON.parse(platform.bytesToString(secret)))
        }
    }
    return { secrets, justBound }
}

export const initializeStorage = async (storage: KeyValueStorage, bindingKey: string, domain: string | 'keepersecurity.com' | 'keepersecurity.eu' | 'keepersecurity.au') => {
    const url = await storage.getValue(KEY_URL)
    if (!url) {
        await storage.saveValue(KEY_URL, `https://${domain}/api/rest/sm/v1/get_secret`)
    }
    const existingBindingKey = await storage.getValue(KEY_BINDING_KEY)
    if (existingBindingKey !== bindingKey) {
        if (existingBindingKey) {  // binding key has changed, need to reset the rest of keys
            await storage.clearValues([KEY_SECRET_KEY, KEY_PRIVATE_KEY])
        }
        await storage.saveValue(KEY_BINDING_KEY, bindingKey)
        const encryptionKeyHash = await platform.hash(webSafe64ToBytes(bindingKey))
        await storage.saveValue(KEY_ID, platform.bytesToBase64(encryptionKeyHash))
    }
};

export const getSecrets = async (storage: KeyValueStorage): Promise<any[]> => {
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
