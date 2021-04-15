import {platform} from './platform'
import {privateKeyToRaw, webSafe64ToBytes} from './utils';

export const KEY_URL = 'url'
export const KEY_ID = 'id'
export const KEY_BINDING_KEY = 'bindingKey'
export const KEY_SECRET_KEY = 'secretKey'
export const KEY_PRIVATE_KEY = 'privateKey'

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
    getValue(key: string): string | null;
    saveValue(key: string, value: string): void;
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
    const clientId = platform.base64ToBytes(storage.getValue(KEY_ID))
    const secretKeyString = storage.getValue(KEY_SECRET_KEY)
    const secretKey = secretKeyString
        ? platform.base64ToBytes(secretKeyString)
        : undefined
    const bindingKey = secretKey ? undefined : platform.base64ToBytes(storage.getValue(KEY_BINDING_KEY))
    const privateKey = storage.getValue(KEY_PRIVATE_KEY)
    let privateKeyDer
    if (clientId.length === 32) { // BAT
        if (privateKey) {
            privateKeyDer = platform.base64ToBytes(privateKey)
        } else {
            privateKeyDer = await platform.generateKeyPair()
            storage.saveValue(KEY_PRIVATE_KEY, platform.bytesToBase64(privateKeyDer))
        }
    } else { // EDK, must have private key
        privateKeyDer = platform.base64ToBytes(privateKey)
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

export const clearBindingKey = async (storage: KeyValueStorage): Promise<void> => {
    const encryptionKey = platform.getRandomBytes(32)
    // const { payload, signature } = await preparePayload(context)
}

export const fetchAndDecryptSecrets = async (storage: KeyValueStorage): Promise<{ secrets: any[], justBound: boolean }> => {
    const context = await prepareContext(storage)
    const { payload, signature } = await preparePayload(context)
    const httpResponse = await platform.post(storage.getValue(KEY_URL), payload, {
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
        storage.saveValue(KEY_ID, response.applicationToken)
    }
    console.log(response)

    let secretKey: Uint8Array
    const secrets = []
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
        storage.saveValue(KEY_SECRET_KEY, platform.bytesToBase64(secretKey))
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
