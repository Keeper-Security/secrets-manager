import {platform} from './platform'
import {webSafe64ToBytes} from './utils';

export function initialize() {
    keeperPublicKeys = [
        webSafe64ToBytes('BLX7FK7OUkjdIDsQnhGCVH_Hi98khXsl8dl9u9qm8iHkCYv6MJp9nv5mlCglJr_hsMvlIRmG9sUZsKHBClwLLHo'),
        webSafe64ToBytes('BLX7FK7OUkjdIDsQnhGCVH_Hi98khXsl8dl9u9qm8iHkCYv6MJp9nv5mlCglJr_hsMvlIRmG9sUZsKHBClwLLHo'),
        webSafe64ToBytes('BLX7FK7OUkjdIDsQnhGCVH_Hi98khXsl8dl9u9qm8iHkCYv6MJp9nv5mlCglJr_hsMvlIRmG9sUZsKHBClwLLHo'),
        webSafe64ToBytes('BLX7FK7OUkjdIDsQnhGCVH_Hi98khXsl8dl9u9qm8iHkCYv6MJp9nv5mlCglJr_hsMvlIRmG9sUZsKHBClwLLHo'),
        webSafe64ToBytes('BLX7FK7OUkjdIDsQnhGCVH_Hi98khXsl8dl9u9qm8iHkCYv6MJp9nv5mlCglJr_hsMvlIRmG9sUZsKHBClwLLHo'),
        webSafe64ToBytes('BLX7FK7OUkjdIDsQnhGCVH_Hi98khXsl8dl9u9qm8iHkCYv6MJp9nv5mlCglJr_hsMvlIRmG9sUZsKHBClwLLHo'),
    ]
}

let keeperPublicKeys: Uint8Array[]

export type ClientConfiguration = {
    url: string;
    clientSecret?: string;
}

type Payload = {
    publicKey?: string
}

type TransmissionKey = {
    key: Uint8Array
    publicKeyId: number
    encryptedKey: Uint8Array
}

export async function generateTransmissionKey(keyNumber: number): Promise<TransmissionKey> {
    const transmissionKey = platform.getRandomBytes(32)
    const encryptedKey = await platform.publicEncrypt(transmissionKey, keeperPublicKeys[keyNumber - 1])
    return {
        publicKeyId: keyNumber,
        key: transmissionKey,
        encryptedKey: encryptedKey
    }
}

export type KeeperHost = 'keepersecurity.com' | 'keepersecurity.eu' | 'keepersecurity.au'

export const createClientConfiguration = (host: KeeperHost): ClientConfiguration => ({
    url: `https://${host}/api/v2/`
});

// client secret:
// 1. one time token
// 2. private key
// 3. nothing

async function preparePayload(options: ClientConfiguration, transmissionKey: TransmissionKey): Promise<Uint8Array> {

    const payload: Payload = {}

    if (options.clientSecret && options.clientSecret.startsWith('device:')) {
        throw new Error('device configuration mode is not implemented yet')
    } else {
        const ecdh = await platform.generateKeyPair()
        payload.publicKey = ecdh.publicKey
        // deviceConfig.publicKey = ecdh.publicKey
        // deviceConfig.privateKey = ecdh.privateKey
    }

    const payloadBytes = platform.stringToBytes(JSON.stringify(payload))
    const encryptedPayload = await platform.aesEncrypt(payloadBytes, transmissionKey.key)
    return encryptedPayload
}

export const getSecret = async (secretUid: Uint8Array, options: ClientConfiguration): Promise<any> => {
    const transmissionKey = await generateTransmissionKey(1)
    const payload = await preparePayload(options, transmissionKey)
    let response = await platform.post(options.url, payload, {
        PublicKeyId: transmissionKey.publicKeyId.toString(),
        TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey)
    })
    if (response.statusCode !== 200) {
        throw new Error(platform.bytesToString(response.data))
    }
    return response
};
