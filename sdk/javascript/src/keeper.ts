import {platform} from './platform'
import {privateKeyToRaw, webSafe64FromBytes, webSafe64ToBytes} from './utils';
import {createPrivateKey} from 'crypto';

export function initialize() {
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
        payload.publicKey = options.clientSecret
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
    const signatureBase = Uint8Array.of(...transmissionKey.encryptedKey, ...payload)
    const privateKey = webSafe64ToBytes(options.clientSecret)
    let signature = await platform.sign(signatureBase, privateKey)
    let response = await platform.post(options.url, payload, {
        PublicKeyId: transmissionKey.publicKeyId.toString(),
        TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
        Signature: platform.bytesToBase64(signature)
    })
    if (response.statusCode !== 200) {
        throw new Error(platform.bytesToString(response.data))
    }
    return response
};
