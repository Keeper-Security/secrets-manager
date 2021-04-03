import {platform} from './platform'

export function webSafe64(source: string): string {
    return source.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function webSafe64ToRegular(source: string): string {
    return source.replace(/-/g, '+').replace(/_/g, '/') + '=='.substring(0, (3 * source.length) % 4)
}

export function webSafe64ToBytes(source: string): Uint8Array {
    return platform.base64ToBytes(webSafe64ToRegular(source))
}

export function webSafe64FromBytes(source: Uint8Array): string {
    return webSafe64(platform.bytesToBase64(source))
}

// converts private key for prime256v1 curve in der/pkcs8 to raw private/public keys
export function privateKeyToRaw(key: Uint8Array): { privateKey: Uint8Array; publicKey: Uint8Array } {
    return {
        privateKey: key.slice(36, 68),
        publicKey: key.slice(73)
    }
}
