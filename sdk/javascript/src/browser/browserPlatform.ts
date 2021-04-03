import {KeeperHttpResponse, Platform} from "../platform"
import {webSafe64FromBytes} from '../utils';

export const browserPlatform: Platform = class {

    static bytesToBase64(data: Uint8Array): string {
        if (!data)
            return null;
        return btoa(browserPlatform.bytesToString(data));
    }

    static base64ToBytes(data: string): Uint8Array {
        //@ts-ignore
        return Uint8Array.from(atob(data), c => c.charCodeAt(0))
    }

    static bytesToString(data: Uint8Array): string {
        if (!data)
            return null;
        return String.fromCharCode(...data);
    }

    static stringToBytes(data: string): Uint8Array {
        return new TextEncoder().encode(data);
    }

    static getRandomBytes(length: number): Uint8Array {
        let data = new Uint8Array(length);
        crypto.getRandomValues(data);
        return data
    }

    static async generateKeyPair(): Promise<Uint8Array> {
        const ecdh = await crypto.subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveBits'])
        const privateKey = await crypto.subtle.exportKey('pkcs8', ecdh.privateKey)
        return new Uint8Array(privateKey);
    }

    static async aesEncrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        let _key = await crypto.subtle.importKey("raw", key, "AES-GCM", true, ["encrypt"]);
        let iv = browserPlatform.getRandomBytes(12);
        let res = await crypto.subtle.encrypt({
            name: "AES-GCM",
            iv: iv
        }, _key, data);
        return Uint8Array.of(...iv, ...new Uint8Array(res))
    }

    static async publicEncrypt(data: Uint8Array, key: Uint8Array, id?: Uint8Array): Promise<Uint8Array> {
        const ephemeralKeyPair = await crypto.subtle.generateKey({
            name: 'ECDH',
            namedCurve: 'P-256'
        }, true, ['deriveBits'])
        const ephemeralPublicKey = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey)
        const recipientPublicKey = await crypto.subtle.importKey('raw', key, {
            name: 'ECDH',
            namedCurve: 'P-256'
        }, true, [])
        const sharedSecret = await crypto.subtle.deriveBits({
            name: 'ECDH',
            public: recipientPublicKey
        }, ephemeralKeyPair.privateKey, 256)
        const idBytes = id || new Uint8Array()
        const sharedSecretCombined = new Uint8Array(sharedSecret.byteLength + idBytes.byteLength)
        sharedSecretCombined.set(new Uint8Array(sharedSecret), 0)
        sharedSecretCombined.set(idBytes, sharedSecret.byteLength)
        const symmetricKey = await crypto.subtle.digest('SHA-256', sharedSecretCombined)
        const cipherText = await browserPlatform.aesEncrypt(data, new Uint8Array(symmetricKey))
        const result = new Uint8Array(ephemeralPublicKey.byteLength + cipherText.byteLength)
        result.set(new Uint8Array(ephemeralPublicKey), 0)
        result.set(new Uint8Array(cipherText), ephemeralPublicKey.byteLength)
        return result
    }

    static async sign(data: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
        let key = await crypto.subtle.importKey("pkcs8",
            privateKey,
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            false,
            ["sign"]);
        let signature = await crypto.subtle.sign({
            name: 'ECDSA',
            hash: 'SHA-256'
        }, key, data);
        return new Uint8Array(signature);
    }

    static async post(
        url: string,
        request: Uint8Array | string,
        headers?: { [key: string]: string }
    ): Promise<KeeperHttpResponse> {
        let resp = await fetch(url, {
            method: "POST",
            headers: new Headers({
                "Content-Type": "application/octet-stream",
                "Content-Length": String(request.length),
                ...headers
            }),
            body: request,
        });
        let body = await resp.arrayBuffer();
        return {
            statusCode: resp.status,
            headers: resp.headers,
            data: new Uint8Array(body)
        }
    }
}
