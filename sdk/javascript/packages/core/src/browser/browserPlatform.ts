import {KeeperHttpResponse, Platform} from "../platform"

export const browserPlatform: Platform = class {

    static bytesToBase64(data: Uint8Array): string {
        return btoa(browserPlatform.bytesToString(data));
    }

    static base64ToBytes(data: string): Uint8Array {
        return Uint8Array.from(atob(data), c => c.charCodeAt(0))
    }

    static bytesToString(data: Uint8Array): string {
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

    static async encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        let _key = await crypto.subtle.importKey("raw", key, "AES-GCM", true, ["encrypt"]);
        let iv = browserPlatform.getRandomBytes(12);
        let res = await crypto.subtle.encrypt({
            name: "AES-GCM",
            iv: iv
        }, _key, data);
        return Uint8Array.of(...iv, ...new Uint8Array(res))
    }

    static async decrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        let _key = await crypto.subtle.importKey("raw", key, "AES-GCM", true, ["decrypt"]);
        let iv = data.subarray(0, 12);
        let encrypted = data.subarray(12);
        let res = await crypto.subtle.decrypt({
            name: "AES-GCM",
            iv: iv
        }, _key, encrypted);
        return new Uint8Array(res);
    }

    static async hash(data: Uint8Array): Promise<Uint8Array> {
        const hash = await crypto.subtle.digest('SHA-256', data)
        return new Uint8Array(hash)
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
        const cipherText = await browserPlatform.encrypt(data, new Uint8Array(symmetricKey))
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
        return new Uint8Array(p1363ToDER(Buffer.from(signature)))
    }

    static async get(url: string, headers: any): Promise<KeeperHttpResponse> {
        let resp = await fetch(url, {
            method: "GET",
            headers: Object.entries(headers),
        });
        let body = await resp.arrayBuffer();
        return {
            statusCode: resp.status,
            headers: resp.headers,
            data: new Uint8Array(body)
        }
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

// derived from https://github.com/litert/signatures.js
function p1363ToDER(p1363: Buffer): Buffer {
    let base = 0;
    let r: Buffer;
    let s: Buffer;
    const hL = p1363.length / 2;
    /**
     * Prepend a 0x00 byte to R or S if it starts with a byte larger than 0x79.
     *
     * Because a integer starts with a byte larger than 0x79 means negative.
     *
     * @see https://bitcointalk.org/index.php?topic=215205.msg2258789#msg2258789
     */
    r = ecdsaRecoverRS(p1363.slice(0, hL));
    s = ecdsaRecoverRS(p1363.slice(hL));
    /**
     * Using long form length if it's larger than 0x7F.
     *
     * @see https://stackoverflow.com/a/47099047
     */
    if (4 + s.length + r.length > 0x7f) {
        base++;
    }
    const der = Buffer.alloc(base + 6 + s.length + r.length);
    if (base) {
        der[1] = 0x81;
    }
    der[0] = 0x30;
    der[base + 1] = 4 + s.length + r.length;
    der[base + r.length + 4] = der[base + 2] = 0x02;
    der[base + r.length + 5] = s.length;
    der[base + 3] = r.length;
    r.copy(der, base + 4);
    s.copy(der, base + 6 + r.length);
    return der;
}

function ecdsaRecoverRS(input: Buffer): Buffer {
    let start: number = 0;
    while (input[start] === 0) {
        start++;
    }
    if (input[start] <= 0x7F) {
        return input.slice(start);
    }
    if (start > 0) {
        return input.slice(start - 1);
    }
    let output = Buffer.alloc(input.length + 1);
    input.copy(output, 1);
    output[0] = 0;
    return output;
}
