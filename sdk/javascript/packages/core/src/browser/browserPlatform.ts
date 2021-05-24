import {KeeperHttpResponse, KeyValueStorage, Platform} from "../platform"

const bytesToBase64 = (data: Uint8Array): string => btoa(browserPlatform.bytesToString(data));

const base64ToBytes = (data: string): Uint8Array => Uint8Array.from(atob(data), c => c.charCodeAt(0));

const bytesToString = (data: Uint8Array): string => String.fromCharCode(...data);

const stringToBytes = (data: string): Uint8Array => new TextEncoder().encode(data);

const getRandomBytes = (length: number): Uint8Array => {
    let data = new Uint8Array(length)
    crypto.getRandomValues(data)
    return data
};

const generatePrivateKey = async (keyId: string, storage: KeyValueStorage): Promise<void> => {
    const pair = await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign', 'verify'])
    await storage.saveValue(keyId, pair)
};

const loadPrivateKey = async (keyId: string, storage: KeyValueStorage): Promise<CryptoKeyPair> => {
    const keyPair = await storage.getValue<CryptoKeyPair>(keyId)
    if (!keyPair) {
        throw new Error('Unable to load the private key')
    }
    return keyPair
}

const exportPublicKey = async (keyId: string, storage: KeyValueStorage): Promise<Uint8Array> => {
    const keyPair = await loadPrivateKey(keyId, storage)
    const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey)
    return new Uint8Array(publicKey)
};

// derived from https://github.com/litert/signatures.js
const p1363ToDER = (p1363: Buffer): Buffer => {

    const ecdsaRecoverRS = (input: Buffer): Buffer => {
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
    };

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
};

const sign = async (data: Uint8Array, keyId: string, storage: KeyValueStorage): Promise<Uint8Array> => {
    const keyPair = await loadPrivateKey(keyId, storage)
    let signature = await crypto.subtle.sign({
        name: 'ECDSA',
        hash: 'SHA-256'
    }, keyPair.privateKey, data);
    return new Uint8Array(p1363ToDER(Buffer.from(signature)))
};

const encrypt = async (data: Uint8Array, key: Uint8Array): Promise<Uint8Array> => {
    let _key = await crypto.subtle.importKey("raw", key, "AES-GCM", true, ["encrypt"]);
    let iv = browserPlatform.getRandomBytes(12);
    let res = await crypto.subtle.encrypt({
        name: "AES-GCM",
        iv: iv
    }, _key, data);
    return Uint8Array.of(...iv, ...new Uint8Array(res))
};

const decrypt = async (data: Uint8Array, key: Uint8Array): Promise<Uint8Array> => {
    let _key = await crypto.subtle.importKey("raw", key, "AES-GCM", true, ["decrypt"]);
    let iv = data.subarray(0, 12);
    let encrypted = data.subarray(12);
    let res = await crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: iv
    }, _key, encrypted);
    return new Uint8Array(res);
};

const hash = async (data: Uint8Array): Promise<Uint8Array> => {
    const hash = await crypto.subtle.digest('SHA-256', data)
    return new Uint8Array(hash)
};

const publicEncrypt = async (data: Uint8Array, key: Uint8Array, id?: Uint8Array): Promise<Uint8Array> => {
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
};

const get = async (url: string, headers: any): Promise<KeeperHttpResponse> => {
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
};

const post = async (
    url: string,
    request: Uint8Array | string,
    headers?: { [key: string]: string }
): Promise<KeeperHttpResponse> => {
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
};

export const browserPlatform: Platform = {
    bytesToBase64: bytesToBase64,
    base64ToBytes: base64ToBytes,
    bytesToString: bytesToString,
    stringToBytes: stringToBytes,
    getRandomBytes: getRandomBytes,
    generatePrivateKey: generatePrivateKey,
    exportPublicKey: exportPublicKey,
    encrypt: encrypt,
    decrypt: decrypt,
    hash: hash,
    publicEncrypt: publicEncrypt,
    sign: sign,
    get: get,
    post: post
}