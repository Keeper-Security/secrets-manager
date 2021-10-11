import { createHash, createHmac, Hmac } from "crypto"

export type Platform = {
//  string routines
    bytesToBase64(data: Uint8Array): string
    base64ToBytes(data: string): Uint8Array
    bytesToString(data: Uint8Array): string
    stringToBytes(data: string): Uint8Array

//  cryptography
    getRandomBytes(length: number): Uint8Array
    generatePrivateKey(keyId: string, storage: KeyValueStorage): Promise<void>
    exportPublicKey(keyId: string, storage: KeyValueStorage): Promise<Uint8Array>
    sign(data: Uint8Array, keyId: string, storage: KeyValueStorage): Promise<Uint8Array>
    publicEncrypt(data: Uint8Array, key: Uint8Array, id?: Uint8Array): Promise<Uint8Array>
    importKey(keyId: string, key: Uint8Array, storage?: KeyValueStorage): Promise<void>
    unwrap(key: Uint8Array, keyId: string, unwrappingKeyId: string, storage?: KeyValueStorage, memoryOnly?: boolean): Promise<void>
    encrypt(data: Uint8Array, keyId: string, storage?: KeyValueStorage): Promise<Uint8Array>
    encryptWithKey(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>
    decrypt(data: Uint8Array, keyId: string, storage?: KeyValueStorage): Promise<Uint8Array>
    decryptWithKey(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>
    hash(data: Uint8Array, tag: string): Promise<Uint8Array>
    cleanKeyCache(): void

//  network
    get(url: string, headers: any): Promise<KeeperHttpResponse>
    post(url: string, request: Uint8Array, headers?: { [key: string]: string }, allowUnverifiedCertificate?: boolean): Promise<KeeperHttpResponse>
}

export type KeyValueStorage = {
    getString(key: string): Promise<string | undefined>
    saveString<T>(key: string, value: string): Promise<void>
    getBytes(key: string): Promise<Uint8Array | undefined>
    saveBytes<T>(key: string, value: Uint8Array): Promise<void>
    delete(key): Promise<void>
    getObject?<T>(key: string): Promise<T | undefined>
    saveObject?<T>(key: string, value: T): Promise<void>
}

export type TransmissionKey = {
    publicKeyId: number
    key: Uint8Array
    encryptedKey: Uint8Array
}

export type EncryptedPayload = {
    payload: Uint8Array
    signature: Uint8Array
}

export type KeeperHttpResponse = {
    statusCode: number
    headers: any
    data: Uint8Array
}

export function connectPlatform(p: Platform) {
    platform = p
}

export let platform: Platform

export const loadJsonConfig = (config: string) : KeyValueStorage  => {
    let jsonStr: string = config
    try
    {
        const str: string = platform.bytesToString(platform.base64ToBytes(config))
        if (str.trimStart().startsWith('{') && str.trimEnd().endsWith('}'))
            jsonStr = str
    }
    catch (e) {
        jsonStr = config
     }

    return inMemoryStorage(JSON.parse(jsonStr))
}

export const inMemoryStorage = (storage: any): KeyValueStorage => {

    const getValue = (key: string): any | undefined => {
        const keyParts = key.split('/')
        let obj = storage
        for (const part of keyParts) {
            obj = obj[part]
            if (!obj) {
                return undefined
            }
        }
        return obj.toString();
    }

    const saveValue = (key: string, value: any): void => {
        const keyParts = key.split('/')
        let obj = storage
        for (const part of keyParts.slice(0, -1)) {
            if (!obj[part]) {
                obj[part] = {}
            }
            obj = obj[part]
        }
        obj[keyParts.slice(-1)[0]] = value
    }

    const clearValue = (key: string): void => {
        const keyParts = key.split('/')
        let obj = storage
        for (const part of keyParts.slice(0, -1)) {
            if (!obj[part]) {
                obj[part] = {}
            }
            obj = obj[part]
        }
        delete obj[keyParts.slice(-1)[0]]
    }

    return {
        getString: key => Promise.resolve(getValue(key)),
        saveString: (key, value) => {
            saveValue(key, value)
            return Promise.resolve()
        },
        getBytes: key => {
            const bytesString: string = getValue(key)
            if (bytesString) {
                return Promise.resolve(platform.base64ToBytes(bytesString))
            } else {
                return Promise.resolve(undefined)
            }
        },
        saveBytes: (key, value) => {
            const bytesString = platform.bytesToBase64(value)
            saveValue(key, bytesString)
            return Promise.resolve()
        },
        delete: (key) => {
            clearValue(key)
            return Promise.resolve()
        }
    }
}

const b32encode = function(base32Text: string) {
    /* encodes a string s to base32 and returns the encoded string */
    const alphabet: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    // private static readonly Regex rxBase32Alphabet = new Regex($"", RegexOptions.Compiled);

    // The padding specified in RFC 3548 section 2.2 is not required and should be omitted.
    const base32: string = (base32Text || '').replace(/=+$/g, '').toUpperCase();
    if (!base32 || !/^[A-Z2-7]+$/.test(base32))
        return null;

    const bytes = Array.from(base32)
    let output = new Array()

    for (let bitIndex = 0; bitIndex < base32.length * 5; bitIndex += 8) {
        const idx = Math.floor(bitIndex / 5);
        let dualByte = alphabet.indexOf(bytes[idx]) << 10;
        if (idx + 1 < bytes.length)
            dualByte |= alphabet.indexOf(bytes[idx + 1]) << 5;
        if (idx + 2 < bytes.length)
            dualByte |= alphabet.indexOf(bytes[idx + 2]);
        dualByte = 0xff & (dualByte >> (15 - bitIndex % 5 - 8));
        output.push(dualByte);
    }

    return new Uint8Array(output);
}

export const getTotpCode = (url: string, unixTimeSeconds: number = 0) : [string, number, number] | null  => {
    let totpUrl: URL;
    try {
        totpUrl = new URL(url);
    } catch (e) {
        return null;
    }

    if (totpUrl.protocol != 'otpauth:')
        return null;

    const secret: string = (totpUrl.searchParams.get('secret') || '').trim();
    if (!secret)
        return null;

    let algorithm: string = (totpUrl.searchParams.get('algorithm') || '').trim();
    if (!algorithm)
        algorithm = 'SHA1'; // default algorithm

    const strDigits: string = (totpUrl.searchParams.get('digits') || '').trim();
    let digits: number = (isNaN(+strDigits) ? 6 : parseInt(strDigits));
    digits = digits == 0 ? 6 : digits;

    const strPeriod: string = (totpUrl.searchParams.get('period') || '').trim();
    let period: number = (isNaN(+strPeriod) ? 30 : parseInt(strPeriod));
    period = period == 0 ? 30 : period;

    const tmBase: number = unixTimeSeconds != 0 ? unixTimeSeconds : Math.floor(Date.now() / 1000);
    const tm: bigint = BigInt(Math.floor(tmBase / period));

    const buffer = new ArrayBuffer(8)
    new DataView(buffer).setBigInt64(0, tm);
    const msg = new Uint8Array(buffer)

    const secretBytes = b32encode(secret.toUpperCase());
    if (secretBytes == null || secretBytes.length < 1)
        return null;

    let hmac: Hmac | null = null;
    switch (algorithm)
    {
        // although once part of Google Key Uri Format - https://github.com/google/google-authenticator/wiki/Key-Uri-Format/_history
        // removed MD5 as unreliable - only digests of length >= 20 can be used (MD5 has a digest length of 16)
        //case 'MD5': hmac = createHmac('MD5', secretBytes); break;
        case 'SHA1': hmac = createHmac('SHA1', secretBytes); break;
        case 'SHA256': hmac = createHmac('SHA256', secretBytes); break;
        case 'SHA512': hmac = createHmac('SHA512', secretBytes); break;
    }

    if (hmac == null)
        return null;

    const digest = hmac.update(msg).digest();
    const offset = digest[digest.length - 1] & 0x0f;
    const codeBytes = new Uint8Array(digest.slice(offset, offset+4));
    codeBytes[0] &= 0x7f;
    let codeInt = new DataView(codeBytes.buffer).getInt32(0);
    codeInt %= Math.floor(Math.pow(10, digits));
    codeInt = Math.floor(codeInt);
    let codeStr = codeInt.toString(10);
    while (codeStr.length < digits)
        codeStr = "0" + codeStr;

    return [codeStr, Math.floor(tmBase % period), period];
}
