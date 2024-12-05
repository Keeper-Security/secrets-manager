import {KeeperHttpResponse, KeyValueStorage, Platform} from '../platform'
import {privateDerToPublicRaw} from '../utils'

const bytesToBase64 = (data: Uint8Array): string => {
    const chunkSize = 0x10000 // max size accepted by String.fromCharCode
    if (data.length <= chunkSize) {
        // @ts-ignore
        return btoa(String.fromCharCode(...data))
    }
    let chunks: string = ''
    for (let i = 0; i < data.length; i = i + chunkSize) {
        // @ts-ignore
        chunks = chunks + String.fromCharCode(...data.slice(i, i + chunkSize))
    }
    return btoa(chunks)
}

const base64ToBytes = (data: string): Uint8Array => Uint8Array.from(atob(data), c => c.charCodeAt(0))

const bytesToString = (data: Uint8Array): string => new TextDecoder().decode(data)

const stringToBytes = (data: string): Uint8Array => new TextEncoder().encode(data)

const getRandomBytes = (length: number): Uint8Array => {
    const data = new Uint8Array(length)
    crypto.getRandomValues(data)
    return data
}

const keyCache: Record<string, CryptoKey> = {}

const loadPrivateKey = async (keyId: string, storage: KeyValueStorage): Promise<CryptoKey> => {
    const cachedPrivateKey = keyCache[keyId]
    if (cachedPrivateKey) {
        return cachedPrivateKey
    }
    let privateKey
    if (storage.getObject) {
        const keyPair = await storage.getObject<CryptoKeyPair>(keyId)
        if (keyPair) {
            privateKey = keyPair.privateKey
        }
    } else {
        const privateKeyDer = await storage.getBytes(keyId)
        if (privateKeyDer) {
            privateKey = await crypto.subtle.importKey('pkcs8',
                privateKeyDer,
                {
                    name: 'ECDSA',
                    namedCurve: 'P-256'
                },
                false,
                ['sign'])
        }
    }
    if (!privateKey) {
        throw new Error(`Unable to load the private key ${keyId}`)
    }
    keyCache[keyId] = privateKey
    return privateKey
}


const loadKey = async (keyId: string, storage?: KeyValueStorage): Promise<CryptoKey> => {
    const cachedKey = keyCache[keyId]
    if (cachedKey) {
        return cachedKey
    }
    let key
    if (storage) {
        if (storage.getObject) {
            key = await storage.getObject<CryptoKey>(keyId)
        } else {
            const keyBytes = await storage.getBytes(keyId)
            if (keyBytes) {
                key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt', 'unwrapKey'])
            }
        }
    }
    if (!key) {
        throw new Error(`Unable to load the key ${keyId}`)
    }
    keyCache[keyId] = key
    return key
}

const generatePrivateKey = async (keyId: string, storage: KeyValueStorage): Promise<void> => {
    const keyPair = await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, !storage.saveObject, ['sign', 'verify'])
    keyCache[keyId] = keyPair.privateKey!
    if (storage.saveObject) {
        await storage.saveObject(keyId, keyPair)
    } else {
        // @ts-ignore
        const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
        await storage.saveBytes(keyId, new Uint8Array(privateKey))
    }
}

const exportPublicKey = async (keyId: string, storage: KeyValueStorage): Promise<Uint8Array> => {
    if (storage.getObject) {
        const keyPair = await storage.getObject<CryptoKeyPair>(keyId)
        if (keyPair) {
            // @ts-ignore
            const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey)!
            return new Uint8Array(publicKey)
        }
    } else {
        const privateKeyDer = await storage.getBytes(keyId)
        if (privateKeyDer) {
            return privateDerToPublicRaw(privateKeyDer)
        }
    }
    throw new Error(`Unable to load the key ${keyId}`)
}

// derived from https://github.com/litert/signatures.js
const p1363ToDER = (p1363: Buffer): Buffer => {

    const ecdsaRecoverRS = (input: Buffer): Buffer => {
        let start: number = 0
        while (input[start] === 0) {
            start++
        }
        if (input[start] <= 0x7F) {
            return input.slice(start)
        }
        if (start > 0) {
            return input.slice(start - 1)
        }
        const output = Buffer.alloc(input.length + 1)
        input.copy(output, 1)
        output[0] = 0
        return output
    }

    let base = 0
    let r: Buffer
    let s: Buffer
    const hL = p1363.length / 2
    /**
     * Prepend a 0x00 byte to R or S if it starts with a byte larger than 0x79.
     *
     * Because a integer starts with a byte larger than 0x79 means negative.
     *
     * @see https://bitcointalk.org/index.php?topic=215205.msg2258789#msg2258789
     */
    r = ecdsaRecoverRS(p1363.slice(0, hL))
    s = ecdsaRecoverRS(p1363.slice(hL))
    /**
     * Using long form length if it's larger than 0x7F.
     *
     * @see https://stackoverflow.com/a/47099047
     */
    if (4 + s.length + r.length > 0x7f) {
        base++
    }
    const der = Buffer.alloc(base + 6 + s.length + r.length)
    if (base) {
        der[1] = 0x81
    }
    der[0] = 0x30
    der[base + 1] = 4 + s.length + r.length
    der[base + r.length + 4] = der[base + 2] = 0x02
    der[base + r.length + 5] = s.length
    der[base + 3] = r.length
    r.copy(der, base + 4)
    s.copy(der, base + 6 + r.length)
    return der
}

const sign = async (data: Uint8Array, keyId: string, storage: KeyValueStorage): Promise<Uint8Array> => {
    const privateKey = await loadPrivateKey(keyId, storage)
    const signature = await crypto.subtle.sign({
        name: 'ECDSA',
        hash: 'SHA-256'
    }, privateKey, data)
    return new Uint8Array(p1363ToDER(Buffer.from(signature)))
}

const importKey = async (keyId: string, key: Uint8Array, storage?: KeyValueStorage): Promise<void> => {
    const _key = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt', 'unwrapKey'])
    keyCache[keyId] = _key
    if (storage) {
        if (storage.saveObject) {
            await storage.saveObject(keyId, _key)
        } else {
            await storage.saveBytes(keyId, key)
        }
    }
}

const encrypt = async (data: Uint8Array, keyId: string, storage?: KeyValueStorage, useCBC?: boolean): Promise<Uint8Array> => {
    const key = await loadKey(keyId, storage)
    return __encrypt(data, key, useCBC)
}

const _encrypt = async (data: Uint8Array, key: Uint8Array, useCBC?: boolean): Promise<Uint8Array> => {
    const _key = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt'])
    return __encrypt(data, _key, useCBC)
}

const __encrypt = async (data: Uint8Array, key: CryptoKey, useCBC?: boolean): Promise<Uint8Array> => {
    const ivLen = useCBC ? 16 : 12
    const algorithmName = useCBC ? 'AES-CBC' : 'AES-GCM'
    const iv = getRandomBytes(ivLen)
    const res = await crypto.subtle.encrypt({
        name: algorithmName,
        iv: iv
    }, key, data)
    return Uint8Array.of(...iv, ...new Uint8Array(res))
}

const unwrap = async (key: Uint8Array, keyId: string, unwrappingKeyId: string, storage?: KeyValueStorage, memoryOnly?: boolean, useCBC?: boolean): Promise<void> => {
    const unwrappingKey = await loadKey(unwrappingKeyId, storage)
    if (!unwrappingKey.usages.includes('unwrapKey')) {
        throw new Error(`Key ${unwrappingKeyId} is not suitable for unwrapping`)
    }
    const ivLen = useCBC ? 16 : 12
    const algorithmName = useCBC ? 'AES-CBC' : 'AES-GCM'
    const unwrappedKey = await crypto.subtle.unwrapKey('raw', key.subarray(ivLen), unwrappingKey,
        {
            iv: key.subarray(0, ivLen),
            name: algorithmName
        },
        algorithmName, storage ? !storage.saveObject : false, ['encrypt', 'decrypt', 'unwrapKey'])
    keyCache[keyId] = unwrappedKey
    if (memoryOnly) {
        return
    }
    if (storage) {
        if (storage.saveObject) {
            await storage.saveObject(keyId, unwrappedKey)
        } else {
            const keyArray = await crypto.subtle.exportKey('raw', unwrappedKey)
            const keyBytes = new Uint8Array(keyArray)
            await storage.saveBytes(keyId, keyBytes)
        }
    }
}

const decrypt = async (data: Uint8Array, keyId: string, storage?: KeyValueStorage, useCBC?: boolean): Promise<Uint8Array> => {
    const key = await loadKey(keyId, storage)
    return __decrypt(data, key, useCBC)
}

const _decrypt = async (data: Uint8Array, key: Uint8Array, useCBC?: boolean): Promise<Uint8Array> => {
    const _key = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt'])
    return __decrypt(data, _key, useCBC)
}

const __decrypt = async (data: Uint8Array, key: CryptoKey, useCBC?: boolean): Promise<Uint8Array> => {
    const ivLen = useCBC ? 16 : 12
    const algorithmName = useCBC ? 'AES-CBC' : 'AES-GCM'
    const iv = data.subarray(0, ivLen)
    const encrypted = data.subarray(ivLen)
    const res = await crypto.subtle.decrypt({
        name: algorithmName,
        iv: iv
    }, key, encrypted)
    return new Uint8Array(res)
}

const hash = async (data: Uint8Array, tag: string): Promise<Uint8Array> => {
    const key = await crypto.subtle.importKey('raw', data, {
        name: 'HMAC',
        hash: {
            name: 'SHA-512'
        }
    }, false, ['sign'])
    const signature = await crypto.subtle.sign('HMAC', key, stringToBytes(tag))
    return new Uint8Array(signature)
}

const publicEncrypt = async (data: Uint8Array, key: Uint8Array, id?: Uint8Array): Promise<Uint8Array> => {
    const ephemeralKeyPair = await crypto.subtle.generateKey({
        name: 'ECDH',
        namedCurve: 'P-256'
    }, false, ['deriveBits'])
    // @ts-ignore
    const ephemeralPublicKey = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey)
    const recipientPublicKey = await crypto.subtle.importKey('raw', key, {
        name: 'ECDH',
        namedCurve: 'P-256'
    }, true, [])
    const sharedSecret = await crypto.subtle.deriveBits({
        name: 'ECDH',
        public: recipientPublicKey
    }, ephemeralKeyPair.privateKey!, 256)
    const idBytes = id || new Uint8Array()
    const sharedSecretCombined = new Uint8Array(sharedSecret.byteLength + idBytes.byteLength)
    sharedSecretCombined.set(new Uint8Array(sharedSecret), 0)
    sharedSecretCombined.set(idBytes, sharedSecret.byteLength)
    const symmetricKey = await crypto.subtle.digest('SHA-256', sharedSecretCombined)
    const cipherText = await _encrypt(data, new Uint8Array(symmetricKey))
    const result = new Uint8Array(ephemeralPublicKey.byteLength + cipherText.byteLength)
    result.set(new Uint8Array(ephemeralPublicKey), 0)
    result.set(new Uint8Array(cipherText), ephemeralPublicKey.byteLength)
    return result
}

const get = async (url: string, headers: any): Promise<KeeperHttpResponse> => {
    const resp = await fetch(url, {
        method: 'GET',
        headers: Object.entries(headers),
    })
    const body = await resp.arrayBuffer()
    return {
        statusCode: resp.status,
        headers: resp.headers,
        data: new Uint8Array(body)
    }
}

const post = async (
    url: string,
    request: Uint8Array | string,
    headers?: { [key: string]: string }
): Promise<KeeperHttpResponse> => {
    const resp = await fetch(url, {
        method: 'POST',
        headers: new Headers({
            'Content-Type': 'application/octet-stream',
            'Content-Length': String(request.length),
            ...headers
        }),
        body: request,
    })
    const body = await resp.arrayBuffer()
    return {
        statusCode: resp.status,
        headers: resp.headers,
        data: new Uint8Array(body)
    }
}

const fileUpload = (
    url: string,
    uploadParameters: { [key: string]: string },
    data: Blob
): Promise<any> => new Promise<any>((resolve, reject) => {
    const form = new FormData();

    for (const key in uploadParameters) {
        form.append(key, uploadParameters[key]);
    }
    form.append('file', data)

    const fetchCfg = {
        method: 'PUT',
        body: form,
    }

    fetch(url, fetchCfg)
        .then(response => response.json())
        .then(res => {
            resolve({
                headers: res.headers,
                statusCode: res.statusCode,
                statusMessage: res.statusMessage
            })
        })
        .catch(error => {
            console.error('Error uploading file:', error);
            reject(error)
        });
})

const cleanKeyCache = () => {
    for (const key in keyCache) {
        delete keyCache[key]
    }
}

const hasKeysCached = (): boolean => {
    return Object.keys(keyCache).length > 0
}

const getHmacDigest = async (algorithm: string, secret: Uint8Array, message: Uint8Array): Promise<Uint8Array> => {
    // although once part of Google Key Uri Format - https://github.com/google/google-authenticator/wiki/Key-Uri-Format/_history
    // removed MD5 as unreliable - only digests of length >= 20 can be used (MD5 has a digest length of 16)
    let algo = algorithm.toUpperCase().trim();
    if (['SHA1', 'SHA256', 'SHA512'].includes(algo)) {
        algo = 'SHA-' + algo.substr(3);
        const key = await crypto.subtle.importKey('raw', secret, {
            name: 'HMAC',
            hash: { name: algo  }
        }, false, ['sign'])
        const signature = await crypto.subtle.sign('HMAC', key, message)
        return new Uint8Array(signature)
    }
    return new Uint8Array();
}

// Returns a sufficiently random number in the range [0, max) i.e. 0 <= number < max
const getRandomNumber = async (n: number): Promise<number> => {
    const uint32Max = Math.pow(2, 32) - 1
    const limit = uint32Max - uint32Max % n
    let values = new Uint32Array(1)
    do {
        const randomBytes = getRandomBytes(4)
        values = new Uint32Array(randomBytes.buffer)
    } while (values[0] > limit)
    return Promise.resolve(values[0] % n)
}

// Given a character set, this function will return one sufficiently random character from the charset.
const getRandomCharacterInCharset = async (charset: string): Promise<string> => {
    const count = charset.length
    const pos = await getRandomNumber(count)
    return Promise.resolve(charset[pos])
}

export const browserPlatform: Platform = {
    bytesToBase64: bytesToBase64,
    base64ToBytes: base64ToBytes,
    bytesToString: bytesToString,
    stringToBytes: stringToBytes,
    getRandomBytes: getRandomBytes,
    generatePrivateKey: generatePrivateKey,
    exportPublicKey: exportPublicKey,
    importKey: importKey,
    unwrap: unwrap,
    encrypt: encrypt,
    encryptWithKey: _encrypt,
    decrypt: decrypt,
    decryptWithKey: _decrypt,
    hash: hash,
    publicEncrypt: publicEncrypt,
    sign: sign,
    get: get,
    post: post,
    fileUpload: fileUpload,
    cleanKeyCache: cleanKeyCache,
    hasKeysCached: hasKeysCached,
    getHmacDigest: getHmacDigest,
    getRandomNumber: getRandomNumber,
    getRandomCharacterInCharset: getRandomCharacterInCharset
}
