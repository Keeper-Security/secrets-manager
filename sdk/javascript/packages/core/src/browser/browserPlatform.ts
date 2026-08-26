import {deadlineSignal, DEFAULT_REQUEST_TIMEOUT_MS, KeeperHttpResponse, KeyValueStorage, Platform} from '../platform'
import {privateDerToPublicRaw} from '../utils'
import {KeeperError, KeeperCryptoError} from '../errors'

const bytesToBase64 = (data: Uint8Array): string => {
    const chunkSize = 0x8000 // String.fromCharCode has limitations
    if (data.length <= chunkSize) {
        return btoa(String.fromCharCode(...data))
    }
    const chunks: string[] = []
    for (let i = 0; i < data.length; i += chunkSize) {
        chunks.push(String.fromCharCode(...data.subarray(i, i + chunkSize)))
    }
    return btoa(chunks.join(''))
}

const base64ToBytes = (data: string): Uint8Array => {
    if (data == null) throw new KeeperError(`base64ToBytes: received ${data === null ? 'null' : 'undefined'}`)
    return Uint8Array.from(atob(data), c => c.charCodeAt(0))
}

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
                privateKeyDer as Uint8Array<ArrayBuffer>,
                {
                    name: 'ECDSA',
                    namedCurve: 'P-256'
                },
                false,
                ['sign'])
        }
    }
    if (!privateKey) {
        throw new KeeperCryptoError(`Unable to load the private key ${keyId}`, 'missing-key', keyId)
    }
    keyCache[keyId] = privateKey
    return privateKey
}


const loadKey = async (keyId: string, storage?: KeyValueStorage, useCBC?: boolean): Promise<CryptoKey> => {
    const cacheKey = useCBC ? `cbc:${keyId}` : keyId
    const cachedKey = keyCache[cacheKey]
    if (cachedKey) {
        return cachedKey
    }
    let key
    if (storage) {
        if (storage.getObject) {
            key = await storage.getObject<CryptoKey>(cacheKey)
        } else {
            const keyBytes = await storage.getBytes(cacheKey)
            if (keyBytes) {
                const algorithmName = useCBC ? 'AES-CBC' : 'AES-GCM'
                key = await crypto.subtle.importKey('raw', keyBytes as Uint8Array<ArrayBuffer>, algorithmName, false, ['encrypt', 'decrypt', 'unwrapKey'])
            }
        }
    }
    if (!key) {
        // Report the caller-facing keyId, not cacheKey: the `cbc:` cache-slot prefix is an
        // internal detail of this platform's dual GCM/CBC key cache (see unwrap below), not
        // something a caller of SecretManagerOptions.onDecryptionError should have to know about.
        throw new KeeperCryptoError(`Unable to load the key ${keyId}`, 'missing-key', keyId)
    }
    keyCache[cacheKey] = key
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
    throw new Error(`Unable to load the public key ${keyId}`)
}

// derived from https://github.com/litert/signatures.js
const p1363ToDER = (p1363: Uint8Array): Uint8Array => {

    const ecdsaRecoverRS = (input: Uint8Array): Uint8Array => {
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
        const output = new Uint8Array(input.length + 1)
        output[0] = 0
        output.set(input, 1)
        return output
    }

    let base = 0
    let r: Uint8Array
    let s: Uint8Array
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
    const der = new Uint8Array(base + 6 + s.length + r.length)
    if (base) {
        der[1] = 0x81
    }
    der[0] = 0x30
    der[base + 1] = 4 + s.length + r.length
    der[base + r.length + 4] = der[base + 2] = 0x02
    der[base + r.length + 5] = s.length
    der[base + 3] = r.length

    der.set(r, base + 4)
    der.set(s, base + 6 + r.length)
    return der
}

const sign = async (data: Uint8Array, keyId: string, storage: KeyValueStorage): Promise<Uint8Array> => {
    const privateKey = await loadPrivateKey(keyId, storage)
    const signature = await crypto.subtle.sign({
        name: 'ECDSA',
        hash: 'SHA-256'
    }, privateKey, data as Uint8Array<ArrayBuffer>)
    return new Uint8Array(p1363ToDER(new Uint8Array(signature)))
}

const importKey = async (keyId: string, key: Uint8Array, storage?: KeyValueStorage, useCBC?: boolean): Promise<void> => {
    const algorithmName = useCBC ? 'AES-CBC' : 'AES-GCM'
    const cacheKey = useCBC ? `cbc:${keyId}` : keyId
    const _key = await crypto.subtle.importKey('raw', key as Uint8Array<ArrayBuffer>, algorithmName, false, ['encrypt', 'decrypt', 'unwrapKey'])
    keyCache[cacheKey] = _key

    if (storage) {
        if (storage.saveObject) {
            await storage.saveObject(cacheKey, _key)
        } else {
            await storage.saveBytes(cacheKey, key)
        }
    }
}

const encrypt = async (data: Uint8Array, keyId: string, storage?: KeyValueStorage, useCBC?: boolean): Promise<Uint8Array> => {
    const key = await loadKey(keyId, storage, useCBC)
    return __encrypt(data, key, useCBC)
}

const _encrypt = async (data: Uint8Array, key: Uint8Array, useCBC?: boolean): Promise<Uint8Array> => {
    const algorithmName = useCBC ? 'AES-CBC' : 'AES-GCM'
    const _key = await crypto.subtle.importKey('raw', key as Uint8Array<ArrayBuffer>, algorithmName, false, ['encrypt'])
    return __encrypt(data, _key, useCBC)
}

// useCBC selects AES-256-CBC, which carries no MAC: this mode exists only because the vault's
// wire format for shared-folder key wraps and folder data is fixed to CBC server-side (KSM-1267)
// - it is not a template for new code; prefer the AES-256-GCM (default) path.
const __encrypt = async (data: Uint8Array, key: CryptoKey, useCBC?: boolean): Promise<Uint8Array> => {
    const ivLen = useCBC ? 16 : 12
    const algorithmName = useCBC ? 'AES-CBC' : 'AES-GCM'
    const iv = getRandomBytes(ivLen)
    const res = await crypto.subtle.encrypt({
        name: algorithmName,
        iv: iv as Uint8Array<ArrayBuffer>
    }, key, data as Uint8Array<ArrayBuffer>)
    const encrypted = new Uint8Array(iv.length + res.byteLength)
    encrypted.set(iv, 0)
    encrypted.set(new Uint8Array(res), iv.length)
    return encrypted
}

const UNWRAPPED_KEY_LENGTH_BITS = 256 // every key this SDK unwraps is AES-256

// WebCrypto's unwrapKey only validates that the recovered raw bytes are a valid AES key size
// (128/192/256 bits, i.e. 16/24/32 bytes) - it does not know or enforce that this SDK's keys must
// specifically be AES-256, so a corrupted-but-plausible 16- or 24-byte result would otherwise be
// cached and used without error (see nodePlatform.ts's UNWRAPPED_KEY_LENGTH check, which performs
// the equivalent guard on Node's raw key bytes). CryptoKey has no raw bytes to check directly
// (unless exported, which requires extractable), but AesKeyAlgorithm.length reports the key size
// in bits without needing to export, so that is checked here instead.
const assertUnwrappedKeyLength = (unwrappedKey: CryptoKey, keyId: string): void => {
    const lengthBits = (unwrappedKey.algorithm as AesKeyAlgorithm).length
    if (lengthBits !== UNWRAPPED_KEY_LENGTH_BITS) {
        throw new Error(`Unwrapped key ${keyId} has invalid length ${lengthBits / 8}, expected ${UNWRAPPED_KEY_LENGTH_BITS / 8}`)
    }
}

const unwrap = async (key: Uint8Array, keyId: string, unwrappingKeyId: string, storage?: KeyValueStorage, memoryOnly?: boolean, useCBC?: boolean): Promise<void> => {
    const loadKeyCBC = unwrappingKeyId === "appKey" ? false : useCBC
    const unwrappingKey = await loadKey(unwrappingKeyId, storage, loadKeyCBC)
    if (!unwrappingKey.usages.includes('unwrapKey')) {
        throw new Error(`Key ${unwrappingKeyId} is not suitable for unwrapping`)
    }

    const keyIdCBC = `cbc:${keyId}`
    const ivLen = unwrappingKey.algorithm.name === 'AES-CBC' ? 16 : 12
    const unwrappingAlgo = {
        name: unwrappingKey.algorithm.name,
        iv: key.subarray(0, ivLen) as Uint8Array<ArrayBuffer>
    }

    const unwrappedKeyGCM = await crypto.subtle.unwrapKey('raw',
        key.subarray(ivLen) as Uint8Array<ArrayBuffer>, unwrappingKey, unwrappingAlgo,
        'AES-GCM', storage ? !storage.saveObject : false, ['encrypt', 'decrypt', 'unwrapKey'])
    assertUnwrappedKeyLength(unwrappedKeyGCM, keyId)
    keyCache[keyId] = unwrappedKeyGCM

    if (useCBC) {
        // A WebCrypto CryptoKey is bound to one algorithm, unlike Node's raw key bytes which work
        // with either cipher - so the same unwrapped folder key must be imported a second time
        // under the AES-CBC algorithm (cached separately as 'cbc:'+keyId) to also decrypt folder.data,
        // which the vault always wraps in CBC regardless of which mode wrapped the folder key itself.
        const unwrappedKeyCBC = await crypto.subtle.unwrapKey('raw',
            key.subarray(ivLen) as Uint8Array<ArrayBuffer>, unwrappingKey, unwrappingAlgo,
            'AES-CBC', storage ? !storage.saveObject : false, ['encrypt', 'decrypt', 'unwrapKey'])
        assertUnwrappedKeyLength(unwrappedKeyCBC, keyId)
        keyCache[keyIdCBC] = unwrappedKeyCBC
    }

    if (memoryOnly) {
        return
    }

    if (storage) {
        if (storage.saveObject) {
            await storage.saveObject(keyId, keyCache[keyId])
            if (useCBC) await storage.saveObject(keyIdCBC, keyCache[keyIdCBC])
        } else {
            const keyArray = await crypto.subtle.exportKey('raw', keyCache[keyId])
            await storage.saveBytes(keyId, new Uint8Array(keyArray))
            if (useCBC) {
                const keyArray = await crypto.subtle.exportKey('raw', keyCache[keyIdCBC])
                await storage.saveBytes(keyIdCBC, new Uint8Array(keyArray))
            }
        }
    }
}

const decrypt = async (data: Uint8Array, keyId: string, storage?: KeyValueStorage, useCBC?: boolean): Promise<Uint8Array> => {
    const key = await loadKey(keyId, storage, useCBC)
    return __decrypt(data, key, useCBC)
}

const _decrypt = async (data: Uint8Array, key: Uint8Array, useCBC?: boolean): Promise<Uint8Array> => {
    const algorithmName = useCBC ? 'AES-CBC' : 'AES-GCM'
    const _key = await crypto.subtle.importKey('raw', key as Uint8Array<ArrayBuffer>, algorithmName, false, ['decrypt'])
    return __decrypt(data, _key, useCBC)
}

// See __encrypt above: no MAC, fixed server-side format, not a template for new code. A failure
// here means malformed input, not a verified integrity failure - and a decrypt success proves
// nothing about integrity either, since CBC has no MAC to fail (see KeeperCryptoError in errors.ts).
const __decrypt = async (data: Uint8Array, key: CryptoKey, useCBC?: boolean): Promise<Uint8Array> => {
    const ivLen = useCBC ? 16 : 12
    const algorithmName = useCBC ? 'AES-CBC' : 'AES-GCM'
    const iv = data.subarray(0, ivLen)
    const encrypted = data.subarray(ivLen)
    const res = await crypto.subtle.decrypt({
        name: algorithmName,
        iv: iv as Uint8Array<ArrayBuffer>
    }, key, encrypted as Uint8Array<ArrayBuffer>)
    return new Uint8Array(res)
}

const hash = async (data: Uint8Array, tag: string): Promise<Uint8Array> => {
    const key = await crypto.subtle.importKey('raw', data as Uint8Array<ArrayBuffer>, {
        name: 'HMAC',
        hash: {
            name: 'SHA-512'
        }
    }, false, ['sign'])
    const signature = await crypto.subtle.sign('HMAC', key, stringToBytes(tag) as Uint8Array<ArrayBuffer>)
    return new Uint8Array(signature)
}

const publicEncrypt = async (data: Uint8Array, key: Uint8Array, id?: Uint8Array): Promise<Uint8Array> => {
    const ephemeralKeyPair = await crypto.subtle.generateKey({
        name: 'ECDH',
        namedCurve: 'P-256'
    }, false, ['deriveBits'])
    // @ts-ignore
    const ephemeralPublicKey = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey)
    const recipientPublicKey = await crypto.subtle.importKey('raw', key as Uint8Array<ArrayBuffer>, {
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

const get = async (url: string, headers: any, timeoutMs?: number): Promise<KeeperHttpResponse> => {
    const {signal, clear} = deadlineSignal(timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS)
    try {
        const resp = await fetch(url, {
            method: 'GET',
            headers: Object.entries(headers),
            signal
        })
        const body = await resp.arrayBuffer()
        return {
            statusCode: resp.status,
            headers: resp.headers,
            data: new Uint8Array(body)
        }
    } finally {
        clear()
    }
}

const post = async (
    url: string,
    request: Uint8Array | string,
    headers?: { [key: string]: string },
    allowUnverifiedCertificate?: boolean,
    timeoutMs?: number
): Promise<KeeperHttpResponse> => {
    const {signal, clear} = deadlineSignal(timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS)
    try {
        const resp = await fetch(url, {
            method: 'POST',
            headers: new Headers({
                'Content-Type': 'application/octet-stream',
                'Content-Length': String(request.length),
                ...headers
            }),
            body: typeof request === 'string' ? request : request as Uint8Array<ArrayBuffer>,
            signal
        })
        const body = await resp.arrayBuffer()
        return {
            statusCode: resp.status,
            headers: resp.headers,
            data: new Uint8Array(body)
        }
    } finally {
        clear()
    }
}

const fileUpload = async (
    url: string,
    uploadParameters: { [key: string]: string },
    data: Uint8Array,
    timeoutMs?: number
): Promise<any> => {
    const form = new FormData();

    for (const key in uploadParameters) {
        form.append(key, uploadParameters[key]);
    }
    form.append('file', new Blob([data as Uint8Array<ArrayBuffer>], {type: 'application/octet-stream'}));

    const {signal, clear} = deadlineSignal(timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS)
    const fetchCfg = {
        method: 'POST',
        body: form,
        signal
    };

    try {
        const res = await fetch(url, fetchCfg);
        return {
            headers: res.headers,
            statusCode: res.status,
            statusMessage: res.statusText
        };
    } catch (error) {
        console.error('Error uploading file:', error);
        throw error;
    } finally {
        clear()
    }
};

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
        const key = await crypto.subtle.importKey('raw', secret as Uint8Array<ArrayBuffer>, {
            name: 'HMAC',
            hash: { name: algo  }
        }, false, ['sign'])
        const signature = await crypto.subtle.sign('HMAC', key, message as Uint8Array<ArrayBuffer>)
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
        values = new Uint32Array(randomBytes.buffer as ArrayBuffer)
    } while (values[0] > limit)
    return Promise.resolve(values[0] % n)
}

// Given a character set, this function will return one sufficiently random character from the charset.
const getRandomCharacterInCharset = async (charset: string): Promise<string> => {
    const count = charset.length
    const pos = await getRandomNumber(count)
    return Promise.resolve(charset[pos])
}

const setCustomProxyAgent = () => {
    console.warn('setCustomProxyAgent is not supported in browser')
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
    getRandomCharacterInCharset: getRandomCharacterInCharset,
    setCustomProxyAgent: setCustomProxyAgent
}
