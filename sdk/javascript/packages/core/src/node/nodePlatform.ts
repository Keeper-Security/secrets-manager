import {KeeperHttpResponse, KeyValueStorage, Platform} from '../platform'
import {privateDerToPublicRaw} from '../utils'
import {request, RequestOptions} from 'https'
import {
    createCipheriv,
    createDecipheriv,
    createECDH,
    createHash, createHmac,
    createPrivateKey,
    createSign,
    generateKeyPair,
    randomBytes
} from 'crypto'
import * as https from "https";

const bytesToBase64 = (data: Uint8Array): string => Buffer.from(data).toString('base64')

const base64ToBytes = (data: string): Uint8Array => Buffer.from(data, 'base64')

const bytesToString = (data: Uint8Array): string => Buffer.from(data).toString()

const stringToBytes = (data: string): Uint8Array => Buffer.from(data)

const getRandomBytes = (length: number): Uint8Array => randomBytes(length)

const keyCache: Record<string, Uint8Array> = {}

const loadKey = async (keyId: string, storage?: KeyValueStorage): Promise<Uint8Array> => {
    const cachedKey = keyCache[keyId]
    if (cachedKey) {
        return cachedKey
    }
    const keyBytes = storage
        ? await storage.getBytes(keyId)
        : undefined
    if (!keyBytes) {
        throw new Error(`Unable to load the key ${keyId}`)
    }
    keyCache[keyId] = keyBytes
    return keyBytes
}

const generateKeeperKeyPair = async (): Promise<Uint8Array> => new Promise<Uint8Array>((resolve, reject) => {
    generateKeyPair('ec', {
        namedCurve: 'prime256v1'
    }, (err, publicKey, privateKey) => {
        if (err) {
            reject(err)
        } else {
            resolve(privateKey.export({
                format: 'der',
                type: 'pkcs8'
            }))
        }
    })
})

const generatePrivateKey = async (keyId: string, storage: KeyValueStorage): Promise<void> => {
    const privateKeyDer = await generateKeeperKeyPair()
    keyCache[keyId] = privateKeyDer
    await storage.saveBytes(keyId, privateKeyDer)
}

const exportPublicKey = async (keyId: string, storage: KeyValueStorage): Promise<Uint8Array> => {
    const privateKeyDer = await loadKey(keyId, storage)
    return privateDerToPublicRaw(privateKeyDer)
}

const privateDerToPEM = (key: Uint8Array): string => {
    const rawPrivate = key.slice(36, 68)
    const rawPublic = key.slice(-65)
    const keyData1 = Buffer.of(0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20)
    const keyData2 = Buffer.of(0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00)
    return `-----BEGIN EC PRIVATE KEY-----\n${bytesToBase64(Buffer.concat([keyData1, rawPrivate, keyData2, rawPublic]))}\n-----END EC PRIVATE KEY-----`
}

const sign = async (data: Uint8Array, keyId: string, storage: KeyValueStorage): Promise<Uint8Array> => {
    const privateKeyDer = await loadKey(keyId, storage)
    const key = privateDerToPEM(privateKeyDer)
    // TODO revert to using createPrivateKey when node 10 interop is not needed anymore
    // const key = createPrivateKey({
    //     key: Buffer.from(privateKeyDer),
    //     format: 'der',
    //     type: 'pkcs8',
    // })
    const sign = createSign('SHA256')
    sign.update(data)
    const sig = sign.sign(key)
    return Promise.resolve(sig)
}

const importKey = async (keyId: string, key: Uint8Array, storage?: KeyValueStorage): Promise<void> => {
    keyCache[keyId] = key
    if (storage) {
        await storage.saveBytes(keyId, key)
    }
}

const encrypt = async (data: Uint8Array, keyId: string, storage?: KeyValueStorage, useCBC?: boolean): Promise<Uint8Array> => {
    const key = await loadKey(keyId, storage)
    return _encrypt(data, key, useCBC)
}

const _encrypt = (data: Uint8Array, key: Uint8Array, useCBC?: boolean): Promise<Uint8Array> => {
    if (useCBC) {
        return _encryptCBC(data, key)
    }
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()])
    const tag = cipher.getAuthTag()
    const result = Buffer.concat([iv, encrypted, tag])
    return Promise.resolve(result)
}

const _encryptCBC = async (data: Uint8Array, key: Uint8Array): Promise<Uint8Array> => {
    let iv = randomBytes(16);
    let cipher = createCipheriv("aes-256-cbc", key, iv).setAutoPadding(true);
    let encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return Buffer.concat([iv, encrypted]);
}

const _decrypt = (data: Uint8Array, key: Uint8Array, useCBC?: boolean): Promise<Uint8Array> => {
    if (useCBC) {
        return _decryptCBC(data, key)
    }
    const iv = data.subarray(0, 12)
    const encrypted = data.subarray(12, data.length - 16)
    const tag = data.subarray(data.length - 16)
    const cipher = createDecipheriv('aes-256-gcm', key, iv)
    cipher.setAuthTag(tag)
    return Promise.resolve(Buffer.concat([cipher.update(encrypted), cipher.final()]))
}

const _decryptCBC = async (data: Uint8Array, key: Uint8Array): Promise<Uint8Array> => {
    let iv = data.subarray(0, 16)
    let encrypted = data.subarray(16)
    let cipher = createDecipheriv("aes-256-cbc", key, iv).setAutoPadding(true)
    return Buffer.concat([cipher.update(encrypted), cipher.final()])
}

const unwrap = async (key: Uint8Array, keyId: string, unwrappingKeyId: string, storage?: KeyValueStorage, memoryOnly?: boolean, useCBC?: boolean): Promise<void> => {
    const unwrappingKey = await loadKey(unwrappingKeyId, storage)
    const unwrappedKey = await _decrypt(key, unwrappingKey, useCBC)
    keyCache[keyId] = unwrappedKey
    if (memoryOnly) {
        return
    }
    if (storage) {
        await storage.saveBytes(keyId, unwrappedKey)
    }
}

const decrypt = async (data: Uint8Array, keyId: string, storage?: KeyValueStorage, useCBC?: boolean): Promise<Uint8Array> => {
    const key = await loadKey(keyId, storage)
    return _decrypt(data, key, useCBC)
}

function hash(data: Uint8Array): Promise<Uint8Array> {
    const hash = createHmac('sha512', data).update('KEEPER_SECRETS_MANAGER_CLIENT_ID').digest()
    return Promise.resolve(hash)
}

const publicEncrypt = async (data: Uint8Array, key: Uint8Array, id?: Uint8Array): Promise<Uint8Array> => {
    const ecdh = createECDH('prime256v1')
    ecdh.generateKeys()
    const ephemeralPublicKey = ecdh.getPublicKey()
    const sharedSecret = ecdh.computeSecret(key)
    const sharedSecretCombined = Buffer.concat([sharedSecret, id || new Uint8Array()])
    const symmetricKey = createHash('SHA256').update(sharedSecretCombined).digest()
    const encryptedData = await _encrypt(data, symmetricKey)
    return Buffer.concat([ephemeralPublicKey, encryptedData])
}

const fetchData = (res, resolve) => {
    const retVal = {
        statusCode: res.statusCode,
        headers: res.headers,
        data: null
    }
    res.on('data', data => {
        retVal.data = retVal.data
            ? Buffer.concat([retVal.data, data])
            : data
    })
    res.on('end', () => {
        resolve(retVal)
    })
}

const get = (
    url: string,
    headers?: { [key: string]: string }
): Promise<KeeperHttpResponse> => new Promise<KeeperHttpResponse>((resolve, reject) => {
    const get = request(url, {
        method: 'get',
        headers: {
            'User-Agent': `Node/${process.version}`,
            ...headers
        }
    }, (res) => {
        fetchData(res, resolve)
    })
    get.on('error', reject)
    get.end()
})

const post = (
    url: string,
    payload: Uint8Array,
    headers?: { [key: string]: string },
    allowUnverifiedCertificate?: boolean
): Promise<KeeperHttpResponse> => new Promise<KeeperHttpResponse>((resolve, reject) => {
    const options: RequestOptions = {
        rejectUnauthorized: !allowUnverifiedCertificate
    }
    const post = request(url, {
        method: 'post',
        ...options,
        headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Length': payload.length,
            'User-Agent': `Node/${process.version}`,
            ...headers,
        },
    }, (res) => {
        fetchData(res, resolve)
    })
    post.on('error', reject)
    post.write(payload)
    post.end()
})

const fileUpload = (
    url: string,
    uploadParameters: { [key: string]: string },
    data: Uint8Array
): Promise<any> => new Promise<any>((resolve, reject) => {
    const boundary = `----------${Date.now()}`
    const boundaryBytes = stringToBytes(`\r\n--${boundary}`)
    let post = https.request(url, {
        method: "post",
        headers: {
            'Content-Type': `multipart/form-data; boundary=${boundary}`,
        }
    });
    post.on('response', function (res: any) {
        resolve({
            headers: res.headers,
            statusCode: res.statusCode,
            statusMessage: res.statusMessage
        })
    })
    post.on('error', reject)
    for (const key in uploadParameters) {
        post.write(boundaryBytes)
        post.write(stringToBytes(`\r\nContent-Disposition: form-data; name=\"${key}\"\r\n\r\n${uploadParameters[key]}`))
    }
    post.write(boundaryBytes)
    post.write(stringToBytes(`\r\nContent-Disposition: form-data; name=\"file\"\r\nContent-Type: application/octet-stream\r\n\r\n`))
    post.write(data)
    post.write(boundaryBytes)
    post.write(stringToBytes(`--\r\n`))
    post.end()
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
    let digest = new Uint8Array()
    const algo = algorithm.toUpperCase().trim()
    if (['SHA1', 'SHA256', 'SHA512'].includes(algo))
        digest = createHmac(algo, secret).update(message).digest()

    return Promise.resolve(digest)
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

export const nodePlatform: Platform = {
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