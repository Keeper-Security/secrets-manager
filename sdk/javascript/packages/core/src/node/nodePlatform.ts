import {KeeperHttpResponse, KeyValueStorage, Platform} from "../platform"
import {request, RequestOptions} from 'https';
import {
    createCipheriv, createDecipheriv,
    createECDH,
    createHash,
    createPrivateKey,
    createSign,
    generateKeyPair,
    randomBytes
} from 'crypto';

function bytesToBase64(data: Uint8Array): string {
    return Buffer.from(data).toString("base64")
}

function base64ToBytes(data: string): Uint8Array {
    return Buffer.from(data, "base64")
}

function bytesToString(data: Uint8Array): string {
    return Buffer.from(data).toString()
}

function stringToBytes(data: string): Uint8Array {
    return Buffer.from(data)
}

function getRandomBytes(length: number): Uint8Array {
    return randomBytes(length);
}

async function generateKeeperKeyPair(): Promise<Uint8Array> {
    return new Promise<Uint8Array>((resolve, reject) => {
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
        });
    })
}

async function generatePrivateKey(keyId: string, storage: KeyValueStorage): Promise<void> {
    const privateKeyDer = await generateKeeperKeyPair()
    await storage.saveValue(keyId, bytesToBase64(privateKeyDer))
}

let cachedPrivateKey: Uint8Array

const loadPrivateKey = async (keyId: string, storage: KeyValueStorage): Promise<Uint8Array> => {
    if (cachedPrivateKey) {
        return cachedPrivateKey
    }
    const privateKeyDerString = await storage.getValue<string>(keyId)
    if (!privateKeyDerString) {
        throw new Error('Unable to load the private key')
    }
    cachedPrivateKey = base64ToBytes(privateKeyDerString)
    return cachedPrivateKey
}
// extracts public raw from private key for prime256v1 curve in der/pkcs8
// privateKey: key.slice(36, 68)
const privateDerToPublicRaw = (key: Uint8Array): Uint8Array => key.slice(73)

async function exportPublicKey(keyId: string, storage: KeyValueStorage): Promise<Uint8Array> {
    const privateKeyDer = await loadPrivateKey(keyId, storage)
    return privateDerToPublicRaw(privateKeyDer)
}

const importKey = async (keyId: string, key: Uint8Array, storage?: KeyValueStorage): Promise<void> => {
    throw new Error('not implemented')
}

function encrypt(data: Uint8Array, keyId: string, storage?: KeyValueStorage): Promise<Uint8Array> {
    throw new Error('not implemented')
    // let iv = randomBytes(12);
    // let cipher = createCipheriv("aes-256-gcm", key, iv);
    // let encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    // const tag = cipher.getAuthTag();
    // let result = Buffer.concat([iv, encrypted, tag]);
    // return Promise.resolve(result);
}

function _encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    let iv = randomBytes(12);
    let cipher = createCipheriv("aes-256-gcm", key, iv);
    let encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();
    let result = Buffer.concat([iv, encrypted, tag]);
    return Promise.resolve(result);
}

const unwrap = async (key: Uint8Array, keyId: string, unwrappingKeyId: string, storage?: KeyValueStorage, memoryOnly?: boolean): Promise<void> => {
    throw new Error('not implemented')
}

function decrypt(data: Uint8Array, keyId: string, storage?: KeyValueStorage): Promise<Uint8Array> {
    throw new Error('not implemented')
    // let iv = data.subarray(0, 12);
    // let encrypted = data.subarray(12, data.length - 16);
    // let tag = data.subarray(data.length - 16);
    // let cipher = createDecipheriv("aes-256-gcm", key, iv);
    // cipher.setAuthTag(tag);
    // return Promise.resolve(Buffer.concat([cipher.update(encrypted), cipher.final()]));
}

function hash(data: Uint8Array): Promise<Uint8Array> {
    const hash = createHash("SHA256").update(data).digest()
    return Promise.resolve(hash)
}

async function publicEncrypt(data: Uint8Array, key: Uint8Array, id?: Uint8Array): Promise<Uint8Array> {
    const ecdh = createECDH('prime256v1')
    ecdh.generateKeys()
    const ephemeralPublicKey = ecdh.getPublicKey()
    const sharedSecret = ecdh.computeSecret(key)
    const sharedSecretCombined = Buffer.concat([sharedSecret, id || new Uint8Array()])
    const symmetricKey = createHash("SHA256").update(sharedSecretCombined).digest()
    const encryptedData = await _encrypt(data, symmetricKey)
    return Buffer.concat([ephemeralPublicKey, encryptedData])
}

async function sign(data: Uint8Array, keyId: string, storage: KeyValueStorage): Promise<Uint8Array> {
    const privateKeyDer = await loadPrivateKey(keyId, storage)
    const key = createPrivateKey({
        key: Buffer.from(privateKeyDer),
        format: 'der',
        type: 'pkcs8',
    })
    const sign = createSign('SHA256')
    sign.update(data)
    const sig = sign.sign(key)
    return Promise.resolve(sig)
}

function get(
    url: string,
    headers?: { [key: string]: string }
): Promise<KeeperHttpResponse> {
    return new Promise<KeeperHttpResponse>((resolve) => {
        let get = request(url, {
            method: "get",
            headers: {
                "User-Agent": `Node/${process.version}`,
                ...headers
            }
        }, (res) => {
            fetchData(res, resolve)
        });
        get.end()
    })
}

function post(
    url: string,
    payload: Uint8Array,
    headers?: { [key: string]: string }
): Promise<KeeperHttpResponse> {
    return new Promise<KeeperHttpResponse>((resolve) => {
        const options: RequestOptions = {
            rejectUnauthorized: false
        }
        let post = request(url, {
            method: 'post',
            ...options,
            headers: {
                "Content-Type": "application/octet-stream",
                "Content-Length": payload.length,
                "User-Agent": `Node/${process.version}`,
                ...headers,
            },
        }, (res) => {
            fetchData(res, resolve)
        });
        post.write(payload)
        post.end()
    })
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
    decrypt: decrypt,
    hash: hash,
    publicEncrypt: publicEncrypt,
    sign: sign,
    get: get,
    post: post
}

function fetchData(res, resolve) {
    let retVal = {
        statusCode: res.statusCode,
        headers: res.headers,
        data: null
    }
    res.on("data", data => {
        retVal.data = retVal.data
            ? Buffer.concat([retVal.data, data])
            : data
    })
    res.on("end", () => {
        resolve(retVal)
    })
}
