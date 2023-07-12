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
    unwrap(key: Uint8Array, keyId: string, unwrappingKeyId: string, storage?: KeyValueStorage, memoryOnly?: boolean, useCBC?: boolean): Promise<void>
    encrypt(data: Uint8Array, keyId: string, storage?: KeyValueStorage, useCBC?: boolean): Promise<Uint8Array>
    encryptWithKey(data: Uint8Array, key: Uint8Array, useCBC?: boolean): Promise<Uint8Array>
    decrypt(data: Uint8Array, keyId: string, storage?: KeyValueStorage, useCBC?: boolean): Promise<Uint8Array>
    decryptWithKey(data: Uint8Array, key: Uint8Array, useCBC?: boolean): Promise<Uint8Array>
    hash(data: Uint8Array, tag: string): Promise<Uint8Array>
    cleanKeyCache(): void
    hasKeysCached(): boolean;
    getHmacDigest(algorithm: string, secret: Uint8Array, message: Uint8Array): Promise<Uint8Array>
    getRandomNumber(n: number): Promise<number>
    getRandomCharacterInCharset(charset: string): Promise<string>

//  network
    get(url: string, headers: any): Promise<KeeperHttpResponse>
    post(url: string, request: Uint8Array, headers?: { [key: string]: string }, allowUnverifiedCertificate?: boolean): Promise<KeeperHttpResponse>
    fileUpload(url: string, uploadParameters: any, data: Uint8Array | Blob): Promise<any>
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
