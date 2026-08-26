export const DEFAULT_REQUEST_TIMEOUT_MS = 30000

// Storage backend file/thumbnail download URLs carry an AWS SigV4 signature in the query string
// (an 8-hour bearer credential, confirmed against the backend's DownloadRequestFactory) - a
// timeout error embedding the full URL would leak that signature into whatever logs the caller's
// catch-all error handler writes to. Strips the query string unconditionally, since a future
// caller could pass a bearer-style URL through post()/fileUpload() too.
export const truncateUrlForError = (url: string): string => {
    try {
        const parsed = new URL(url)
        return `${parsed.origin}${parsed.pathname}`
    } catch {
        return url.split('?')[0]
    }
}

export type Deadline = {
    signal: AbortSignal | undefined
    clear: () => void
}

// A plain AbortController-driven deadline rather than the AbortSignal.timeout() shorthand: Node's
// http.request(...) treats its own `timeout` option as an idle timer that resets on socket
// activity, not a deadline, so both platforms need this to fire at a fixed point in time
// regardless of activity. AbortController's support is broader than AbortSignal.timeout()'s, so
// this also avoids hard-failing every request on older runtimes that lack the newer static method.
// Callers must call clear() once the request settles, or the underlying setTimeout outlives it.
export const deadlineSignal = (timeoutMs: number): Deadline => {
    if (typeof AbortController === 'undefined') {
        return {signal: undefined, clear: () => {}}
    }
    const controller = new AbortController()
    const timer: any = setTimeout(() => controller.abort(), timeoutMs)
    // Node's Timeout object supports unref() so this timer alone can't keep the process alive if
    // the caller never settles (a thrown/mocked request, for instance); browsers' setTimeout
    // returns a plain number with no such method.
    timer.unref?.()
    return {signal: controller.signal, clear: () => clearTimeout(timer)}
}

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
    get(url: string, headers: any, timeoutMs?: number): Promise<KeeperHttpResponse>
    post(url: string, request: Uint8Array, headers?: { [key: string]: string }, allowUnverifiedCertificate?: boolean, timeoutMs?: number): Promise<KeeperHttpResponse>
    fileUpload(url: string, uploadParameters: any, data: Uint8Array | Blob, timeoutMs?: number): Promise<any>
    setCustomProxyAgent(proxyAgent: any): void
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

export const setCustomProxyAgent = (proxyAgent: any) => {
    platform.setCustomProxyAgent(proxyAgent)
}