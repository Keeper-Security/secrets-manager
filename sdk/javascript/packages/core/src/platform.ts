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
    decrypt(data: Uint8Array, keyId: string, storage?: KeyValueStorage): Promise<Uint8Array>
    hash(data: Uint8Array): Promise<Uint8Array>

//  network
    get(url: string, headers: any): Promise<KeeperHttpResponse>;
    post(url: string, request: Uint8Array, headers?: { [key: string]: string }): Promise<KeeperHttpResponse>
}

export type KeyValueStorage = {
    getValue<T>(key: string): Promise<T | undefined>;
    saveValue<T>(key: string, value: T): Promise<void>;
    clearValues(keys: string[]): Promise<void>;
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
