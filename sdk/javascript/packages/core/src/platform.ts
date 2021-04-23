export type Platform = {
//  string routines
    bytesToBase64(data: Uint8Array): string
    base64ToBytes(data: string): Uint8Array
    bytesToString(data: Uint8Array): string
    stringToBytes(data: string): Uint8Array

//  cryptography
    getRandomBytes(length: number): Uint8Array;
    generateKeyPair(): Promise<Uint8Array>
    encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>
    decrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>
    hash(data: Uint8Array): Promise<Uint8Array>
    publicEncrypt(data: Uint8Array, key: Uint8Array, id?: Uint8Array): Promise<Uint8Array>
    sign(data: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>

//  network
    post(url: string, request: Uint8Array, headers?: { [key: string]: string }): Promise<KeeperHttpResponse>
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
