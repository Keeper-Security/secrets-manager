import {KeeperHttpResponse, Platform} from "../platform"
import {request, RequestOptions} from 'https';
import {randomBytes, createCipheriv, createECDH, createHash} from 'crypto';
import {webSafe64FromBytes} from '../utils';

export const nodePlatform: Platform = class {

    static bytesToBase64(data: Uint8Array): string {
        return Buffer.from(data).toString("base64")
    }

    static base64ToBytes(data: string): Uint8Array {
        return Buffer.from(data, "base64")
    }

    static bytesToString(data: Uint8Array): string {
        return Buffer.from(data).toString()
    }

    static stringToBytes(data: string): Uint8Array {
        return Buffer.from(data)
    }

    static getRandomBytes(length: number): Uint8Array {
        return randomBytes(length);
    }

    static async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
        const ecdh = createECDH('prime256v1')
        ecdh.generateKeys()
        return Promise.resolve({
            privateKey: webSafe64FromBytes(ecdh.getPrivateKey()),
            publicKey: webSafe64FromBytes(ecdh.getPublicKey())
        })
    }

    static aesEncrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        let iv = randomBytes(12);
        let cipher = createCipheriv("aes-256-gcm", key, iv);
        let encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        let result = Buffer.concat([iv, encrypted, tag]);
        return Promise.resolve(result);
    }

    static async publicEncrypt(data: Uint8Array, key: Uint8Array, id?: Uint8Array): Promise<Uint8Array> {
        const ecdh = createECDH('prime256v1')
        ecdh.generateKeys()
        const ephemeralPublicKey = ecdh.getPublicKey()
        const sharedSecret = ecdh.computeSecret(key)
        const sharedSecretCombined = Buffer.concat([sharedSecret, id || new Uint8Array()])
        const symmetricKey = createHash("SHA256").update(sharedSecretCombined).digest()
        const encryptedData = await nodePlatform.aesEncrypt(data, symmetricKey)
        return Buffer.concat([ephemeralPublicKey, encryptedData])
    }

    static post(
        url: string,
        payload: Uint8Array,
        headers?: {[key: string]: string}
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
