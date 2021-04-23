import {KeeperHttpResponse, Platform} from "../platform"
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

    static async generateKeyPair(): Promise<Uint8Array> {
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

    static encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        let iv = randomBytes(12);
        let cipher = createCipheriv("aes-256-gcm", key, iv);
        let encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        let result = Buffer.concat([iv, encrypted, tag]);
        return Promise.resolve(result);
    }

    static decrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        let iv = data.subarray(0, 12);
        let encrypted = data.subarray(12, data.length - 16);
        let tag = data.subarray(data.length - 16);
        let cipher = createDecipheriv("aes-256-gcm", key, iv);
        cipher.setAuthTag(tag);
        return Promise.resolve(Buffer.concat([cipher.update(encrypted), cipher.final()]));
    }

    static hash(data: Uint8Array): Promise<Uint8Array> {
        const hash = createHash("SHA256").update(data).digest()
        return Promise.resolve(hash)
    }

    static async publicEncrypt(data: Uint8Array, key: Uint8Array, id?: Uint8Array): Promise<Uint8Array> {
        const ecdh = createECDH('prime256v1')
        ecdh.generateKeys()
        const ephemeralPublicKey = ecdh.getPublicKey()
        const sharedSecret = ecdh.computeSecret(key)
        const sharedSecretCombined = Buffer.concat([sharedSecret, id || new Uint8Array()])
        const symmetricKey = createHash("SHA256").update(sharedSecretCombined).digest()
        const encryptedData = await nodePlatform.encrypt(data, symmetricKey)
        return Buffer.concat([ephemeralPublicKey, encryptedData])
    }

    static sign(data: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
        const key = createPrivateKey({
            key: Buffer.from(privateKey),
            format: 'der',
            type: 'pkcs8',
        })
        const sign = createSign('SHA256')
        sign.update(data)
        const sig = sign.sign(key)
        return Promise.resolve(sig)
    }

    static post(
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
