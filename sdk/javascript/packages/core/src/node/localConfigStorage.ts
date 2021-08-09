import {EncryptedPayload, KeeperHttpResponse, KeyValueStorage, platform, TransmissionKey} from "../platform";
import * as fs from 'fs';

export const localConfigStorage = (configName?: string): KeyValueStorage => {

    const readStorage = (): any => {
        if (!configName) {
            return {}
        }
        try {
            return JSON.parse(fs.readFileSync(configName).toString())
        } catch (e) {
            return {}
        }
    }

    const storage: any = readStorage()

    const saveStorage = (storage: any) => {
        if (!configName) {
            return
        }
        fs.writeFileSync(configName, JSON.stringify(storage, null, 2))
    }

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
        saveStorage(storage)
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
        saveStorage(storage)
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

export const cachingPostFunction = async (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload): Promise<KeeperHttpResponse> => {
    try {
        const response = await platform.post(url, payload.payload, {
            PublicKeyId: transmissionKey.publicKeyId.toString(),
            TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
            Authorization: `Signature ${platform.bytesToBase64(payload.signature)}`
        })
        if (response.statusCode == 200) {
            fs.writeFileSync('cache.dat', Buffer.concat([transmissionKey.key, response.data]))
        }
        return response
    } catch (e) {
        let cachedData
        try {
            cachedData = fs.readFileSync('cache.dat')
        } catch {
        }
        if (!cachedData) {
            throw new Error('Cached value does not exist')
        }
        transmissionKey.key = cachedData.slice(0, 32)
        return {
            statusCode: 200,
            data: cachedData.slice(32),
            headers: []
        }
    }
}