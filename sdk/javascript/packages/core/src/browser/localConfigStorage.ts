import {EncryptedPayload, KeeperHttpResponse, KeyValueStorage, TransmissionKey, platform} from "../platform";

export const localConfigStorage = (client: string, useObjects: boolean): KeyValueStorage => {

    const getObjectStore = async (mode: IDBTransactionMode): Promise<IDBObjectStore> =>
        new Promise<IDBObjectStore>(((resolve, reject) => {
            const request = indexedDB.open(client, 1)
            request.onupgradeneeded = () => {
                request.result.createObjectStore('secrets');
            }
            request.onsuccess = () => {
                resolve(request.result.transaction('secrets', mode).objectStore('secrets'))
            }
        }))

    const getValue = async (key: string): Promise<any | undefined> => {
        const objectStore = await getObjectStore('readonly')
        return new Promise<string | undefined>(((resolve, reject) => {
            const request = objectStore.get(key)
            request.onsuccess = () => {
                resolve(request.result)
            }
        }))
    }

    const saveValue = async (key: string, value: any): Promise<void> => {
        const objectStore = await getObjectStore('readwrite')
        return new Promise<void>(((resolve, reject) => {
            const request = objectStore.put(value, key)
            request.onsuccess = () => {
                resolve()
            }
        }))
    }

    const deleteValue = async (key: string): Promise<void> => {
        const objectStore = await getObjectStore('readwrite')
        return new Promise<void>(((resolve, reject) => {
            const request = objectStore.delete(key)
            request.onsuccess = () => {
                resolve()
            }
        }))
    }

    let storage: KeyValueStorage = {
        getString: getValue,
        saveString: saveValue,
        getBytes: getValue,
        saveBytes: saveValue,
        delete: deleteValue
    }

    if (useObjects) {
        storage = {
            ...storage,
            getObject: getValue,
            saveObject: saveValue,
        }
    }

    return storage
};

export function createCachingFunction(storage: KeyValueStorage): (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload) => Promise<KeeperHttpResponse> {

    return async (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload): Promise<KeeperHttpResponse> => {
        try {
            const response = await platform.post(url, payload.payload, {
                PublicKeyId: transmissionKey.publicKeyId.toString(),
                TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
                Authorization: `Signature ${platform.bytesToBase64(payload.signature)}`
            })
            if (response.statusCode == 200) {
                await storage.saveBytes('cache', Buffer.concat([transmissionKey.key, response.data]))
            }
            return response
        } catch (e) {
            const cachedData = await storage.getBytes('cache')
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
}