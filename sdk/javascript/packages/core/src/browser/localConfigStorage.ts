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

    const getBytes = async (key: string): Promise<Uint8Array | undefined> => {
        const value = await getValue(key)
        return typeof value === 'string' ? platform.base64ToBytes(value) : value;
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
        getBytes: getBytes,
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

export const secureStorage = async (dbName: string): Promise<KeyValueStorage> => {
    const STORE_NAME = 'secure'
    const META_KEY = '__secureKey__'

    const getObjectStore = async (mode: IDBTransactionMode): Promise<IDBObjectStore> =>
        new Promise<IDBObjectStore>((resolve) => {
            const req = indexedDB.open(dbName, 1)
            req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME)
            req.onsuccess = () => resolve(req.result.transaction(STORE_NAME, mode).objectStore(STORE_NAME))
        })

    const getRaw = async (key: string): Promise<any> => {
        const store = await getObjectStore('readonly')
        return new Promise<any>(resolve => {
            const r = store.get(key)
            r.onsuccess = () => resolve(r.result)
        })
    }

    const putRaw = async (key: string, value: any): Promise<void> => {
        const store = await getObjectStore('readwrite')
        return new Promise<void>(resolve => {
            const r = store.put(value, key)
            r.onsuccess = () => resolve()
        })
    }

    const delRaw = async (key: string): Promise<void> => {
        const store = await getObjectStore('readwrite')
        return new Promise<void>(resolve => {
            const r = store.delete(key)
            r.onsuccess = () => resolve()
        })
    }

    let wrappingKey: CryptoKey = await getRaw(META_KEY)
    if (!wrappingKey) {
        wrappingKey = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false, // non-extractable: key bytes can never be exported
            ['encrypt', 'decrypt']
        )
        await putRaw(META_KEY, wrappingKey)
    }

    const encryptBytes = async (data: Uint8Array): Promise<Uint8Array> => {
        const iv = crypto.getRandomValues(new Uint8Array(12))
        const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer> }, wrappingKey, data as Uint8Array<ArrayBuffer>)
        const out = new Uint8Array(12 + ct.byteLength)
        out.set(iv, 0)
        out.set(new Uint8Array(ct), 12)
        return out
    }

    const decryptBytes = async (data: Uint8Array): Promise<Uint8Array> => {
        const iv = data.slice(0, 12)
        const ct = data.slice(12)
        return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer> }, wrappingKey, ct as Uint8Array<ArrayBuffer>))
    }

    return {
        getString: async (key: string) => {
            const enc: Uint8Array | undefined = await getRaw(key)
            if (enc == null) return undefined
            return new TextDecoder().decode(await decryptBytes(enc))
        },
        saveString: async (key: string, value: string) => {
            await putRaw(key, await encryptBytes(new TextEncoder().encode(value)))
        },
        getBytes: async (key: string) => {
            const enc: Uint8Array | undefined = await getRaw(key)
            if (enc == null) return undefined
            return decryptBytes(enc)
        },
        saveBytes: async (key: string, value: Uint8Array) => {
            await putRaw(key, await encryptBytes(value))
        },
        delete: async (key: string) => delRaw(key)
    }
}

export function createCachingFunction(storage: KeyValueStorage): (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload) => Promise<KeeperHttpResponse> {

    return async (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload): Promise<KeeperHttpResponse> => {
        try {
            const response = await platform.post(url, payload.payload, {
                PublicKeyId: transmissionKey.publicKeyId.toString(),
                TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
                Authorization: `Signature ${platform.bytesToBase64(payload.signature)}`
            })
            if (response.statusCode == 200) {
                await storage.saveBytes('cache', new Uint8Array([...transmissionKey.key, ...response.data]))
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