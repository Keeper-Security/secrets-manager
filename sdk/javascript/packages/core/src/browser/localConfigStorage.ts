import {EncryptedPayload, KeeperHttpResponse, KeyValueStorage, TransmissionKey, platform} from "../platform";
import {KeeperError} from "../errors";

type Reject = (reason: Error) => void

// Duck-typed rather than `instanceof Error`. IndexedDB reports failures as a DOMException, and
// whether that satisfies `instanceof Error` depends on the realm it was constructed in, so a
// cross-realm failure (a worker, an iframe) would otherwise lose the diagnostic entirely.
const describeCause = (cause: unknown): string => {
    const {name, message} = (cause ?? {}) as { name?: unknown, message?: unknown }
    if (typeof name === 'string' && typeof message === 'string') return `${name}: ${message}`
    if (typeof message === 'string') return message
    return 'unknown error'
}

const idbFailure = (operation: string, cause: unknown): KeeperError =>
    new KeeperError(`IndexedDB ${operation} failed: ${describeCause(cause)}`)

// A failing IDBRequest fires onerror and never onsuccess, so a promise that only handles
// onsuccess stays pending forever. The caller then hangs with no error, no rejection and no
// timeout, which is far worse than failing. Every request in this file is wired through here.
const rejectOnError = (request: IDBRequest, reject: Reject, operation: string): void => {
    request.onerror = () => reject(idbFailure(operation, request.error))
}

const rejectOnOpenFailure = (request: IDBOpenDBRequest, reject: Reject, dbName: string): void => {
    rejectOnError(request, reject, `open of database '${dbName}'`)
    // onblocked fires when another live connection holds the database at the old version during
    // an upgrade. Neither onsuccess nor onerror follows it, so this is the only chance to settle.
    request.onblocked = () => reject(new KeeperError(
        `IndexedDB open of database '${dbName}' is blocked by another open connection to it`))
}

export const localConfigStorage = (client: string, useObjects: boolean): KeyValueStorage => {

    const STORE_NAME = 'secrets'

    const getObjectStore = async (mode: IDBTransactionMode): Promise<IDBObjectStore> =>
        new Promise<IDBObjectStore>(((resolve, reject) => {
            const request = indexedDB.open(client, 1)
            rejectOnOpenFailure(request, reject, client)
            request.onupgradeneeded = () => {
                request.result.createObjectStore(STORE_NAME);
            }
            request.onsuccess = () => {
                // transaction() throws synchronously when the store is missing, and a throw
                // inside an event handler is not caught by the Promise executor, so it has to
                // be turned into a rejection here or the promise never settles.
                try {
                    resolve(request.result.transaction(STORE_NAME, mode).objectStore(STORE_NAME))
                } catch (e) {
                    reject(idbFailure(`transaction on store '${STORE_NAME}'`, e))
                }
            }
        }))

    const getValue = async (key: string): Promise<any | undefined> => {
        const objectStore = await getObjectStore('readonly')
        return new Promise<string | undefined>(((resolve, reject) => {
            const request = objectStore.get(key)
            rejectOnError(request, reject, `read of key '${key}'`)
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
            rejectOnError(request, reject, `write of key '${key}'`)
            request.onsuccess = () => {
                resolve()
            }
        }))
    }

    const deleteValue = async (key: string): Promise<void> => {
        const objectStore = await getObjectStore('readwrite')
        return new Promise<void>(((resolve, reject) => {
            const request = objectStore.delete(key)
            rejectOnError(request, reject, `delete of key '${key}'`)
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
        new Promise<IDBObjectStore>((resolve, reject) => {
            const req = indexedDB.open(dbName, 1)
            rejectOnOpenFailure(req, reject, dbName)
            req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME)
            req.onsuccess = () => {
                try {
                    resolve(req.result.transaction(STORE_NAME, mode).objectStore(STORE_NAME))
                } catch (e) {
                    reject(idbFailure(`transaction on store '${STORE_NAME}'`, e))
                }
            }
        })

    const getRaw = async (key: string): Promise<any> => {
        const store = await getObjectStore('readonly')
        return new Promise<any>((resolve, reject) => {
            const r = store.get(key)
            rejectOnError(r, reject, `read of key '${key}'`)
            r.onsuccess = () => resolve(r.result)
        })
    }

    const putRaw = async (key: string, value: any): Promise<void> => {
        const store = await getObjectStore('readwrite')
        return new Promise<void>((resolve, reject) => {
            const r = store.put(value, key)
            rejectOnError(r, reject, `write of key '${key}'`)
            r.onsuccess = () => resolve()
        })
    }

    const delRaw = async (key: string): Promise<void> => {
        const store = await getObjectStore('readwrite')
        return new Promise<void>((resolve, reject) => {
            const r = store.delete(key)
            rejectOnError(r, reject, `delete of key '${key}'`)
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

// Signature matches SecretManagerOptions.queryFunction so the trailing options, including
// requestTimeoutMs, reach platform.post instead of being dropped on the floor.
export function createCachingFunction(storage: KeyValueStorage): (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload, allowUnverifiedCertificate?: boolean, timeoutMs?: number) => Promise<KeeperHttpResponse> {

    return async (url: string, transmissionKey: TransmissionKey, payload: EncryptedPayload, allowUnverifiedCertificate?: boolean, timeoutMs?: number): Promise<KeeperHttpResponse> => {
        try {
            const response = await platform.post(url, payload.payload, {
                PublicKeyId: transmissionKey.publicKeyId.toString(),
                TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
                Authorization: `Signature ${platform.bytesToBase64(payload.signature)}`
            }, allowUnverifiedCertificate, timeoutMs)
            if (response.statusCode == 200) {
                await storage.saveBytes('cache', new Uint8Array([...transmissionKey.key, ...response.data]))
            }
            return response
        } catch (e) {
            // A deliberate client-side timeout is not a transport failure: falling back to stale
            // cache here would silently turn a slow/hung request into a fake success instead of
            // surfacing it to the caller.
            if (e instanceof KeeperError) {
                throw e
            }
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