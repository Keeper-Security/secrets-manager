import {KeyValueStorage} from '@keeper/secrets-manager-core';

const deleteValue = async (objectStore: IDBObjectStore, key: string): Promise<void> =>
    new Promise<void>(((resolve, reject) => {
        const request = objectStore.delete(key)
        request.onsuccess = () => {
            resolve()
        }
    }))

export const indexedDbValueStorage = (client: string): KeyValueStorage => {

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

    return {
        getValue: async (key: string): Promise<any | undefined> => {
            const objectStore = await getObjectStore('readonly')
            return new Promise<string | undefined>(((resolve, reject) => {
                const request = objectStore.get(key)
                request.onsuccess = () => {
                    resolve(request.result)
                }
            }))
        },

        saveValue: async (key: string, value: any): Promise<void> => {
            const objectStore = await getObjectStore('readwrite')
            return new Promise<void>(((resolve, reject) => {
                const request = objectStore.put(value, key)
                request.onsuccess = () => {
                    resolve()
                }
            }))
        },

        clearValues: async (keys: string[]): Promise<void> => {
            const objectStore = await getObjectStore('readwrite')
            for (const key of keys) {
                await deleteValue(objectStore, key)
            }
        }
    }
};

