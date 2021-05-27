import {KeyValueStorage} from '@keeper/secrets-manager-core';

export const indexedDbValueStorage = (client: string, useObjects: boolean): KeyValueStorage => {

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

