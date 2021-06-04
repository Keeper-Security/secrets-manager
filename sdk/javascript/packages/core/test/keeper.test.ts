import {
    generateTransmissionKey,
    getSecrets,
    initializeStorage,
    KeyValueStorage,
    platform,
    KeeperHttpResponse
} from '../'

import * as fs from 'fs';

test('Transmission keys generated ok', async () => {
    for (let keyNumber of [1, 2, 3, 4, 5, 6]) {
        const key = await generateTransmissionKey(keyNumber)
        expect(key.publicKeyId).toBe(keyNumber);
        expect(key.encryptedKey.length).toBe(125)
    }
})

test('Get secrets e2e', async () => {

    const responses: { transmissionKey: string; data: string, statusCode: number } [] = JSON.parse(fs.readFileSync('../../../test_data.json').toString())

    let responseNo = 0

    const getRandomBytesStub = (): Uint8Array => platform.base64ToBytes(responses[responseNo].transmissionKey);

    const postStub = (): Promise<KeeperHttpResponse> => {
        const response = responses[responseNo++]
        return Promise.resolve({
            data: platform.base64ToBytes(response.data),
            statusCode: response.statusCode,
            headers: []
        });
    };

    platform.getRandomBytes = getRandomBytesStub
    platform.post = postStub
    const kvs = inMemoryStorage()
    await initializeStorage(kvs, 'VB3sGkzVyRB9Lup6WE7Rx-ETFZxyWR2zqY2b9f2zwBo', 'local.keepersecurity.com')
    const secrets = await getSecrets(kvs)
    expect(secrets.records[1].data.fields[1].value[0]).toBe('N$B!lkoOrVL1RUNDBvn2')
    try {
        await getSecrets(kvs)
        fail('Did not throw')
    } catch (e) {
        expect(JSON.parse(e.message).message).toBe('Signature is invalid')
    }
})

const inMemoryStorage = (): KeyValueStorage => {

    const storage: any = {}

    const getValue = (key: string): any | undefined => {
        const obj = storage[key]
        return !obj ? undefined : obj.toString();
    }

    const saveValue = (key: string, value: any): void => {
        storage[key] = value
    }

    const clearValue = (key: string): void => {
        delete storage[key]
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
