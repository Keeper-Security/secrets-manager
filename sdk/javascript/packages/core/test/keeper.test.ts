import {
    generateTransmissionKey,
    getSecrets,
    initializeStorage,
    KeyValueStorage,
    platform,
    KeeperHttpResponse
} from '../'

test('Transmission keys generated properly', async () => {
    for (let keyNumber of [1, 2, 3, 4, 5, 6]) {
        const key = await generateTransmissionKey(keyNumber)
        expect(key.publicKeyId).toBe(keyNumber);
        expect(key.encryptedKey.length).toBe(125)
    }
})

test('Get secrets happy path', async () => {
    platform.getRandomBytes = getRandomBytesStub
    platform.post = postStub
    const kvs = testKeyValueStorage()
    await initializeStorage(kvs, 'PqvIhkf-uV7TVV5Hlc1Ypp1d41s9iQFEJ-stc_IBJrU', 'local.keepersecurity.com')
    await kvs.saveBytes('appKey', platform.base64ToBytes('L+NXDmCw5QpdhjFnnZr2ETEq9ek+9fKBvA0jhSx7wQ8='))
    const secrets = await getSecrets(kvs)
    expect(secrets.records[1].data.fields[1].value[0]).toBe('N$B!lkoOrVL1RUNDBvn2')
})

const testKeyValueStorage = (): KeyValueStorage => {

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

function getRandomBytesStub(length: number): Uint8Array {
    return platform.base64ToBytes('8YQmju81uxVTV1QKixTG99/radmofMU5NONDukJDvac=');
}

function postStub(
    url: string,
    payload: Uint8Array,
    headers?: { [key: string]: string }
): Promise<KeeperHttpResponse> {
    return Promise.resolve({
        data: platform.base64ToBytes('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'),
        statusCode: 200,
        headers: []
    })
}
