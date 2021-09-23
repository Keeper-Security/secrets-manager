import {
    KeeperHttpResponse,
    getSecrets,
    initializeStorage,
    platform,
    localConfigStorage, SecretManagerOptions, inMemoryStorage
} from '../'

import * as fs from 'fs';

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
    const kvs = localConfigStorage()
    await initializeStorage(kvs, 'VB3sGkzVyRB9Lup6WE7Rx-ETFZxyWR2zqY2b9f2zwBo', 'local.keepersecurity.com')
    const options: SecretManagerOptions = {
        storage: kvs,
        queryFunction: postStub
    }
    const secrets = await getSecrets(options)
    expect(secrets.records[1].data.fields[1].value[0]).toBe('N$B!lkoOrVL1RUNDBvn2')
    try {
        await getSecrets(options)
        fail('Did not throw')
    } catch ({message}) {
        expect(JSON.parse(message as string).message).toBe('Signature is invalid')
    }
})

test('Storage prefixes', async () => {
    let storage = inMemoryStorage({})
    await initializeStorage(storage, 'US:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw')
    expect(await storage.getString('hostname')).toBe('keepersecurity.com')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'EU:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw')
    expect(await storage.getString('hostname')).toBe('keepersecurity.eu')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'AU:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw')
    expect(await storage.getString('hostname')).toBe('keepersecurity.com.au')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'eu:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw')
    expect(await storage.getString('hostname')).toBe('keepersecurity.eu')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'local.keepersecurity.com:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw')
    expect(await storage.getString('hostname')).toBe('local.keepersecurity.com')
})

