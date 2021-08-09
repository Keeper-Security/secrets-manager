import {
    KeeperHttpResponse,
    getSecrets,
    initializeStorage,
    platform,
    localConfigStorage, SecretManagerOptions
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
    } catch (e) {
        expect(JSON.parse(e.message).message).toBe('Signature is invalid')
    }
})