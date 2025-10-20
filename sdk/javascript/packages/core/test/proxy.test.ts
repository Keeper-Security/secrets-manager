import {
    getSecrets,
    initializeStorage,
    platform,
    localConfigStorage,
    SecretManagerOptions,
    setCustomProxyAgent,
} from '../'

import * as https from 'https';
import { HttpsProxyAgent } from 'https-proxy-agent';
import * as fs from 'fs'

jest.mock('https', () => {
    return {
        request: jest.fn()
    }
})

test('Test proxy when agent is not set', async () => {
    const responses: { transmissionKey: string, data: string, statusCode: number } [] = JSON.parse(fs.readFileSync('../../../fake_data.json').toString())

    let responseNo = 0

    const getRandomBytesStub = (): Uint8Array => platform.base64ToBytes(responses[responseNo].transmissionKey)

    platform.getRandomBytes = getRandomBytesStub
    const kvs = localConfigStorage()

    const fakeOneTimeCode = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

    await initializeStorage(kvs, fakeOneTimeCode, 'fake.keepersecurity.com')
    const options: SecretManagerOptions = {
        storage: kvs
    }
    try {
        await getSecrets(options)
    } catch (e) {}

    const mockedRequest = (https.request as unknown as jest.Mock)
    const agent = mockedRequest.mock.calls[0][1].agent as HttpsProxyAgent<string>
    expect(agent).toBeUndefined()
})

test('Test when custom proxy agent is invalid', async () => {
    const responses: { transmissionKey: string, data: string, statusCode: number } [] = JSON.parse(fs.readFileSync('../../../fake_data.json').toString())

    let responseNo = 0

    const getRandomBytesStub = (): Uint8Array => platform.base64ToBytes(responses[responseNo].transmissionKey)

    platform.getRandomBytes = getRandomBytesStub
    const kvs = localConfigStorage()

    const fakeOneTimeCode = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

    await initializeStorage(kvs, fakeOneTimeCode, 'fake.keepersecurity.com')
    setCustomProxyAgent({} as https.Agent)
    const options: SecretManagerOptions = {
        storage: kvs
    }
    try {
        await getSecrets(options)
    } catch (e) {
        expect(e).toBeDefined()
    }
})

test('Test proxy support when proxt agent is set', async () => {
    const testProxyUrl = 'http://localhost:7777'

    const responses: { transmissionKey: string, data: string, statusCode: number } [] = JSON.parse(fs.readFileSync('../../../fake_data.json').toString())

    let responseNo = 0

    const getRandomBytesStub = (): Uint8Array => platform.base64ToBytes(responses[responseNo].transmissionKey)

    platform.getRandomBytes = getRandomBytesStub
    const kvs = localConfigStorage()

    const fakeOneTimeCode = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

    await initializeStorage(kvs, fakeOneTimeCode, 'fake.keepersecurity.com')
    const options: SecretManagerOptions = {
        storage: kvs
    }
    setCustomProxyAgent(new HttpsProxyAgent(testProxyUrl))
    try {
        await getSecrets(options)
    } catch (e) {}

    const mockedRequest = (https.request as unknown as jest.Mock)
    const agent = mockedRequest.mock.calls[2][1].agent as HttpsProxyAgent<string>
    expect(agent).toBeDefined()
    expect(agent.proxy).toBeDefined()
    expect(agent.proxy.origin).toBe(testProxyUrl)
})