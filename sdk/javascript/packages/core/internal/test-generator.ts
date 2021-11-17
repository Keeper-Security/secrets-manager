import {
    getSecrets,
    initialize,
    initializeStorage
} from '../src/keeper';
import {nodePlatform} from '../src/node/nodePlatform';
import {localConfigStorage} from '../src/node/localConfigStorage';
import {connectPlatform, KeeperHttpResponse, platform} from '../src/platform';
import {inspect} from 'util';
import * as fs from 'fs';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

connectPlatform(nodePlatform)
initialize()

const platformPost = platform.post;
const platformRandomBytes = platform.getRandomBytes
const responses: { transmissionKey: string; data: string, statusCode: number } [] = []
const clientKey = 'VB3sGkzVyRB9Lup6WE7Rx-ETFZxyWR2zqY2b9f2zwBo'

async function generateTests() {
    platform.post = postProxy
    platform.getRandomBytes = getRandomBytesProxy
    try {
        const kvs = localConfigStorage()
        await initializeStorage(kvs, clientKey, 'dev.keepersecurity.com')
        const response = await getSecrets({
            storage: kvs
        })
        console.log(inspect(response, false, 6))
        const kvs1 = localConfigStorage()
        await initializeStorage(kvs1, clientKey, 'dev.keepersecurity.com') // expect failure on invalid signature
        await getSecrets({
            storage: kvs1
        })
    } catch (e) {
        console.error(e)
    }
    console.log(responses)
    fs.writeFileSync('../../../test_data.json', JSON.stringify(responses, null, 2))
}

generateTests().finally()

let currentTransmissionKey: string

function getRandomBytesProxy(length: number): Uint8Array {
    const bytes = platformRandomBytes(length)
    currentTransmissionKey = platform.bytesToBase64(bytes)
    return bytes
}

async function postProxy(
    url: string,
    payload: Uint8Array,
    headers?: { [key: string]: string }
): Promise<KeeperHttpResponse> {
    const response = await platformPost(url, payload, headers)
    responses.push({
        transmissionKey: currentTransmissionKey,
        data: platform.bytesToBase64(response.data),
        statusCode: response.statusCode
    })
    return Promise.resolve(response)
}
