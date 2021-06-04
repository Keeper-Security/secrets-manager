import {
    getSecrets,
    initialize,
    initializeStorage,
    KeyValueStorage
} from '../src/keeper';
import {nodePlatform} from '../src/node/nodePlatform';
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
        const kvs = inMemoryStorage()
        await initializeStorage(kvs, clientKey, 'dev.keepersecurity.com')
        const response = await getSecrets(kvs)
        console.log(inspect(response, false, 6))
        const kvs1 = inMemoryStorage()
        await initializeStorage(kvs1, clientKey, 'dev.keepersecurity.com') // expect failure on invalid signature
        await getSecrets(kvs)
    } catch (e) {
        console.error(e)
    }
    console.log(responses)
    fs.writeFileSync('../../../test_data.json', JSON.stringify(responses, null, 2))
}

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
