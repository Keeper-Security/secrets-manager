import {
    downloadFile,
    getSecrets,
    initialize,
    initializeStorage,
    KeyValueStorage, updateSecret
} from '../src/keeper';
import {nodePlatform} from '../src/node/nodePlatform';
import {connectPlatform, platform} from '../src/platform';
import * as fs from 'fs';
import {inspect} from 'util';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

connectPlatform(nodePlatform)
initialize()

const configFileName = 'client-config-admin+rte.json'
const clientKey = 'Sl8gZ2A9xbR8RgwT3ylwEU_anb81EMpqnt4oU5vIZMo'

async function test() {
    const kvs = testKeyValueStorage(configFileName)
    await initializeStorage(kvs, clientKey, 'dev.keepersecurity.com')
    // const response = await getSecrets(kvs, ['i3v4ehaoB-Bwsb7bbbek2g'])
    const response = await getSecrets(kvs)
    console.log(inspect(response, false, 6))

    // response[0].data.title = response[0].data.title + '+'
    // await updateSecret(kvs, response[0])
    // const fileData = await downloadFile(response.records[0].files![0])
    // console.log(fileData)
}

const testKeyValueStorage = (configName: string): KeyValueStorage => {

    const readStorage = (): any => {
        try {
            return  JSON.parse(fs.readFileSync(configName).toString())
        }
        catch (e) {
            return {}
        }
    }

    const saveStorage = (storage: any) => {
        fs.writeFileSync(configName, JSON.stringify(storage, null, 2))
    }

    const getValue = (key: string): any | undefined => {
        const storage = readStorage()
        const keyParts = key.split('/')
        let obj = storage
        for (const part of keyParts) {
            obj = obj[part]
            if (!obj) {
                return undefined
            }
        }
        return obj.toString();
    }

    const saveValue = (key: string, value: any): void => {
        const storage = readStorage()
        const keyParts = key.split('/')
        let obj = storage
        for (const part of keyParts.slice(0, -1)) {
            if (!obj[part]) {
                obj[part] = {}
            }
            obj = obj[part]
        }
        obj[keyParts.slice(-1)[0]] = value
        saveStorage(storage)
    }

    const clearValue = (key: string): void =>  {
        const storage = readStorage()
        const keyParts = key.split('/')
        let obj = storage
        for (const part of keyParts.slice(0, -1)) {
            if (!obj[part]) {
                obj[part] = {}
            }
            obj = obj[part]
        }
        delete obj[keyParts.slice(-1)[0]]
        saveStorage(storage)
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
            }
            else {
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

test().finally()
