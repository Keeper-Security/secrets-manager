import {
    downloadFile,
    getSecrets,
    initialize,
    initializeStorage,
    KeyValueStorage, updateSecret
} from '../src/keeper';
import {nodePlatform} from '../src/node/nodePlatform';
import {connectPlatform} from '../src/platform';
import * as fs from 'fs';
import {inspect} from 'util';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

connectPlatform(nodePlatform)
initialize()

const configFileName = 'client-config-admin+rte.json'
const clientKey = 'HC5aooIvPREFklD8x1v7AtT0YakXpUx7lY-wBdpINXQ'

async function test() {
    const kvs = new TestKeyValueStorage()
    await initializeStorage(kvs, clientKey, 'local.keepersecurity.com')
    // const response = await getSecrets(kvs, ['i3v4ehaoB-Bwsb7bbbek2g'])
    const response = await getSecrets(kvs)
    console.log(inspect(response, false, 6))

    // response[0].data.title = response[0].data.title + '+'
    // await updateSecret(kvs, response[0])
    // const fileData = await downloadFile(response[0].files![0])
    // console.log(fileData)
}

export class TestKeyValueStorage implements KeyValueStorage {

    readStorage(): any {
        try {
            return  JSON.parse(fs.readFileSync(configFileName).toString())
        }
        catch (e) {
            return {}
        }
    }

    saveStorage(storage: any) {
        fs.writeFileSync(configFileName, JSON.stringify(storage, null, 2))
    }

    getValue(key: string): Promise<string | undefined> {
        const storage = this.readStorage()
        const keyParts = key.split('/')
        let obj = storage
        for (const part of keyParts) {
            obj = obj[part]
            if (!obj) {
                return Promise.resolve(undefined)
            }
        }
        return Promise.resolve(obj.toString());
    }

    saveValue(key: string, value: string): Promise<void> {
        const storage = this.readStorage()
        const keyParts = key.split('/')
        let obj = storage
        for (const part of keyParts.slice(0, -1)) {
            if (!obj[part]) {
                obj[part] = {}
            }
            obj = obj[part]
        }
        obj[keyParts.slice(-1)[0]] = value
        this.saveStorage(storage)
        return Promise.resolve()
    }

    clearValues(keys: string[]): Promise<void> {
        const storage = this.readStorage()
        for (const key of keys) {
            const keyParts = key.split('/')
            let obj = storage
            for (const part of keyParts.slice(0, -1)) {
                if (!obj[part]) {
                    obj[part] = {}
                }
                obj = obj[part]
            }
            delete obj[keyParts.slice(-1)[0]]
        }
        this.saveStorage(storage)
        return Promise.resolve()
    }
}

test().finally()
