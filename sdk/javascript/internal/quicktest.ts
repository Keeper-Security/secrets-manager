import {getSecret, initialize, KEY_BINDING_KEY, KEY_ID, KEY_URL, KeyValueStorage} from '../src/keeper';
import {nodePlatform} from '../src/node/nodePlatform';
import {connectPlatform, platform} from '../src/platform';
import * as fs from 'fs';
import {webSafe64ToBytes} from '../src/utils';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

connectPlatform(nodePlatform)
initialize()

const configFileName = 'client-config.json'
const bindingKey = 'LU4tfHXMyRhLqTLWkBv_33bDSG2oDKtkQFvp3GiUK7U'

async function test() {
    const kvs = new TestKeyValueStorage()
    if (!kvs.getValue(KEY_URL)) {
        kvs.saveValue(KEY_URL, 'https://local.keepersecurity.com/api/rest/sm/v1/get_secret')
    }
    if (!kvs.getValue(KEY_ID)) {
        kvs.saveValue(KEY_BINDING_KEY, bindingKey)
        const encryptionKeyHash = await platform.hash(webSafe64ToBytes(bindingKey))
        kvs.saveValue(KEY_ID, platform.bytesToBase64(encryptionKeyHash))
    }
    const response = await getSecret(kvs)
    console.log(response)
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

    getValue(key: string): string | null {
        const storage = this.readStorage()
        const keyParts = key.split('/')
        let obj = storage
        for (const part of keyParts) {
            obj = obj[part]
            if (!obj) {
                return null
            }
        }
        return obj.toString();
    }

    saveValue(key: string, value: string): void {
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
    }
}

test().finally()
