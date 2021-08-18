import {
    downloadFile,
    getSecrets,
    initialize,
    initializeStorage,
    SecretManagerOptions,
    updateSecret
} from '../src/keeper';
import {nodePlatform} from '../src/node/nodePlatform';
import {connectPlatform} from '../src/platform';
import {inspect} from 'util';
import {cachingPostFunction, localConfigStorage} from "../src/node";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const version = require("../package.json").version;
connectPlatform(nodePlatform)
initialize(version)

// const configFileName = 'client-config-admin+rte.json'
// const clientKey = '122iGmGds8JSRem1aJZN1r8PNiG2a6UyoLa4j60kGcY'
const configFileName = 'client-config-prod.json'
const clientKey = '9n5Yq2h4uCe-WVV0-jXjOjhETUmhTYU0xkTV3jIHUkw'

async function test() {
    const kvs = localConfigStorage(configFileName)
    // await initializeStorage(kvs, clientKey, 'keepersecurity.com')
    // const response = await getSecrets(kvs, ['i3v4ehaoB-Bwsb7bbbek2g'])
    const options: SecretManagerOptions = {
        storage: kvs,
        // queryFunction: cachingPostFunction
    }
    const { records } = await getSecrets(options)
    console.log(inspect(records, false, 6))

    const firstRecord = records[0]
    firstRecord.data.title = firstRecord.data.title + '+'
    await updateSecret(options, firstRecord)
    // const fileData = await downloadFile(response.records[0].files![0])
    // console.log(fileData)
}

test().finally()
