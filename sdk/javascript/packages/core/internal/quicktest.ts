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

// process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const version = require("../package.json").version;
connectPlatform(nodePlatform)
initialize(version)

// const configFileName = 'client-config-admin+rte.json'
// const clientKey = '122iGmGds8JSRem1aJZN1r8PNiG2a6UyoLa4j60kGcY'
const clientKey = 'US:Oc4nJ6etAQ46Rlm-HmbZHJjgOQDzTuDWpBUfvWp9SAw'
const configFileName = `client-config-${clientKey.replace(':', '_')}.json`


async function test() {
    const kvs = localConfigStorage(configFileName)
    await initializeStorage(kvs, clientKey)
    const options: SecretManagerOptions = {
        storage: kvs,
        queryFunction: cachingPostFunction
        // allowUnverifiedCertificate: true
    }
    const { records } = await getSecrets(options)
    // const { records } = await getSecrets(options, ['EG6KdJaaLG7esRZbMnfbFA'])
    console.log(inspect(records, false, 6))

    // const firstRecord = records[0]
    // firstRecord.data.title = firstRecord.data.title + '+'
    // await updateSecret(options, firstRecord)
    // const fileData = await downloadFile(response.records[0].files![0])
    // console.log(fileData)
}

test().finally()
