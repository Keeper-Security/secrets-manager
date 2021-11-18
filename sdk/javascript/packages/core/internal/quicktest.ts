import {
    createSecret,
    downloadFile,
    getSecrets,
    initialize,
    initializeStorage,
    SecretManagerOptions,
    updateSecret
} from '../src/keeper'
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
const configFileName = 'client-config-local.json'
const clientKey = 'local.keepersecurity.com:4wqhs0M-PU3fxhS6bmo66kiAkH3wWoEETz1KPjQuEdg'

async function test() {
    const kvs = localConfigStorage(configFileName)
    await initializeStorage(kvs, clientKey)
    const options: SecretManagerOptions = {
        storage: kvs,
        // queryFunction: cachingPostFunction
        allowUnverifiedCertificate: true
    }
    const { records } = await getSecrets(options)
    // const { records } = await getSecrets(options, ['EG6KdJaaLG7esRZbMnfbFA'])
    console.log(inspect(records, false, 6))

    // const templateRecord = records[1]
    // templateRecord.data.title = 'RF14'
    // const recordUid = await createSecret(options, templateRecord.folderUid!, templateRecord.data)
    // console.log(recordUid)
    // await updateSecret(options, firstRecord)
    // const fileData = await downloadFile(response.records[0].files![0])
    // console.log(fileData)
}

test().finally()
