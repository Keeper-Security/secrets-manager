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
const configFileName = 'client-config-dev-msp.json'
const clientKey = 'dev.keepersecurity.com:vvJTfYZj7nGPdDniLaRou1TAYIGG7_IiBgyeIKciCSs'

async function test() {
    const kvs = localConfigStorage(configFileName)
    // await initializeStorage(kvs, clientKey)
    const options: SecretManagerOptions = {
        storage: kvs,
        // queryFunction: cachingPostFunction
        allowUnverifiedCertificate: true
    }
    // const { records, warnings } = await getSecrets(options)
    const { records, warnings } = await getSecrets(options, ['CIhAuI-WuVCYVLyzFVjWwQ'])
    // const { records, warnings } = await getSecrets(options, ['EG6KdJaaLG7esRZbMnfbFA'])
    console.log(inspect(records, false, 6))
    if (warnings) {
        for (const warning of warnings) {
            console.log(warning)
        }
    }

    // const templateRecord = records[1]
    // templateRecord.data.title = 'RF14'
    // const recordUid = await createSecret(options, templateRecord.folderUid!, templateRecord.data)
    // console.log(recordUid)
    // await updateSecret(options, firstRecord)
    // const fileData = await downloadFile(response.records[0].files![0])
    // console.log(fileData)
}

test().finally()
