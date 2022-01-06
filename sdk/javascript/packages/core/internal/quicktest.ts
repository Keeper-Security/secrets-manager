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

const configFileName = 'client-config-local.json'
const oneTimeToken = 'US:ONE_TIME_TOKEN'

async function test() {
    const kvs = localConfigStorage(configFileName)
    await initializeStorage(kvs, oneTimeToken)
    const options: SecretManagerOptions = {
        storage: kvs,
        // queryFunction: cachingPostFunction
        allowUnverifiedCertificate: true
    }
    const { records } = await getSecrets(options)
    // const { records } = await getSecrets(options, ['SECRET_UID'])
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
