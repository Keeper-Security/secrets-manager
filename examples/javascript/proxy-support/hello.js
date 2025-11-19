process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const {
    getSecrets,
    initializeStorage,
    localConfigStorage,
    setCustomProxyAgent
} = require('@keeper-security/secrets-manager-core')
const { HttpsProxyAgent } = require('https-proxy-agent')

const getKeeperRecords = async () => {
    // Set you proxy URL
    setCustomProxyAgent(new HttpsProxyAgent('http://user:password@127.0.0.1:3128'))

    const storage = localConfigStorage("config.json")

    // if your Keeper Account is in other region than US, update the hostname accordingly
    await initializeStorage(storage, 'US:EXAMPLE_ONE_TIME_TOKEN', 'keepersecurity.com')
    const {records} = await getSecrets({storage: storage})

    // const {records} = await getSecrets({storage: storage}, ['RECORD_UID'])
    console.log(records)
}

getKeeperRecords().finally()
