process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const {
    getSecrets,
    initializeStorage,
    localConfigStorage,
    downloadFile,
    updateSecret
} = require('@keeper-security/secrets-manager-core')
const fs = require("fs")

const getKeeperRecords = async () => {
    const storage = localConfigStorage("config.json")
    // if your Keeper Account is in other region than US, update the hostname accordingly
    await initializeStorage(storage, 'US:EXAMPLE_ONE_TIME_TOKEN', 'keepersecurity.com')
    const {records} = await getSecrets({storage: storage})
    // const {records} = await getSecrets({storage: storage}, ['RECORD_UID'])
    console.log(records)

    const firstRecord = records[0]
    const firstRecordPassword = firstRecord.data.fields.find(x => x.type === 'password')
    console.log(firstRecordPassword.value[0])

    const file = firstRecord.files.find(x => x.data.name === 'acme.cer')
    if (file) {
        const fileBytes = await downloadFile(file)
        fs.writeFileSync(file.data.name, fileBytes)
    }

    firstRecordPassword.value[0] = 'N3wP4$$w0rd'
    await updateSecret({storage: storage}, firstRecord)
}

getKeeperRecords().finally()
