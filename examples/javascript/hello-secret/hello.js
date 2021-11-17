process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const {
    getSecrets,
    initializeStorage,
    localConfigStorage,
    downloadFile,
    updateSecret
} = require('@keeper-security/secrets-manager-core')
const fs = require("fs")

const bindingKey = '9XJIPhkOA40-SFAA2dXQRniqfH-lzj38gec2dDh0u1U'

const getKeeperRecords = async () => {
    const storage = localConfigStorage("config.json")
    // if your Keeper Account is in other region than US, update the hostname accordingly
    await initializeStorage(storage, bindingKey, 'keepersecurity.com')
    const {records} = await getSecrets({storage: storage})
    // const {records} = await getSecrets({storage: storage}, ['UlzQ-jKQTgQcEvpJI9vxxQ'])
    console.log(records)

    const firstRecord = records[0]
    const firstRecordPassword = firstRecord.data.fields.find(x => x.type === 'password')
    console.log(firstRecordPassword.value[0])

    const file = firstRecord.files.find(x => x.data.name === 'acme.cer')
    if (file) {
        const fileBytes = await downloadFile(file)
        fs.writeFileSync(file.data.name, fileBytes)
    }

    firstRecordPassword.value[0] = 'aP1$t367QOCvL$eM$bG#'
    await updateSecret({storage: storage}, firstRecord)
}

getKeeperRecords().finally()
