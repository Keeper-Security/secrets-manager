process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const {getSecrets, initializeStorage, localConfigStorage} = require('@keeper-security/secrets-manager-core')

const bindingKey = 'B8C-9WWPtOt5zTygab92az0O28yAbkI-Oc6e2CXAgBE'

const getKeeperRecords = async () => {
    const storage = localConfigStorage("config.json")
    await initializeStorage(storage, bindingKey, 'keepersecurity.com')
    const {records} = await getSecrets({storage: storage})
    // const {records} = await getSecrets({storage: storage}, ['UlzQ-jKQTgQcEvpJI9vxxQ'])
    console.log(records)

    const password = records[0].data.fields.find(x => x.type === 'password').value[0]
    console.log(password)
}

getKeeperRecords().finally()
