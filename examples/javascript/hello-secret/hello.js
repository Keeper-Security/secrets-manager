process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const getSecrets = require('@keeper/secrets-manager-core').getSecrets
const initializeStorage = require('@keeper/secrets-manager-core').initializeStorage
const awsKeyValueStorage = require('@keeper/secrets-manager-aws').awsKeyValueStorage

const bindingKey = 'YORS3cDrUGHkPhUkczAYYqoSCEuUH_GKBa2n0k2VKbY'

initializeStorage(awsKeyValueStorage, bindingKey, 'local.keepersecurity.com')
    .then(_ => getSecrets(awsKeyValueStorage))
    .then(x => console.log(x))
    .finally()
