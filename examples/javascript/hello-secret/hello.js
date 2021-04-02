process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const getSecret = require('keeper-secrets-manager').getSecret

getSecret(null, {    url: 'https://local.keepersecurity.com/api/rest/sm/v1/get_secret'})
    .then(x => console.log(x))
    .finally()

