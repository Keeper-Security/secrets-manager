import {getSecret, initialize} from '../src/keeper';
import {nodePlatform} from '../src/node/nodePlatform';
import {connectPlatform} from '../src/platform';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

connectPlatform(nodePlatform)
initialize()

async function test() {
    const response = await getSecret(null, {
        url: 'https://local.keepersecurity.com/api/rest/sm/v1/get_secret'
    })
    console.log(Buffer.from(response.data).toString())
}

test().finally()
