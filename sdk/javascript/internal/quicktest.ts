import {getSecret, initialize} from '../src/keeper';
import {nodePlatform} from '../src/node/nodePlatform';
import {connectPlatform} from '../src/platform';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

connectPlatform(nodePlatform)
initialize()

async function test() {
    const response = await getSecret(null, {
        url: 'https://local.keepersecurity.com/api/rest/sm/v1/get_secret',
        clientSecret: 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqPnfWS6ZCcw_Ck39AMgDfMGAMta2sxTQeNHQa123JUWhRANCAASE53TMecnKpiywT83g0I9tMdLsJqO2AYDmp6nRJQhWcgEKURGVEeE429oyDMPyRW-XNCZKl7L8e1PEnaADkQj7'
    })
    console.log(Buffer.from(response.data).toString())
}

test().finally()
