/**
 * The OAuth read flow, minimal. Two configurations, and neither holds what the other needs:
 *
 *   auth  - hostname + clientId only. Authenticates with a JWT from the IdP, fetches ciphertext.
 *   codec - holds the app key. Decrypts the fetched bundle; never touches the network.
 *
 * Prerequisites:
 *   1. kidp running as the IdP:   cd ../../../../../kidp && ./gradlew :server:run
 *   2. the device's claim binding registered on its app_client row - the SQL is printed by
 *      `npx ts-node internal/oauth-binding-setup.ts <one-time-token>`
 *   3. oneTimeToken below set, for the first run only (binding is one-time; blank it out afterwards)
 *
 * Run:  npm run quicktest-oauth
 *
 * See quicktest-split.ts for the same flow with the native and ambient schemes alongside, and for
 * what each side does and does not hold.
 */
import {
    bearerAuth,
    decryptSecrets,
    fetchSecrets,
    initialize,
    initializeAuthStorage,
    initializeCryptoStorage,
    oauthClientCredentials,
    SecretManagerOptions,
    TokenEndpointPost
} from '../src/keeper'
import {connectPlatform} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'
import {localConfigStorage} from '../src/node'
import {inspect} from 'util'

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

connectPlatform(nodePlatform)
initialize(require('../package.json').version)

const authStorage = localConfigStorage('client-config-split-auth-oauth.json')
const cryptoStorage = localConfigStorage('client-config-split-crypto-oauth.json')
const oneTimeToken = 'US:ONE_TIME_TOKEN'

// kidp speaks plain http and nodePlatform.post is https-only, so the token endpoint gets its own
// transport. Against a real authorization server this argument is omitted.
const tokenEndpointPost: TokenEndpointPost = async (url, body, headers) => {
    // The body is form-encoded text, so hand fetch a string rather than fighting BodyInit typing.
    const response = await fetch(url, {method: 'POST', headers, body: Buffer.from(body).toString()})
    return {
        statusCode: response.status,
        headers: response.headers,
        data: new Uint8Array(await response.arrayBuffer())
    }
}

// kidp signs sub = client_id, so clientId here must match the subject in the registered binding.
const authorizer = bearerAuth(oauthClientCredentials({
    tokenEndpoint: 'http://localhost:8080/token',
    clientId: 'ksm-demo',
    audience: 'https://keepersecurity.com/api/rest/sm'
}, tokenEndpointPost))

const options: SecretManagerOptions = {
    storage: authStorage,
    authorizer: authorizer,
    allowUnverifiedCertificate: true
}

async function test() {
    if (oneTimeToken !== 'US:ONE_TIME_TOKEN') {
        // The token goes to the codec client only; the auth client gets the non-secret bootstrap.
        const authBoostrap = await initializeCryptoStorage(cryptoStorage, oneTimeToken)
        await initializeAuthStorage(authStorage, authBoostrap, authorizer)
    }

    let bundle = await fetchSecrets(options)
    let secrets = await decryptSecrets(cryptoStorage, bundle)
    if (bundle.justBound) {
        // The binding response does not carry the full record set, so fetch once more.
        bundle = await fetchSecrets(options)
        secrets = await decryptSecrets(cryptoStorage, bundle)
    }

    console.log(inspect(secrets.records, false, 6))
}

test().finally()
