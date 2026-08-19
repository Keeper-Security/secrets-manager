/**
 * Prints the OAuth claim binding to register for one KSM device, as SQL.
 *
 * The binding normally arrives through the vault: app_client_add carries authType + oauthBinding, and
 * KA writes it to the device's app_client row - where its presence is what marks the client as
 * OAuth-authenticated. Until the vault client sends those fields, this script emits the equivalent
 * UPDATE so the flow can be exercised end to end.
 *
 * Usage:
 *   npx ts-node internal/oauth-binding-setup.ts <one-time-token> [subject]
 *
 * The one-time token is only used to derive the clientId (a local HMAC - nothing is sent anywhere,
 * and the token is not consumed).
 */
import {getClientId, initialize} from '../src/keeper'
import {connectPlatform} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'

connectPlatform(nodePlatform)
initialize()

// Matches the oauth constants in quicktest-split.ts and how kidp is started.
const ISSUER = 'http://localhost:8080'
// kidp stamps ISSUER into the iss claim, but KA resolves keys from inside Docker, where the host is
// reachable as host.docker.internal. Hence the explicit jwksUri: iss is an identity string, the
// jwksUri is an address, and in a split-horizon setup they are not the same.
const JWKS_URI = 'http://host.docker.internal:8080/jwks'
const AUDIENCE = 'https://keepersecurity.com/api/rest/sm'

async function main() {
    const oneTimeToken = process.argv[2]
    if (!oneTimeToken) {
        console.error('Usage: npx ts-node internal/oauth-binding-setup.ts <one-time-token> [subject]')
        process.exit(1)
    }
    // Token formats: <clientKey> | <region-or-host>:<clientKey> | IL5:<clientKey>:<keyId>:<serverKey>
    const parts = oneTimeToken.split(':')
    const clientKey = parts.length === 1 ? parts[0] : parts[1]
    const clientId = await getClientId(clientKey)
    const subject = process.argv[3] ?? 'ksm-demo'

    console.log(`clientId: ${clientId}`)
    console.log('')
    console.log('KA side - run against the keeper database:')
    console.log('')
    console.log('UPDATE app_client')
    console.log(`   SET oauth_issuer = '${ISSUER}',`)
    console.log(`       oauth_subject = '${subject}',`)
    console.log(`       oauth_audience = '${AUDIENCE}',`)
    console.log(`       oauth_jwks_uri = '${JWKS_URI}'`)
    console.log(` WHERE client_id = FROM_BASE64('${clientId}');`)
    console.log('')
    console.log(`(the subject must equal oauthClientId in quicktest-split.ts: kidp signs sub = client_id)`)
}

main().finally()
