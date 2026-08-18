/**
 * Prints everything needed to wire up one KSM device for the static bearer auth prototype:
 * the bearer token for the client side, and the KSM_BEARER_CLIENTS entry for the KA side.
 *
 * Usage:
 *   npx ts-node internal/bearer-setup.ts <one-time-token> [bearer-token]
 *
 * The one-time token is only used to derive the clientId (a local HMAC - nothing is sent anywhere,
 * and the token is not consumed). When no bearer token is given, a fresh 32-byte one is generated.
 */
import {getClientId, initialize} from '../src/keeper'
import {connectPlatform} from '../src/platform'
import {nodePlatform} from '../src/node/nodePlatform'
import {createHash, randomBytes} from 'crypto'

connectPlatform(nodePlatform)
initialize()

async function main() {
    const oneTimeToken = process.argv[2]
    if (!oneTimeToken) {
        console.error('Usage: npx ts-node internal/bearer-setup.ts <one-time-token> [bearer-token]')
        process.exit(1)
    }
    // Token formats: <clientKey> | <region-or-host>:<clientKey> | IL5:<clientKey>:<keyId>:<serverKey>
    const parts = oneTimeToken.split(':')
    const clientKey = parts.length === 1 ? parts[0] : parts[1]
    const clientId = await getClientId(clientKey)
    const bearerToken = process.argv[3] ?? randomBytes(32).toString('base64url')
    const digest = createHash('sha256').update(bearerToken, 'utf8').digest('base64url')

    console.log('client side - bearerToken in quicktest-split.ts (or KSM provisioning, one day):')
    console.log(`  ${bearerToken}`)
    console.log('')
    console.log('KA side - environment variable for the KeeperApp container:')
    console.log(`  KSM_BEARER_CLIENTS='${clientId}:${digest}'`)
    console.log('')
    console.log('(multiple devices: join entries with ";")')
}

main().finally()
