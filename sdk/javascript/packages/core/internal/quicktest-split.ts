/**
 * Split-role variant of quicktest.ts: the same read flow, but authentication and decryption are
 * carried out by two separate clients that never share key material.
 *
 * Client 1 (AUTH)  - holds hostname, clientId + whatever its auth scheme needs. Posts requests,
 *                    sees only ciphertext.
 * Client 2 (CODEC) - holds hostname, clientId, appKey (and the clientKey until binding). Decrypts,
 *                    never touches the network.
 *
 * The one-time token goes to client 2 only. It derives the clientId (a non-secret hash of the client
 * key) and hands that over as an AuthBootstrap so client 1 can set up its auth scheme. Neither
 * client ever holds both the auth credential and the app key.
 *
 * AUTH SCHEMES: because client 1 is now a pure transport, its proof of identity is pluggable
 * (Authorizer). Set AUTH_MODE below:
 *  - 'native' - the shipping scheme: EC key pair generated at bootstrap, every request signed.
 *  - 'bearer' - `Authorization: Bearer <token>`. The token is generated when the device is added to
 *               the application and registered with the service alongside the encrypted app key, so
 *               the client is provisioned with two values: the bearer token (auth client) and the
 *               one-time token (codec client). The same token authenticates the first and all
 *               subsequent calls until the admin rotates it. NOTE: the service does not accept
 *               bearer yet - this demonstrates the client-side API shape only.
 *
 * NOTE ON THIS DEMO: both roles run in one process here, and platform key material is cached in one
 * process-global keyCache. So this file demonstrates the *storage/protocol* separation - what each
 * side persists and what crosses between them - not process isolation. In a real deployment the two
 * halves are separate processes or hosts and the bundle crosses as JSON.
 */
import {
    AuthBootstrap,
    Authorizer,
    bearerAuth,
    decryptFolders,
    decryptSecrets,
    EncryptedSecrets,
    fetchFolders,
    fetchSecrets,
    initialize,
    initializeAuthStorage,
    initializeCryptoStorage,
    KeeperSecrets,
    QueryOptions,
    SecretManagerOptions,
    signatureAuth
} from '../src/keeper'
import {nodePlatform} from '../src/node/nodePlatform';
import {connectPlatform, KeyValueStorage} from '../src/platform';
import {inspect} from 'util';
import {localConfigStorage} from "../src/node";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const version = require("../package.json").version;
connectPlatform(nodePlatform)
initialize(version)

const authConfigFileName = 'client-config-split-auth.json'
const cryptoConfigFileName = 'client-config-split-crypto.json'
// Provisioned together when the device is added to the application:
const oneTimeToken = 'US:ONE_TIME_TOKEN'    // goes to the codec client
const bearerToken = 'BEARER_TOKEN'          // goes to the auth client (bearer mode only)

// How client 1 authenticates (also settable via KSM_AUTH_MODE=bearer). The codec client is
// unaffected by this choice - decryption is the same regardless of how the ciphertext was fetched.
const AUTH_MODE = (process.env.KSM_AUTH_MODE ?? 'native') as 'native' | 'bearer'

const makeAuthorizer = (): Authorizer => {
    switch (AUTH_MODE) {
        case 'bearer':
            // The token is passed once, at initialization; bootstrap() persists it in the auth
            // config, and later runs may use bearerAuth() with no argument.
            return bearerAuth(bearerToken)
        default:
            return signatureAuth
    }
}

// ---------------------------------------------------------------------------------------------
// Client 1: authentication only. Its whole world is an auth config plus transport options.
// ---------------------------------------------------------------------------------------------
class AuthClient {
    private readonly options: SecretManagerOptions

    constructor(private readonly storage: KeyValueStorage, private readonly authorizer: Authorizer) {
        this.options = {
            storage: storage,
            authorizer: authorizer,
            allowUnverifiedCertificate: true
        }
    }

    // Step 2 of binding: set up the auth scheme's local state from the non-secret bootstrap
    // (native generates its key pair here; bearer persists the provisioned token).
    async bootstrap(bootstrap: AuthBootstrap): Promise<void> {
        await initializeAuthStorage(this.storage, bootstrap, this.authorizer)
    }

    // Returns ciphertext. This client cannot read any of it.
    async fetch(queryOptions?: QueryOptions): Promise<EncryptedSecrets> {
        return fetchSecrets(this.options, queryOptions)
    }

    async fetchFolders() {
        return fetchFolders(this.options)
    }
}

// ---------------------------------------------------------------------------------------------
// Client 2: decryption only. No network, no signing key - just a codec over a config.
// ---------------------------------------------------------------------------------------------
class CodecClient {
    constructor(private readonly storage: KeyValueStorage) {
    }

    // Step 1 of binding: consume the token, keep the client key, emit the non-secret bootstrap.
    async bootstrap(token: string): Promise<AuthBootstrap> {
        return initializeCryptoStorage(this.storage, token)
    }

    async decrypt(bundle: EncryptedSecrets): Promise<KeeperSecrets> {
        return decryptSecrets(this.storage, bundle)
    }

    async decryptFolders(bundle: {version: number, response: any}) {
        return decryptFolders(this.storage, bundle)
    }
}

// The bundle is JSON, so make the boundary explicit: everything client 1 hands over survives a
// round-trip through a wire format, and nothing in it is readable without the app key.
const overTheWire = (bundle: EncryptedSecrets): EncryptedSecrets => JSON.parse(JSON.stringify(bundle))

async function test() {
    const authStorage = localConfigStorage(authConfigFileName)
    const cryptoStorage = localConfigStorage(cryptoConfigFileName)

    const authClient = new AuthClient(authStorage, makeAuthorizer())
    const codecClient = new CodecClient(cryptoStorage)

    // --- Binding ------------------------------------------------------------------------------
    // The token never reaches the auth client.
    if (oneTimeToken != 'US:ONE_TIME_TOKEN') {
        const bootstrap = await codecClient.bootstrap(oneTimeToken)
        await authClient.bootstrap(bootstrap)
        console.log('bootstrap handed to the auth client (no secrets in here):', bootstrap)
    }

    // --- Read ---------------------------------------------------------------------------------
    // First fetch carries the encrypted app key; the codec client unwraps it with the client key.
    let bundle = overTheWire(await authClient.fetch())
    let secrets = await codecClient.decrypt(bundle)

    if (bundle.justBound) {
        // Same reason the single-client SDK re-fetches after binding: the binding response does not
        // carry the full record set.
        bundle = overTheWire(await authClient.fetch())
        secrets = await codecClient.decrypt(bundle)
    }

    const { records } = secrets
    console.log(inspect(records, false, 6))

    // Folders take the same shape.
    // const folders = await codecClient.decryptFolders(await authClient.fetchFolders())
    // console.log(folders)

    await showSeparation(authStorage, cryptoStorage, bundle)
}

// Prints what each side actually persists, and demonstrates that a fetched bundle carries no plaintext.
async function showSeparation(authStorage: KeyValueStorage, cryptoStorage: KeyValueStorage, bundle: EncryptedSecrets) {
    const has = async (storage: KeyValueStorage, key: string) => (await storage.getString(key)) != null
    console.log('\n--- what each side holds ---')
    console.log('auth   config: privateKey=%s bearerToken=%s appKey=%s clientKey=%s bound=%s',
        await has(authStorage, 'privateKey'), await has(authStorage, 'bearerToken'),
        await has(authStorage, 'appKey'), await has(authStorage, 'clientKey'), await has(authStorage, 'bound'))
    console.log('codec  config: privateKey=%s bearerToken=%s appKey=%s clientKey=%s bound=%s',
        await has(cryptoStorage, 'privateKey'), await has(cryptoStorage, 'bearerToken'),
        await has(cryptoStorage, 'appKey'), await has(cryptoStorage, 'clientKey'), await has(cryptoStorage, 'bound'))

    // What the auth client sees of a record: a UID, a revision, and two opaque blobs.
    const first = bundle.response.records?.[0]
    if (first) {
        console.log('\n--- a record as the auth client sees it ---')
        console.log({
            recordUid: first.recordUid,
            revision: first.revision,
            recordKey: `${first.recordKey?.slice(0, 24)}... (wrapped with the app key)`,
            data: `${first.data?.slice(0, 24)}... (encrypted with the record key)`
        })
    }
}

test().finally()
