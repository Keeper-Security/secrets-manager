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
 *               subsequent calls until the admin rotates it.
 *  - 'oauth'  - same bearer wire format, but the credential is minted by an OAuth authorization
 *               server (client_credentials grant) and refreshed automatically before expiry. Run
 *               kidp (../kidp: KIDP_ISSUER=http://host.docker.internal:8080 ./gradlew :server:run)
 *               and configure KA's KSM_OAUTH_CLIENTS; see the oauth constants below.
 *  - 'ambient' - same wire format again, but the credential is one the platform already provides
 *               (kubelet-projected service account token, cloud metadata identity): the SDK just
 *               reads a file the platform maintains, and persists nothing. To simulate the platform
 *               locally, run `npx ts-node internal/project-token.ts --watch`, which mints kidp
 *               tokens into ambientTokenPath the way a kubelet re-mints a projected token.
 *
 * NOTE: the service accepts only 'native' today - the other modes demonstrate the client-side API
 * shape (an Authorizer over a TokenSource) and the token acquisition/caching behavior.
 *
 * NOTE ON THIS DEMO: both roles run in one process here, and platform key material is cached in one
 * process-global keyCache. So this file demonstrates the *storage/protocol* separation - what each
 * side persists and what crosses between them - not process isolation. In a real deployment the two
 * halves are separate processes or hosts and the bundle crosses as JSON.
 */
import {
    ambientToken,
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
    oauthClientCredentials,
    QueryOptions,
    SecretManagerOptions,
    signatureAuth,
    TokenEndpointPost
} from '../src/keeper'
import {nodePlatform} from '../src/node/nodePlatform';
import {connectPlatform, KeeperHttpResponse, KeyValueStorage} from '../src/platform';
import {inspect} from 'util';
import {localConfigStorage} from "../src/node";
import {promises as fs} from 'fs';
import {request as httpRequest} from 'http';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
process.env.KSM_AUTH_MODE = 'ambient'

const version = require("../package.json").version;
connectPlatform(nodePlatform)
initialize(version)

const authConfigFileName = 'client-config-split-auth-bearer.json'
const cryptoConfigFileName = 'client-config-split-crypto-bearer.json'
// Provisioned together when the device is added to the application:
const oneTimeToken = 'US:ONE_TIME_TOKEN'    // goes to the codec client
const bearerToken = 'BEARER_TOKEN'          // goes to the auth client (bearer mode only)

// oauth mode, against the kidp IdP (../kidp). kidp issues sub = client_id, so oauthClientId must
// match the 'sub' in KA's KSM_OAUTH_CLIENTS binding for this device's clientId.
const oauthTokenEndpoint = 'http://localhost:8080/token'
const oauthClientId = 'ksm-demo'
const oauthAudience = 'https://keepersecurity.com/api/rest/sm'

// ambient mode: the file the "platform" keeps a fresh credential in (see internal/project-token.ts).
const ambientTokenPath = 'ambient-token.jwt'

// kidp is plain http and nodePlatform.post speaks https only, so the token endpoint gets its own
// tiny transport. A real deployment would use the default (platform.post).
const httpPost: TokenEndpointPost = (url, body, headers) => new Promise<KeeperHttpResponse>((resolve, reject) => {
    const post = httpRequest(url, {method: 'POST', headers: {...headers, 'Content-Length': body.length}}, res => {
        const chunks: Buffer[] = []
        res.on('data', chunk => chunks.push(chunk))
        res.on('end', () => resolve({statusCode: res.statusCode!, headers: res.headers, data: new Uint8Array(Buffer.concat(chunks))}))
    })
    post.on('error', reject)
    post.end(Buffer.from(body))
})

// How client 1 authenticates (also settable via KSM_AUTH_MODE=bearer|oauth|ambient). The codec
// client is unaffected by this choice - decryption is the same regardless of how the ciphertext was
// fetched.
const AUTH_MODE = (process.env.KSM_AUTH_MODE ?? 'bearer') as 'bearer' | 'native' | 'oauth' | 'ambient'

const makeAuthorizer = (): Authorizer => {
    switch (AUTH_MODE) {
        case 'bearer':
            // The token is passed once, at initialization; bootstrap() persists it in the auth
            // config, and later runs may use bearerAuth() with no argument.
            return bearerAuth(bearerToken)
        case 'oauth':
            // Short-lived access tokens from the AS, cached by the source and renewed ~60s before
            // expiry. bootstrap() persists the non-secret settings; pass clientSecret (and
            // persistSecret: true to store it) when the AS requires one - the stub does not.
            return bearerAuth(oauthClientCredentials({
                tokenEndpoint: oauthTokenEndpoint,
                clientId: oauthClientId,
                audience: oauthAudience
            }, httpPost))
        case 'ambient':
            // The federated flow from federated-oauth-flow.md: the platform mints and rotates the
            // credential; nothing is persisted. JWTs are cached until shortly before their exp, so
            // the file is re-read only when the cached token is close to expiring.
            return bearerAuth(ambientToken(async () =>
                (await fs.readFile(ambientTokenPath, 'utf8')).trim()))
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
    // @ts-ignore
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
