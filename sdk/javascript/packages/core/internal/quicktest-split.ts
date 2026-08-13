/**
 * Split-role variant of quicktest.ts: the same read flow, but authentication and decryption are
 * carried out by two separate clients that never share key material.
 *
 * Client 1 (AUTH)  - holds hostname, clientId, privateKey. Signs and posts, sees only ciphertext.
 * Client 2 (CODEC) - holds hostname, clientId, appKey (and the clientKey until binding). Decrypts,
 *                    never touches the network.
 *
 * The one-time token goes to client 2 only. It derives the clientId (a non-secret hash of the client
 * key) and hands that over as an AuthBootstrap so client 1 can generate its signing key pair. Neither
 * client ever holds both the private key and the app key.
 *
 * NOTE ON THIS DEMO: both roles run in one process here, and platform key material is cached in one
 * process-global keyCache. So this file demonstrates the *storage/protocol* separation - what each
 * side persists and what crosses between them - not process isolation. In a real deployment the two
 * halves are separate processes or hosts and the bundle crosses as JSON.
 */
import {
    AuthBootstrap,
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
    SecretManagerOptions
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
const oneTimeToken = 'US:ONE_TIME_TOKEN'

// ---------------------------------------------------------------------------------------------
// Client 1: authentication only. Its whole world is an auth config plus transport options.
// ---------------------------------------------------------------------------------------------
class AuthClient {
    private readonly options: SecretManagerOptions

    constructor(private readonly storage: KeyValueStorage) {
        this.options = {
            storage: storage,
            allowUnverifiedCertificate: true
        }
    }

    // Step 2 of binding: generate the signing key pair from the non-secret bootstrap.
    async bootstrap(bootstrap: AuthBootstrap): Promise<void> {
        await initializeAuthStorage(this.storage, bootstrap)
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

    const authClient = new AuthClient(authStorage)
    const codecClient = new CodecClient(cryptoStorage)

    // --- Binding ------------------------------------------------------------------------------
    // The token never reaches the auth client.
    const bootstrap = await codecClient.bootstrap(oneTimeToken)
    await authClient.bootstrap(bootstrap)
    console.log('bootstrap handed to the auth client (no secrets in here):', bootstrap)

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
    console.log('auth   config: privateKey=%s appKey=%s clientKey=%s bound=%s',
        await has(authStorage, 'privateKey'), await has(authStorage, 'appKey'),
        await has(authStorage, 'clientKey'), await has(authStorage, 'bound'))
    console.log('codec  config: privateKey=%s appKey=%s clientKey=%s bound=%s',
        await has(cryptoStorage, 'privateKey'), await has(cryptoStorage, 'appKey'),
        await has(cryptoStorage, 'clientKey'), await has(cryptoStorage, 'bound'))

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
