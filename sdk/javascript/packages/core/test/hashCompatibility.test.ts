import {nodePlatform} from '../src/node/nodePlatform'
import {browserPlatform} from '../src/browser/browserPlatform'

// hash() is HMAC-SHA512 keyed by `data`, over the message `tag`, and not the other way round.
// The client id every SDK sends at binding time is that digest, so what this file pins is wire
// format shared with the Python, Java, .NET, Go, Rust and Ruby SDKs, not a Node-local detail.
const CLIENT_ID_HASH_TAG = 'KEEPER_SECRETS_MANAGER_CLIENT_ID'

// A pinned digest rather than one recomputed with the same crypto call the implementation makes:
// a recomputed expectation drifts along with the implementation, and this value must not drift.
// Cross-checked against the Python SDK's
// hmac.new(client_key_bytes, b'KEEPER_SECRETS_MANAGER_CLIENT_ID', 'sha512').
test('hash produces the client id digest the other SDKs produce for the same client key', async () => {
    const clientKey = Buffer.from('0123456789abcdef0123456789abcdef', 'hex')
    const digest = await nodePlatform.hash(clientKey, CLIENT_ID_HASH_TAG)
    expect(Buffer.from(digest).toString('hex')).toBe(
        'e25a52879c9913c1ee272ea381e6fab73ad219a61f45fe74633dfa37496b187b' +
        '7b1c3d1fafdf1ab8738a4e5802b80d3acbb5356c6c54884b8e2fdc46e8e79f5e')
})

// The guard against a Node hash() that ignores its tag again. Every call site inside the SDK
// passes CLIENT_ID_HASH_TAG, so an implementation that hardcoded that string would still agree
// with the browser everywhere the SDK itself looks; only a tag the code does not contain
// separates the two. A caller outside the SDK is free to pass one.
test('node and browser hash agree on a tag the SDK does not use internally', async () => {
    const data = new TextEncoder().encode('client-key-bytes')
    const tag = 'SOME_OTHER_TAG'
    const nodeDigest = await nodePlatform.hash(data, tag)
    const browserDigest = await browserPlatform.hash(data, tag)
    expect(Buffer.from(nodeDigest).equals(Buffer.from(browserDigest))).toBe(true)
})
