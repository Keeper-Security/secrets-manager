import {
    ambientToken,
    bearerAuth,
    inMemoryStorage,
    KeeperHttpResponse,
    oauthClientCredentials,
    platform,
    TokenEndpointPost,
} from '../'

const storage = () => inMemoryStorage({})

// A syntactically valid JWT whose payload carries the given claims (signature is not verified
// client-side, so any third segment will do).
const makeJwt = (claims: object): string => {
    const b64url = (s: string) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    return `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify(claims))}.sig`
}

const tokenEndpoint = (
    responses: Array<{ statusCode?: number, body: object | string }>,
    requests: Array<{ url: string, body: string, headers: { [key: string]: string } }> = []
): { post: TokenEndpointPost, requests: typeof requests } => ({
    post: async (url, body, headers): Promise<KeeperHttpResponse> => {
        requests.push({url, body: platform.bytesToString(body), headers})
        const next = responses.length > 1 ? responses.shift()! : responses[0]
        const text = typeof next.body === 'string' ? next.body : JSON.stringify(next.body)
        return {
            statusCode: next.statusCode ?? 200,
            headers: {},
            data: platform.stringToBytes(text)
        }
    },
    requests
})

describe('ambientToken', () => {
    test('opaque credentials are re-read on every request', async () => {
        let reads = 0
        const source = ambientToken(async () => `opaque-${++reads}`)
        expect(await source.getToken(storage())).toBe('opaque-1')
        expect(await source.getToken(storage())).toBe('opaque-2')
    })

    test('a JWT is cached until shortly before its exp', async () => {
        let reads = 0
        const jwt = makeJwt({exp: Math.floor(Date.now() / 1000) + 3600})
        const source = ambientToken(async () => {
            reads++
            return jwt
        })
        await source.getToken(storage())
        await source.getToken(storage())
        expect(reads).toBe(1)
    })

    test('a JWT expiring within the refresh skew is re-read', async () => {
        let reads = 0
        const jwt = makeJwt({exp: Math.floor(Date.now() / 1000) + 30}) // inside the default 60s skew
        const source = ambientToken(async () => {
            reads++
            return jwt
        })
        await source.getToken(storage())
        await source.getToken(storage())
        expect(reads).toBe(2)
    })

    test('invalidate drops the cache and suggests a retry', async () => {
        let reads = 0
        const jwt = makeJwt({exp: Math.floor(Date.now() / 1000) + 3600})
        const source = ambientToken(async () => {
            reads++
            return jwt
        })
        await source.getToken(storage())
        expect(await source.invalidate!()).toBe(true)
        await source.getToken(storage())
        expect(reads).toBe(2)
    })
})

describe('oauthClientCredentials', () => {
    const config = {
        tokenEndpoint: 'https://as.example.com/oauth2/token',
        clientId: 'ksm-device-1',
        clientSecret: 's3cret',
        scope: 'ksm.read',
        audience: 'https://keepersecurity.com/api/rest/sm'
    }

    test('sends a form-encoded client_credentials request', async () => {
        const endpoint = tokenEndpoint([{body: {access_token: 'T1', token_type: 'Bearer', expires_in: 3600}}])
        const source = oauthClientCredentials(config, endpoint.post)
        expect(await source.getToken(storage())).toBe('T1')
        expect(endpoint.requests).toHaveLength(1)
        const request = endpoint.requests[0]
        expect(request.url).toBe(config.tokenEndpoint)
        expect(request.headers['Content-Type']).toBe('application/x-www-form-urlencoded')
        const params = new URLSearchParams(request.body)
        expect(params.get('grant_type')).toBe('client_credentials')
        expect(params.get('client_id')).toBe('ksm-device-1')
        expect(params.get('client_secret')).toBe('s3cret')
        expect(params.get('scope')).toBe('ksm.read')
        expect(params.get('audience')).toBe(config.audience)
    })

    test('caches by expires_in and re-acquires after invalidate', async () => {
        const endpoint = tokenEndpoint([
            {body: {access_token: 'T1', expires_in: 3600}},
            {body: {access_token: 'T2', expires_in: 3600}}
        ])
        const source = oauthClientCredentials(config, endpoint.post)
        const kvs = storage()
        expect(await source.getToken(kvs)).toBe('T1')
        expect(await source.getToken(kvs)).toBe('T1')
        expect(endpoint.requests).toHaveLength(1)
        expect(await source.invalidate!()).toBe(true)
        expect(await source.getToken(kvs)).toBe('T2')
        expect(endpoint.requests).toHaveLength(2)
    })

    test('a token expiring within the skew is not served from cache', async () => {
        const endpoint = tokenEndpoint([
            {body: {access_token: 'T1', expires_in: 30}}, // inside the default 60s skew
            {body: {access_token: 'T2', expires_in: 30}}
        ])
        const source = oauthClientCredentials(config, endpoint.post)
        const kvs = storage()
        expect(await source.getToken(kvs)).toBe('T1')
        expect(await source.getToken(kvs)).toBe('T2')
    })

    test('falls back to the JWT exp when expires_in is absent', async () => {
        const jwt = makeJwt({exp: Math.floor(Date.now() / 1000) + 3600})
        const endpoint = tokenEndpoint([{body: {access_token: jwt}}])
        const source = oauthClientCredentials(config, endpoint.post)
        const kvs = storage()
        await source.getToken(kvs)
        await source.getToken(kvs)
        expect(endpoint.requests).toHaveLength(1)
    })

    test('a response with no expiry information is not cached', async () => {
        const endpoint = tokenEndpoint([{body: {access_token: 'opaque'}}])
        const source = oauthClientCredentials(config, endpoint.post)
        const kvs = storage()
        await source.getToken(kvs)
        await source.getToken(kvs)
        expect(endpoint.requests).toHaveLength(2)
    })

    test('concurrent calls share one in-flight request', async () => {
        const endpoint = tokenEndpoint([{body: {access_token: 'T1', expires_in: 3600}}])
        const source = oauthClientCredentials(config, endpoint.post)
        const kvs = storage()
        const [a, b] = await Promise.all([source.getToken(kvs), source.getToken(kvs)])
        expect(a).toBe('T1')
        expect(b).toBe('T1')
        expect(endpoint.requests).toHaveLength(1)
    })

    test('non-200 and malformed responses are errors', async () => {
        const denied = oauthClientCredentials(config, tokenEndpoint([{statusCode: 400, body: {error: 'invalid_client'}}]).post)
        await expect(denied.getToken(storage())).rejects.toThrow('Token endpoint returned 400')
        const empty = oauthClientCredentials(config, tokenEndpoint([{body: {token_type: 'Bearer'}}]).post)
        await expect(empty.getToken(storage())).rejects.toThrow('no access_token')
        const mac = oauthClientCredentials(config, tokenEndpoint([{body: {access_token: 'T', token_type: 'mac'}}]).post)
        await expect(mac.getToken(storage())).rejects.toThrow("unsupported token_type 'mac'")
    })

    test('setup persists non-secret settings; the secret only with persistSecret', async () => {
        const kvs = storage()
        await oauthClientCredentials(config, tokenEndpoint([{body: {}}]).post).setup!(kvs)
        expect(JSON.parse((await kvs.getString('oauthConfig'))!)).toEqual({
            tokenEndpoint: config.tokenEndpoint,
            clientId: config.clientId,
            scope: config.scope,
            audience: config.audience
        })
        expect(await kvs.getString('oauthClientSecret')).toBeUndefined()

        await oauthClientCredentials({...config, persistSecret: true}, tokenEndpoint([{body: {}}]).post).setup!(kvs)
        expect(await kvs.getString('oauthClientSecret')).toBe('s3cret')
    })

    test('a no-config source runs from persisted settings', async () => {
        const kvs = storage()
        await oauthClientCredentials({...config, persistSecret: true}).setup!(kvs)
        const endpoint = tokenEndpoint([{body: {access_token: 'T1', expires_in: 3600}}])
        const source = oauthClientCredentials(undefined, endpoint.post)
        expect(await source.getToken(kvs)).toBe('T1')
        const params = new URLSearchParams(endpoint.requests[0].body)
        expect(params.get('client_id')).toBe('ksm-device-1')
        expect(params.get('client_secret')).toBe('s3cret')
    })

    test('missing settings are an error', async () => {
        const source = oauthClientCredentials(undefined, tokenEndpoint([{body: {}}]).post)
        await expect(source.getToken(storage())).rejects.toThrow('OAuth client settings are missing')
    })
})

describe('bearerAuth over a TokenSource', () => {
    const request = {encryptedTransmissionKey: new Uint8Array(), encryptedPayload: new Uint8Array()}

    test('produces the Authorization header from the source', async () => {
        const endpoint = tokenEndpoint([{body: {access_token: 'T1', expires_in: 3600}}])
        const authorizer = bearerAuth(oauthClientCredentials({
            tokenEndpoint: 'https://as.example.com/oauth2/token',
            clientId: 'c'
        }, endpoint.post))
        expect(authorizer.kind).toBe('bearer:oauth-client-credentials')
        expect(await authorizer.authorize(request, storage())).toBe('Bearer T1')
    })

    test('a callback argument behaves as an ambient credential', async () => {
        const authorizer = bearerAuth(async () => 'from-platform')
        expect(authorizer.kind).toBe('bearer:ambient')
        expect(await authorizer.authorize(request, storage())).toBe('Bearer from-platform')
        // A bearer client enrolls no key pair; the binding request carries no public key.
        expect(await authorizer.bindingPublicKey(storage())).toBeUndefined()
    })

    test('onAuthRejected invalidates the source and requests a retry when refreshable', async () => {
        const endpoint = tokenEndpoint([
            {body: {access_token: 'T1', expires_in: 3600}},
            {body: {access_token: 'T2', expires_in: 3600}}
        ])
        const kvs = storage()
        const authorizer = bearerAuth(oauthClientCredentials({
            tokenEndpoint: 'https://as.example.com/oauth2/token',
            clientId: 'c'
        }, endpoint.post))
        expect(await authorizer.authorize(request, kvs)).toBe('Bearer T1')
        expect(await authorizer.onAuthRejected!()).toBe(true)
        expect(await authorizer.authorize(request, kvs)).toBe('Bearer T2')
    })
})
