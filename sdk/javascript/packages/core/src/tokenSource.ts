import {KeeperHttpResponse, KeyValueStorage, platform} from './platform'
import {webSafe64ToBytes} from './utils'

export const KEY_BEARER_TOKEN = 'bearerToken' // The bearer credential, when the client uses the bearer auth scheme
const KEY_OAUTH_CONFIG = 'oauthConfig' // Non-secret OAuth client settings: {tokenEndpoint, clientId, scope?, audience?}
const KEY_OAUTH_CLIENT_SECRET = 'oauthClientSecret' // The OAuth client secret, persisted only on explicit opt-in

/**
 * Where a bearer credential comes from, and when it is refreshed. This is the acquisition layer
 * beneath the bearer auth scheme: the Authorizer decides *how a request proves identity*
 * (signature vs bearer header); a TokenSource decides *where the bearer credential comes from*
 * (provisioned at device creation, minted by an OAuth token endpoint, ambient in the platform).
 */
export type TokenSource = {
    // Diagnostic discriminator, e.g. 'provisioned', 'ambient', 'oauth-client-credentials'.
    kind: string
    // Called once by initializeAuthStorage: persist whatever the source needs for later runs.
    setup?(storage: KeyValueStorage): Promise<void>
    // Called per request. Implementations cache internally and refresh ahead of expiry.
    getToken(storage: KeyValueStorage): Promise<string>
    // Called when the service rejects the presented token. Drop any cache so the next getToken
    // re-acquires; return true if a retry with a fresh token is worthwhile.
    invalidate?(): Promise<boolean> | boolean
}

// Renew a cached token this long before its expiry.
export const DEFAULT_REFRESH_SKEW_SECONDS = 60

// Best-effort JWT expiry (ms since epoch); undefined for opaque tokens or malformed JWTs.
const decodeJwtExpiry = (token: string): number | undefined => {
    const parts = token.split('.')
    if (parts.length !== 3) {
        return undefined
    }
    try {
        const claims = JSON.parse(platform.bytesToString(webSafe64ToBytes(parts[1])))
        return typeof claims.exp === 'number' ? claims.exp * 1000 : undefined
    } catch {
        return undefined
    }
}

type CachedToken = {
    token: string
    expiresAt?: number // ms since epoch; undefined = does not expire as far as we know
}

const isFresh = (cached: CachedToken | undefined, skewSeconds: number): cached is CachedToken =>
    cached != null && (cached.expiresAt === undefined || Date.now() < cached.expiresAt - skewSeconds * 1000)

/**
 * A static token issued when the device was added to the application and registered with the
 * service alongside the encrypted app key. Pass the token once, at initialization - setup()
 * persists it in the auth configuration - and construct with no argument on later runs to use the
 * stored one. An explicitly passed token always wins over the stored one (that is also the
 * rotation path). Never expires client-side; rotation is the admin's action.
 */
export const provisionedToken = (token?: string): TokenSource => ({
    kind: 'provisioned',
    setup: async storage => {
        if (token) {
            await storage.saveString(KEY_BEARER_TOKEN, token)
        }
    },
    getToken: async storage => {
        const effective = token ?? await storage.getString(KEY_BEARER_TOKEN)
        if (!effective) {
            throw new Error('Bearer token is missing from the configuration')
        }
        return effective
    },
    // Re-presenting the same static token cannot succeed; the admin has to rotate it.
    invalidate: () => false
})

/**
 * A credential the runtime platform already provides - a kubelet-projected service account token,
 * a cloud metadata identity document, a SPIFFE SVID. `read` fetches the current credential; the
 * platform rotates it out of band. When the credential is a JWT its `exp` is honored (cached and
 * re-read shortly before expiry); opaque credentials are re-read on every request. Nothing is ever
 * persisted - the credential's home is the platform, not the Keeper configuration.
 */
export const ambientToken = (read: () => Promise<string>, options?: { refreshSkewSeconds?: number }): TokenSource => {
    const skew = options?.refreshSkewSeconds ?? DEFAULT_REFRESH_SKEW_SECONDS
    let cached: CachedToken | undefined
    return {
        kind: 'ambient',
        getToken: async () => {
            if (isFresh(cached, skew)) {
                return cached.token
            }
            const token = await read()
            const expiresAt = decodeJwtExpiry(token)
            // An opaque (non-JWT) credential is not cached - the read is assumed cheap and the
            // platform may rotate it at any time.
            cached = expiresAt !== undefined ? {token, expiresAt} : undefined
            return token
        },
        invalidate: () => {
            const hadCache = cached !== undefined
            cached = undefined
            // A re-read may return a newer credential the platform has already rotated in, so a
            // retry is worthwhile even if this exact read was fresh.
            return hadCache
        }
    }
}

export type OAuthClientCredentialsConfig = {
    tokenEndpoint: string // e.g. https://login.example.com/oauth2/token
    clientId: string // the OAuth client id - NOT the KSM clientId
    clientSecret?: string // omit when the token endpoint authenticates the client by other means
    scope?: string
    audience?: string // must name the KSM service so the token is useless elsewhere
    refreshSkewSeconds?: number
    // Persist clientSecret into the configuration on setup(). Off by default so the
    // federation-has-no-secrets-at-rest story stays the default posture.
    persistSecret?: boolean
}

// Transport used to reach the token endpoint. Separate from the config because it is not
// persistable; defaults to platform.post. Overridable for tests and exotic proxies.
export type TokenEndpointPost = (url: string, body: Uint8Array, headers: { [key: string]: string }) => Promise<KeeperHttpResponse>

/**
 * RFC 6749 client_credentials grant. Acquires a short-lived access token from an OAuth
 * authorization server and caches it until shortly before expiry (`expires_in` from the token
 * response, falling back to the JWT `exp`; a response with neither is not cached).
 *
 * setup() persists the non-secret settings (endpoint, client id, scope, audience) so later runs may
 * construct oauthClientCredentials() with no config; the client secret is persisted only with
 * persistSecret: true. Concurrent getToken calls share one in-flight request.
 */
export const oauthClientCredentials = (config?: OAuthClientCredentialsConfig, post?: TokenEndpointPost): TokenSource => {
    let cached: CachedToken | undefined
    let pending: Promise<string> | undefined

    const fetchToken = async (storage: KeyValueStorage): Promise<string> => {
        const storedJson = config ? undefined : await storage.getString(KEY_OAUTH_CONFIG)
        const effective: OAuthClientCredentialsConfig | undefined = config ?? (storedJson ? JSON.parse(storedJson) : undefined)
        if (!effective) {
            throw new Error('OAuth client settings are missing from the configuration')
        }
        const clientSecret = effective.clientSecret ?? await storage.getString(KEY_OAUTH_CLIENT_SECRET)
        const params = new URLSearchParams()
        params.set('grant_type', 'client_credentials')
        params.set('client_id', effective.clientId)
        if (clientSecret) {
            params.set('client_secret', clientSecret)
        }
        if (effective.scope) {
            params.set('scope', effective.scope)
        }
        if (effective.audience) {
            params.set('audience', effective.audience)
        }
        const body = platform.stringToBytes(params.toString())
        const doPost: TokenEndpointPost = post ?? ((url, data, headers) => platform.post(url, data, headers))
        const response = await doPost(effective.tokenEndpoint, body, {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        })
        const responseText = response.data ? platform.bytesToString(response.data) : ''
        if (response.statusCode !== 200) {
            throw new Error(`Token endpoint returned ${response.statusCode}: ${responseText.slice(0, 200)}`)
        }
        let tokenResponse: { access_token?: string, token_type?: string, expires_in?: number }
        try {
            tokenResponse = JSON.parse(responseText)
        } catch {
            throw new Error('Token endpoint returned a non-JSON response')
        }
        if (!tokenResponse.access_token) {
            throw new Error('Token endpoint response has no access_token')
        }
        if (tokenResponse.token_type && tokenResponse.token_type.toLowerCase() !== 'bearer') {
            throw new Error(`Token endpoint returned unsupported token_type '${tokenResponse.token_type}'`)
        }
        const expiresAt = typeof tokenResponse.expires_in === 'number'
            ? Date.now() + tokenResponse.expires_in * 1000
            : decodeJwtExpiry(tokenResponse.access_token)
        // No expiry information means no caching - re-request rather than risk a stale token.
        cached = expiresAt !== undefined ? {token: tokenResponse.access_token, expiresAt} : undefined
        return tokenResponse.access_token
    }

    return {
        kind: 'oauth-client-credentials',
        setup: async storage => {
            if (!config) {
                return
            }
            const {tokenEndpoint, clientId, scope, audience} = config
            await storage.saveString(KEY_OAUTH_CONFIG, JSON.stringify({tokenEndpoint, clientId, scope, audience}))
            if (config.persistSecret && config.clientSecret) {
                await storage.saveString(KEY_OAUTH_CLIENT_SECRET, config.clientSecret)
            }
        },
        getToken: async storage => {
            const skew = config?.refreshSkewSeconds ?? DEFAULT_REFRESH_SKEW_SECONDS
            if (isFresh(cached, skew)) {
                return cached.token
            }
            if (!pending) {
                pending = fetchToken(storage).finally(() => {
                    pending = undefined
                })
            }
            return pending
        },
        invalidate: () => {
            cached = undefined
            return true
        }
    }
}
