# KSM Federated OAuth — mock flow

**Status:** research note. Describes the end-to-end flow that becomes possible after Phase 3 of the
auth plan (server-side OIDC validation + claim-binding provisioning). Client-side, it builds on the
`Authorizer` / `bearerAuth` / auth-codec split already prototyped in this package; nothing here
requires SDK changes beyond the planned `TokenSource` layer (Phase 1).

**Scenario:** a `billing-api` pod in a Kubernetes cluster needs secrets from the KSM app
**payments-prod**. No Keeper-issued secret ever exists inside the pod's auth container.

## Cast

| Actor | Holds |
|---|---|
| Admin (vault/Commander) | app key (a vault user — the party that encrypts it for delivery) |
| K8s platform | the pod's identity; issues + auto-rotates projected JWTs; publishes JWKS at its OIDC issuer URL |
| Auth client (container 1) | `hostname`, `clientId` — **nothing secret** |
| Codec client (container 2) | `clientKey`, later `appKey` |
| KA | claim binding, JWKS cache, app-key ciphertext |

## Sequence

```mermaid
sequenceDiagram
    participant Admin as Admin (vault)
    participant Codec as Codec client<br/>(container 2)
    participant Auth as Auth client<br/>(container 1)
    participant KA as Keeper (KA)
    participant K8s as K8s platform<br/>(kubelet + OIDC issuer)

    rect rgb(245, 245, 245)
    note over Admin, KA: A — Provisioning (admin, once)
    Admin->>KA: device row, auth = oauth_federated · claim binding {iss, sub, aud}
    Admin->>KA: encrypted_app_key = AES-GCM(appKey, clientKey)
    Admin->>Codec: one-time token (carries clientKey)
    end

    note over Codec, Auth: B — Initialization (once per client)
    Codec->>Codec: clientId = HMAC(clientKey)
    Codec->>Auth: AuthBootstrap {clientId, hostname} — nothing secret
    Auth->>Auth: entire config: {hostname, clientId}

    rect rgb(245, 245, 245)
    note over Auth, K8s: C — First fetch (binding)
    K8s->>Auth: projected JWT (aud = ksm, exp ≈ 1 h)
    Auth->>KA: POST get_secret · Bearer JWT<br/>encrypted payload {clientVersion, clientId} — no publicKey
    KA->>K8s: fetch JWKS (cached)
    KA->>KA: verify sig · exp · aud, match iss + sub ↔ stored binding
    KA->>Auth: ciphertext records + encryptedAppKey (first call only)
    Auth->>Codec: EncryptedSecrets bundle — JSON, still ciphertext
    Codec->>Codec: unwrap appKey with clientKey · delete clientKey
    Codec->>Codec: record keys → plaintext records
    end

    note over Auth, K8s: D — Steady state (every fetch)
    K8s-->>Auth: kubelet re-mints JWT (~hourly — no admin, no restart)
    Auth->>KA: Bearer fresh JWT
    KA->>Auth: ciphertext only (row bound after 2nd call)
    Auth->>Codec: bundle → plaintext
```

## Phase A — Provisioning (admin, once)

**A1.** Admin adds a device to *payments-prod*, auth type **OAuth (federated)**, and enters the
claim binding:

```
issuer:   https://oidc.eks.us-east-1.amazonaws.com/id/4F0E...        (cluster's OIDC issuer)
subject:  system:serviceaccount:payments:billing-api
audience: https://keepersecurity.com/api/rest/sm                     (fixed KSM audience)
```

**A2.** Vault generates the OTT client key as today, derives `clientId = HMAC(clientKey)`, and
pushes the `app_client` row: `clientId`, `auth_type = oauth_federated`, the claim binding, and
`encrypted_app_key = AES-GCM(appKey, clientKey)`. *Delta from static bearer: a claim binding is
stored where the token digest would have been. App-key delivery is completely unchanged.*

**A3.** Two things leave the admin's hands, to two different places:

- **OTT** `US:AbC123…` → codec container's secret store
- nothing to the auth container — its credential is ambient. The pod spec just projects a token:

```yaml
volumes:
- projected:
    sources:
    - serviceAccountToken:
        path: keeper-token
        audience: https://keepersecurity.com/api/rest/sm
        expirationSeconds: 3600        # kubelet re-mints it automatically
```

## Phase B — Initialization (each client, once)

**B4.** Codec: `initializeCryptoStorage(cryptoStorage, oneTimeToken)` → stores `clientKey`, derives
`clientId`, emits the bootstrap.

**B5.** Bootstrap `{clientId, hostname}` crosses to the auth container (it's non-secret; a
ConfigMap is fine).

**B6.** Auth:

```ts
const authorizer = bearerAuth(ambientToken(() =>
    fs.readFile('/var/run/secrets/tokens/keeper-token', 'utf8')))
await initializeAuthStorage(authStorage, bootstrap, authorizer)
```

Auth config after this, in its entirety: `{"hostname": "keepersecurity.com", "clientId": "abc…"}`.
`setup()` had nothing to persist — compare native (private key) or static bearer (token).

## Phase C — First fetch (binding)

**C7.** `fetchSecrets(options)` → `ambientToken` reads the projected JWT:

```json
{ "iss": "https://oidc.eks.us-east-1.amazonaws.com/id/4F0E...",
  "sub": "system:serviceaccount:payments:billing-api",
  "aud": ["https://keepersecurity.com/api/rest/sm"],
  "exp": 1765731600 }
```

**C8.** On the wire — payload has **no `publicKey`** (`bindingPublicKey → undefined`); transport
envelope identical to today:

```
POST /api/rest/sm/v1/get_secret
PublicKeyId: 10
TransmissionKey: <32-byte key, ECIES-encrypted to Keeper's server key>
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6...

<AES-GCM({clientVersion, clientId}, transmissionKey)>
```

**C9.** KA filter: transmission key decrypt + IV replay check (unchanged) → sees `Bearer` → **new
path**: issuer must be on the app's allowlist, JWKS fetched/cached from
`{iss}/.well-known/openid-configuration`, signature + `exp`/`nbf` + `aud` verified. Then payload
decrypt, clientId extraction, throttle (unchanged).

**C10.** KA rest: row for `clientId` says `oauth_federated` → compare token's `iss`/`sub` to the
stored binding. Match ⇒ authenticated. `verifySignature` is never called for this row.
`encrypted_app_key` still present ⇒ include it in the response; audit `app_client_connected`.
*Note what's better than native here: native's first call is authenticated only by clientId
possession; this first call carries a fully verified identity.*

**C11.** Auth client strips the transmission envelope → `EncryptedSecrets` bundle (ciphertext +
`justBound: true`) → hands it to the codec container.

**C12.** Codec: `decryptSecrets` unwraps `appKey` with `clientKey`, deletes `clientKey`, decrypts
record keys → records. Codec config now: `{hostname, clientId, appKey, appOwnerPublicKey}`.

## Phase D — Steady state

**D13.** Every subsequent fetch = C7–C12 minus the app-key parts; on the second call KA clears
`encrypted_app_key` (row fully bound, same state machine as today).

**D14.** ~Hourly, kubelet re-mints the projected token. Nobody notices: `ambientToken` reads the
file per request (or caches until `exp` minus skew). **Rotation involves no Keeper admin, no SDK
restart, no config change.**

**D15.** Revocation: admin deletes the device row, or platform-side deletes/renames the
ServiceAccount — next token no longer matches `sub`. Blast radius of a fully compromised auth
container: ciphertext + impersonation *while the platform keeps issuing it tokens* — never
plaintext, never the app key.

## Failure modes

- **Token expired mid-flight** (read at 59:59): KA returns 401 with a distinct
  `error: "token_expired"`; SDK re-reads the source and retries once — a Phase 1 SDK detail to
  remember.
- **Issuer JWKS unreachable from KA**: validation fails closed; KA serves nothing on a stale key.
  Cache TTL + `kid`-miss refetch is the standard mitigation.

## At rest, who holds what

| Actor | Holdings |
|---|---|
| Admin vault | `appKey` — encrypts it for delivery at provisioning |
| Codec container | `clientKey` until first fetch, then `appKey` |
| Auth container | **no secret** — `hostname` + `clientId` only |
| K8s platform | issuer signing keys, behind the cluster OIDC endpoint |
| Keeper (KA) | claim binding + ciphertext; `encrypted_app_key` until bound |

## Key observation

Steps **C11–C12 are identical in every auth scheme**. The entire OAuth story happens on the
transport side of the bundle hand-off, which is exactly what the auth/codec split was for: swapping
native / bearer / OAuth changes nothing about how secrets are decrypted, and cannot affect the
zero-knowledge properties of record data.
