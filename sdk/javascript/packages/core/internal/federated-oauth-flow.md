# KSM Federated OAuth — mock flow

**Status:** research note, now backed by a working prototype. Phases 1–3 of the auth plan are built
and were verified end-to-end on 2026-08-18 against a local KA (server-dev-env Docker, dev database)
with kidp (a sibling repo — a minimal Kotlin/Ktor test IdP) as the OAuth issuer:

- **Phase 1 (SDK):** `Authorizer` over a `TokenSource` — `provisionedToken` / `ambientToken` /
  `oauthClientCredentials` (caching, refresh-before-expiry, `token_expired` retry-once).
- **Phase 2 (KA):** static bearer digests via the `KSM_BEARER_CLIENTS` property. Verified.
- **Phase 3 (KA):** OIDC validation (JWKS fetch + cache, signature, iss/sub/aud/exp/nbf) against
  claim bindings in the `KSM_OAUTH_CLIENTS` property. Verified with client_credentials tokens.

The K8s scenario below is unchanged as the *target* design; see "How the prototype maps to this
design" and "Lessons learned" at the end for where reality differed.

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
`{iss}/.well-known/openid-configuration` (or from an explicit per-binding `jwksUri` — see Lessons),
signature + `exp`/`nbf` + `aud` verified. Then payload decrypt, clientId extraction, throttle
(unchanged).

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
  `error: "token_expired"` (`ResponseCode.token_expired`); the SDK invalidates its token cache and
  retries once. Implemented on both sides.
- **Issuer JWKS unreachable from KA**: validation fails closed; KA serves nothing on a stale key.
  Mitigations implemented: 5-minute JWKS cache with a rate-limited `kid`-miss refetch (which also
  covers an issuer restarting with a fresh key), and eviction of a *discovered* `jwks_uri` on fetch
  failure so a reconfigured issuer is re-discovered instead of failing forever.

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
zero-knowledge properties of record data. The prototype confirmed this literally: the codec client
and the codec-side config were untouched between the native, static-bearer and OAuth runs.

## How the prototype maps to this design

The prototype needed **no database changes** — two substitutions cover the gap:

- **Claim bindings / token digests live in properties**, not on the `app_client` row:
  `KSM_BEARER_CLIENTS=<clientId>:<b64url sha256(token)>[;...]` and
  `KSM_OAUTH_CLIENTS=[{"clientId","iss","sub","aud","jwksUri"?}]` (env var, `-D` property, or
  config.properties — standard KA `Property` resolution). Empty values keep both schemes rejected,
  so the code is inert unless explicitly configured.
- **The device public key slot doubles as the binding marker.** A bearer/OAuth client never has a
  key pair, but KA's binding state machine keys off `device_public_key` (enroll on call 1, clear
  `encrypted_app_key` on call 2). A stable digest stands in: `sha256(token)` for static bearer,
  `sha256("oauth|iss|sub")` for OAuth — identity-derived, so hourly token rotation does not disturb
  it. The rest of `validateAppClient` runs unchanged.

Verification order matters and differs from native: the bearer/OAuth credential is verified
**before** `validateAppClient` runs, because for these schemes the first call enrolls the digest —
enrollment must never be reachable unauthenticated. (Native enrolls its public key on a first call
authenticated only by clientId possession; the pre-registered credential is strictly stronger.)

The issuer in the prototype is kidp (`../kidp`), not a K8s cluster: an RFC 6749 client_credentials
grant where `sub` = the requested `client_id` and `aud` echoes the request. Same validation path as
the projected-JWT scenario; only the token acquisition differs (`oauthClientCredentials` source vs
`ambientToken` reading a projected file).

## Lessons learned

1. **`iss` is an identity string, not an address.** The binding's `iss` must equal what the issuer
   *stamps into tokens*, not whatever URL happens to reach it from the verifier's network position.
   With KA in Docker and the issuer on the host (split horizon: host sees `localhost:8080`, the
   container sees `host.docker.internal:8080`), the two roles must be assigned deliberately. Real
   IdPs pin one canonical https issuer URL, which is why this never surfaces outside a lab setup —
   but the provisioning UX should still validate that the entered issuer matches the discovery
   document's self-declared `issuer`.
2. **Discovery means following the document.** KA fetches `{iss}/.well-known/openid-configuration`
   and then trusts the advertised `jwks_uri` — which can point somewhere the verifier cannot reach
   if the issuer is misconfigured. Two consequences implemented: an explicit per-binding `jwksUri`
   override (decouples key fetching from the identity string; also useful for issuers without
   discovery), and eviction of cached discovery results when the JWKS fetch fails.
3. **The JWKS location must come from the binding, never the token** — a forged `iss` claim must
   not be able to steer the verifier's outbound fetch (SSRF / attacker-controlled-keys). The claim
   is *compared to* the binding, not *used*.
4. **kidp needed an `/.well-known/openid-configuration` alias**: it served only the RFC 8414 path
   (`oauth-authorization-server`), while OIDC-style verifiers (KA included) resolve the OIDC path.
   Real IdPs commonly serve both; a test IdP must too.
5. **Property plumbing is the actual failure mode in practice.** Both misfires during testing were
   configuration visibility, not protocol: an env var not set on the KA container (env is read at
   JVM start — restart required; only config.properties is re-read live), and the standing risk of
   shell quotes becoming part of the value in compose list-form env or properties files. The
   verifiers therefore log *which side* failed (entry count, clientId-not-found vs digest/claim
   mismatch — never the token), which turned every subsequent misconfiguration into a one-look
   diagnosis.
6. **Fresh-key issuers are handled by the `kid`-miss refetch.** kidp generates a new RS256 key per
   start; KA recovers without restarts because an unknown `kid` triggers one rate-limited JWKS
   refetch. That behavior doubles as routine key-rotation support.
