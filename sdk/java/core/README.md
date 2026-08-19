## Keeper Secrets Manager Java SDK

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/java-sdk

# Change Log

## 17.4.0
**Breaking Changes**
- `deleteFolder()` returns `SecretsManagerDeleteFolderResponse` instead of `SecretsManagerDeleteResponse`. The new type exposes a `folders` list, where each entry has `folderUid`, `responseCode`, and an optional `errorMessage`; callers that read `.records` on the old return type must switch to `.folders`. In practice no working code can be affected: the old return type required a `records` field while the backend sends `folders`, so every previous call to `deleteFolder()` threw `MissingFieldException` instead of returning a value.
- `KeeperRecord` gained a constructor parameter (`isEditable`) and `SecretsManagerOptions` gained three (`connectTimeoutMillis`, `readTimeoutMillis`, `proxyUrl`). Recompiling is enough: Kotlin source needs no edit, and Java call sites keep every constructor form published in 17.3.0 because both types carry `@JvmOverloads`. What does change is bytecode-level. The generated `copy()` methods and the synthetic constructor Kotlin emits for omitted default arguments both changed arity, so Kotlin code compiled against 17.3.0 throws `NoSuchMethodError` if the 17.4.0 jar is swapped in without recompiling. Rebuild dependents against 17.4.0 rather than replacing the jar in place.

- KSM-531 - Add HTTP/HTTPS proxy support
  - New `proxyUrl` option on `SecretsManagerOptions`, e.g. `SecretsManagerOptions(storage, proxyUrl = "http://proxy.local:8080")`. Java callers can also use `SecretsManagerOptions.withProxy(storage, "http://proxy.local:8080")`.
  - Authenticated proxies use the `http://user:password@host:port` URL form. Reserved characters in the password can be percent-encoded (e.g. `p%40ss` for `p@ss`).
  - Applies to secret queries (`getSecrets`), file uploads (`uploadFile`), and file downloads. File downloads require the options-taking overloads: `downloadFile(options, file)` and `downloadThumbnail(options, file)`. The single-argument forms `downloadFile(file)` and `downloadThumbnail(file)` use ambient proxy settings (`HTTPS_PROXY`, `https.proxyHost`, etc.) but do not pick up `allowUnverifiedCertificate` from options. Notation lookups that resolve file attachments (`getValue`) use ambient proxy settings but cannot carry `options.proxyUrl`; use `getNotationResults(options, notation)` for explicit-proxy-aware notation resolution.
  - **Upgrade note:** 17.4.0 makes all SDK connections honour `HTTPS_PROXY` and `https.proxyHost` environment variables and JVM system properties that the SDK previously ignored. Deployments running in containers or environments where these variables are set for other tools should verify the values before upgrading.
  - When `proxyUrl` is not set, the SDK checks JVM system properties (`https.proxyHost`/`https.proxyPort`) then the `HTTPS_PROXY`/`https_proxy` environment variables; `NO_PROXY`/`no_proxy` and `http.nonProxyHosts` exclusions are honored. `HTTP_PROXY` is intentionally excluded: all KSM traffic is HTTPS and an http-scoped setting would route traffic the operator may not have intended.
  - Credentials found in ambient environment variables (`HTTPS_PROXY`) are detected but not registered with the JVM `Authenticator`. Registering the global `Authenticator` from ambient env values would silently interfere with other libraries in the same process. To use authenticated proxy credentials, pass them explicitly via the `proxyUrl` field in `SecretsManagerOptions`.
  - **Authenticated proxies require a JVM startup flag in most applications.** Java disables Basic auth over HTTPS CONNECT tunnels by default (`jdk.http.auth.tunneling.disabledSchemes`, a CVE-2016-5597 mitigation), and that default locks in the first time `java.net.HttpURLConnection` is loaded — which any HTTP or HTTPS connection can trigger — before this SDK gets a chance to run. The SDK does clear it automatically when proxy credentials are supplied, but that only works if the SDK's proxied call happens to be the very first connection in the JVM, which is not the common case in a real application. If you use an authenticated proxy, set this **before your application makes any other HTTP or HTTPS call**:
    - Command line: `-Djdk.http.auth.tunneling.disabledSchemes=`
    - Environment variable (Java 9+): `JDK_JAVA_OPTIONS=-Djdk.http.auth.tunneling.disabledSchemes=`
    - Environment variable (Java 8): `_JAVA_OPTIONS=-Djdk.http.auth.tunneling.disabledSchemes=` or `JAVA_TOOL_OPTIONS=-Djdk.http.auth.tunneling.disabledSchemes=`

    If this is not set in time, the SDK throws a `SecretsManagerException` with this exact remediation in the message rather than surfacing a bare 407, so the failure is loud and actionable, not a silent/confusing auth error.
  - Proxy credentials are supplied via a default `java.net.Authenticator` scoped to the configured proxy host, re-asserted on every proxied connection. Applications that install their own default `Authenticator` should pass proxy credentials through that mechanism instead.
  - `cachingPostFunction` cannot carry `options.proxyUrl`; ambient proxies (`HTTPS_PROXY`, `https.proxyHost`) still apply. To use an explicit `proxyUrl`, use the default query path instead.
  - `cachingPostFunction` now prints a warning to stderr when it falls back to stale cached data.
This output is unconditional and not gated by `loggingEnabled`, because the function has no access to `SecretsManagerOptions`.
KSM-1298 tracks the proper fix for the next release.
  - `allowUnverifiedCertificate` now applies to file downloads and uploads when using the options-taking overloads, in addition to secret queries. Deployments that set this flag should be aware that certificate verification is now bypassed on all SDK outbound connections when it is enabled.
- KSM-1081 - Fixed `getFolders()` crashing when any folder in the response has a corrupted or missing key. The SDK now skips undecryptable folders and returns the remaining folders normally. The skipped-folder diagnostic names the exception type and is suppressed when `loggingEnabled` is false.
- KSM-1086 - Fixed `deleteFolder()` to return `SecretsManagerDeleteFolderResponse` (typed per-folder status), matching `deleteSecret()`. Both `deleteFolder()` and `deleteSecret()` now report per-item server failures to stderr, gated on `loggingEnabled`, and include them in the return value so callers can detect partial failures.
- KSM-1176 - `KeeperRecord` now exposes `isEditable: Boolean`, forwarded from the server response envelope. Callers can inspect this field before calling `updateSecret` to determine whether the app has write permission for the record. The field is the last constructor parameter and `KeeperRecord` carries `@JvmOverloads`, so Java code that constructs a record positionally, and Kotlin code that destructures one, are unaffected.
- KSM-1203 - Fixed `generatePassword` using a non-cryptographic PRNG (Kotlin `Random.Default`) for the final character shuffle. The shuffle now uses `SecureRandom`, so the entire password generation path is cryptographically secure. Passwords already generated do not need to be rotated: character selection always drew from `SecureRandom`, so only the arrangement of already-secret characters was affected, and the strength that remained is far beyond brute-force reach (for `generatePassword(32, 8, 8, 8, 8)`, roughly 137 of the 193 bits were never at risk, and the default `generatePassword()` was unaffected because all of its characters come from a single character set).
- KSM-1207 - Fixed all `HttpsURLConnection` calls defaulting to an infinite timeout. Added `connectTimeoutMillis` (default 5 000 ms) and `readTimeoutMillis` (default 30 000 ms) to `SecretsManagerOptions`. A stalled or unresponsive server now causes a `SocketTimeoutException` rather than an indefinite hang. The configured values apply to API requests and to the file upload transport. `downloadFile()` and `downloadThumbnail()` take only a `KeeperFile`, so they apply the built-in defaults rather than the values configured on `SecretsManagerOptions`. A custom `queryFunction` supplies its own transport and is responsible for its own timeouts.
- KSM-1248 - Server-supplied key IDs are validated against the embedded public key table before being stored. An unrecognized key ID throws `SecretsManagerException` and leaves storage unchanged. Key rotation retries are now capped at `MAX_KEY_ROTATION_RETRIES` (3); exhausted retries throw a typed error naming the last suggested key ID.
- KSM-1262 - On POSIX systems, config and cache files are now written via a temp-file swap with 0600 permissions set before data is written, closing the window where other local users could read the file during a write. Three behavior changes come with the new approach: (1) a symlinked config path is replaced by a regular file on the first write; (2) a config file in a directory without write permission (for example, a read-only container volume mount) will fail at temp-file creation, so move the config to a writable directory or use `InMemoryStorage` with an injected config string instead; (3) the config file is now read as UTF-8 explicitly, where it was previously read using the JVM default charset while always being written as UTF-8. A write that cannot be staged now reports what the file system returned and retains the original `IOException` as the exception cause, and `SecretsManagerException` gained a `(message, cause)` constructor to carry it.
- KSM-1269 - Fixed the Java CI workflow not running on pull requests targeting release branches.
The test matrix now triggers on both `master` and `release/sdk/java/core/**` targets.
- KSM-1270 - Fixed `getSharedFolderKey` looping indefinitely when server folder data contains a parent cycle. The function now tracks visited folder UIDs and exits on re-visit; `getFolders` skips the affected folders and continues normally.

## 17.3.0
**Breaking Changes**
- `KeeperFile.url` changed from `String` to `String?` — callers that access `url` directly must now handle null; `downloadFile()` already does this with a typed exception
- `KeeperRecordData.custom` changed from `MutableList<KeeperRecordField>?` to `MutableList<KeeperRecordField>` — assigning `null` to this field will no longer compile; use an empty list instead
- `KEY_SERVER_PUBIC_KEY_ID` is deprecated — replace with `KEY_SERVER_PUBLIC_KEY_ID` (corrected spelling); the old name is retained as a `@Deprecated` alias for back-compatibility

- KSM-878 - Throttle retry with exponential backoff
  - Automatically retries HTTP 403 `{"error":"throttled"}` responses up to 5 times (`MAX_THROTTLE_RETRIES`)
  - Exponential backoff starting at 11s (1s margin over the backend's 10s memcached TTL), with one-sided 0-25% jitter (delay never undercuts the server's requested `retry_after`); uses `retry_after` from the response body when present, capped at 176s (`MAX_THROTTLE_DELAY_SEC`)
  - Warning logged to stderr on each retry (gated on `loggingEnabled`)
  - Exhausted retries throw `KeeperThrottleException` (public; catchable separately from generic `Exception`)
  - Injectable `throttleSleepMillis` hook in `SecretsManagerOptions` for test overrides
- KSM-1008 - Align `KeeperRecordLink` accessors with Python reference
  - Recursive `jsonElementToValue`/`jsonObjectToMap` helpers preserve JSON nulls (lossless, matching Python SDK)
  - `getLinkData()` now returns `Map<String, Any?>` with typed scalars (String/Boolean/Int/Long/Double); nested objects and arrays are preserved
  - `getBooleanValue` checks the nested `allowedSettings` object for permission flags in `path:"meta"` links when `checkAllowedSettings = true`; accessors for `allowsRotation()`, `allowsConnections()`, etc. updated accordingly
  - Added `KeeperRecordLinkTest` suite covering all accessors, nested structures, and null preservation
- KSM-1066 - Fix IL5 custom server public key not persisted by LocalConfigStorage
  - `serverPublicKey` is now saved to and loaded from the on-disk config alongside `serverPublicKeyId`
  - Without this fix, a second run after IL5 bind failed with "Key number X is not supported" because the key ID was stored but the key bytes were not
- KSM-1067 - Fix IL5 stale-key diagnostic message swallowed by bare catch
  - The actionable "Server rejected the custom server public key" error now propagates to callers instead of being swallowed
- KSM-902 - Add IL5 (DoD Impact Level 5) region mapping and dynamic server public key injection
  - Region: `IL5` OTT prefix maps to `il5.keepersecurity.us`
  - Layer 1 (config field): `serverPublicKey` in storage config overrides the embedded key table
  - Layer 2 (extended OTT): 4-segment `REGION:clientKey:keyId:serverPublicKey` saves key and ID on bind
  - Layer 3 (constructor param): `SecretsManagerOptions(serverPublicKey = "...", serverPublicKeyId = "...")` persists both to storage
  - When a custom key is configured, a server key-rotation hint throws a clear error rather than silently overwriting the custom key ID
  - Note: the storage constant for the key ID is `KEY_SERVER_PUBLIC_KEY_ID`
- KSM-823 - Fix `custom` field omitted from record create payload when no custom fields are set
  - `KeeperRecordData.custom` now defaults to `mutableListOf()` instead of `null` — `kotlinx-serialization` previously skipped null fields, causing `"custom"` to be absent from the V3 API payload
  - Consistent with Commander and Vault which always include `"custom": []`
- KSM-854 - Fix `KeeperFileData` crash when `lastModified` field is absent from file metadata
  - Files uploaded by non-SDK Keeper clients (iOS, Android, Web Vault) may omit `lastModified`
  - Previously threw `MissingFieldException` and silently skipped the file attachment
  - Now defaults to `0` when the field is absent, consistent with .NET SDK behavior (KSM-674)
- KSM-753 - Fix record key decryption for shared folder records in flat `response.records[]`
  - Records created via Commander/PowerShell in shared folders have their key encrypted with the folder key, not the app key
  - SDK previously always used the app key for flat records, causing all field values to return null
  - Now detects `innerFolderUid` and decrypts using the correct folder key
- KSM-765 - Fix NPE crash when `url` field is absent from file response
  - `KeeperFile.url` is now `String?` (nullable); server may omit it for files without a download URL
- KSM-855 - Fix file descriptor leaks in `LocalConfigStorage` and HTTP connections
  - `LocalConfigStorage`: replaced manual `stream.close()` calls with Kotlin `.use { }` in 4 locations — streams previously leaked on any I/O exception, and the init block never closed its reader at all
  - `downloadFile`, `uploadFile`, `postFunction`: `HttpsURLConnection` is now explicitly disconnected in a `finally` block; `with()` is not try-with-resources and did not guarantee cleanup on exception
- KSM-985 - Add typed empty-string guard to internal Base64 decoders (KSM-808 parity)
  - `base64ToBytes("")` and `webSafe64ToBytes("")` now throw a `Keeper` exception instead of an opaque NPE from inside `java.util.Base64`
- KSM-1026 - Make `SecretsManagerException` public
  - Java consumers can now `catch (SecretsManagerException e)` to handle SDK-level errors by type instead of catching bare `Exception`
  - `SecureRandomException` / `SecureRandomSlowGenerationException` remain internal (no public use case)

## 17.2.0
- **SECURITY (KSM-699)** - Fix file permissions for config.json and cache.dat
  - Config and cache files now created with 0600 permissions (owner read/write only)
  - Fixes vulnerability where sensitive data was world-readable
  - Existing config files retain permissions until SDK modifies them
  - New files created with owner-only permissions (0600 on Unix, equivalent on Windows)
  - Multi-user workflows sharing config files will need to manage permissions manually
- KSM-733 - Fix notation error with duplicate UIDs from shortcuts
  - When an application has access to both an original record and its shortcut, the same UID appears multiple times in getSecrets() response
  - Now deduplicates by UID to keep only the first occurrence
  - Title-based lookups still correctly detect genuine ambiguity (multiple records with same title)
- KSM-742 - Add transmission public key #18 for Gov Cloud Dev support
- chore - Upgrade gradle-build-action to setup-gradle@v4

## 17.1.3
- KSM-738 - Add missing PAM connection settings fields (61 new fields for VAUL-7662)
  - PamRbiConnection: Add audio/clipboard controls (disableAudio, disableCopy, disablePaste, audioChannels, audioBps, audioSampleRate)
  - PamSettingsConnection: Add protocol-specific fields (SSH/Terminal, VNC, RDP, Kubernetes)
  - PamSettingsPortForward: Add local port configuration (useSpecifiedLocalPort, localPort)
- feat - Add automated Maven Central verification workflow

## 17.1.2
- KSM-651 - Add retrieve file by name to Notation.getFile()
- KSM-654 - Add fatJar gradle task
- KSM-660 - Handle broken records, files, and folders

## 17.1.1
- KSM-581 - Add GraphSync library to KSM SDK
- KSM-582 - fix NPE use safe cast in KeeperRecordData.getField()
- KSM-586 - Add recordingIncludeKeys to data classes
- KSM-587 - Add logging option
- KSM-627 - Java SDK Add GraphSync links
- KSM-634 - Added links2Remove parameter for files removal

## 17.0.0
- KSM-580 - Added new PAM fields

## 16.6.6
- KSM-560 - Improved error handling when parsing JSON

## 16.6.5
- KSM-548 - Make sure autogenerated UIDs don't start with '-'
- KSM-553 - Added new field types and updated PAM field types
- Upgraded package dependencies to latest versions and switched to gradle-8.10.1

## 16.6.4
- KSM-501 - Switched to non-strict JSON parser
- KSM-506 - Adding support for Privacy screen in the passkey field type
- Upgraded some dependencies to latest versions and gradle to gradle-8.6

## 16.6.3
- KSM-486 - Fix security provider not supporting AES/CBC/PKCS7Padding
- KSM-473 - Make Notation function public

## 16.6.2
- KSM-452 - Java SDK broken when using Java default crypto provider.
- KSM-453 - Upgrade kotlin-stdlib-jdk8 dependency scope to api

## 16.6.1
- KSM-443 - Improved folder support and updated unit tests

## 16.6.0
- KSM-415 - Added support for Folders

## 16.5.4
- KSM-431 - Improved Passkey field type support
- KSM-421 - Improved Logging

## 16.5.3
- KSM-401 - Update PAM Record types and Field types to have the latest updates
- KSM-406 - New field type: Passkey
- KSM-382 - Support for record Transactions

## 16.5.2
- KSM-379 - Remove deprecation from getValue function

## 16.5.1
- KSM-374 - Add support for PAM record types

## 16.5.0
- KSM-314 - Notation improvements
- KSM-356 - Create custom fields

## 16.4.0
- KSM-293 - Allow to run under Java 16+
- KSM-309 - Improved password generation
- Record Deletion

## 16.3.6
- KSM-324 - Support for new regions: Japan and Canada
- Checking for SecureRandom to work properly. Throw exception if `haveged` or `rng-tools` are not installed
