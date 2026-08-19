## Keeper Secrets Manager Java SDK

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/java-sdk

# Change Log

## 17.4.0
**Breaking Changes**
- `SecretsManagerOptions.copy()` binary signature changed — callers compiled against 17.3.0 that invoke `copy()` must recompile against 17.4.0.

- KSM-1203 - Fixed `generatePassword` using a non-cryptographic PRNG (Kotlin `Random.Default`) for the final character shuffle. The shuffle now uses `SecureRandom`, so the entire password generation path is cryptographically secure.
- KSM-1176 - `KeeperRecord` now exposes `isEditable: Boolean`, forwarded from the server response envelope. Callers can inspect this field before calling `updateSecret` to determine whether the app has write permission for the record.
- KSM-1207 - Fixed all `HttpsURLConnection` calls defaulting to an infinite timeout. Added `connectTimeoutMillis` (default 5 000 ms) and `readTimeoutMillis` (default 30 000 ms) to `SecretsManagerOptions`. A stalled or unresponsive server now causes a `SocketTimeoutException` rather than an indefinite hang.
- KSM-1081 - Fixed `getFolders()` crashing when any folder in the response has a corrupted or missing key. The SDK now skips undecryptable folders and returns the remaining folders normally.
- KSM-1086 - Fixed `deleteFolder()` to return `SecretsManagerDeleteFolderResponse` (typed per-folder status), matching `deleteSecret()`. The SDK now logs per-item server failures to stderr and includes them in the return value so callers can detect partial failures.
- KSM-1248 - Server-supplied key IDs are validated against the embedded public key table before being stored. An unrecognized key ID throws `SecretsManagerException` and leaves storage unchanged. Key rotation retries are now capped at `MAX_KEY_ROTATION_RETRIES` (3); exhausted retries throw a typed error naming the last suggested key ID.
- KSM-1262 - On POSIX systems, config and cache files are now written via a temp-file swap with 0600 permissions set before data is written, closing the window where other local users could read the file during a write. Two behavior changes from the new approach: (1) a symlinked config path is replaced by a regular file on the first write; (2) a config file in a directory without write permission (for example, a read-only container volume mount) will fail at temp-file creation — move the config to a writable directory or use `InMemoryStorage` with an injected config string instead.
- KSM-531 - Add HTTP/HTTPS proxy support
  - New `proxyUrl` option on `SecretsManagerOptions`, e.g. `SecretsManagerOptions(storage, proxyUrl = "http://proxy.local:8080")`. Java callers can also use `SecretsManagerOptions.withProxy(storage, "http://proxy.local:8080")`.
  - Authenticated proxies use the `http://user:password@host:port` URL form
  - Applies to secret queries (`getSecrets`) and file uploads (`uploadFile`). Notation lookups that resolve file attachments (`getValue`) are not proxied; use `getNotationResults(options, notation)` for proxy-aware notation resolution. File downloads require the options-taking overloads: `downloadFile(options, file)` and `downloadThumbnail(options, file)`. The single-argument forms `downloadFile(file)` and `downloadThumbnail(file)` use ambient proxy settings (`HTTPS_PROXY`, `https.proxyHost`, etc.) but do not pick up `allowUnverifiedCertificate` from options.
  - When `proxyUrl` is not set, the SDK falls back to JVM system properties (`https.proxyHost`/`https.proxyPort`), then the `HTTPS_PROXY`/`HTTP_PROXY` environment variables; `NO_PROXY` and `http.nonProxyHosts` exclusions are honored
  - Credentials found in ambient environment variables (`HTTPS_PROXY`, `HTTP_PROXY`) are detected but not registered with the JVM `Authenticator` by default. Registering the global `Authenticator` from ambient env values would silently interfere with other libraries in the same process. To use authenticated proxy credentials, pass them explicitly via the `proxyUrl` field in `SecretsManagerOptions`.
  - **Authenticated proxies require a JVM startup flag in most applications.** Java disables Basic auth over HTTPS CONNECT tunnels by default (`jdk.http.auth.tunneling.disabledSchemes`, a CVE-2016-5597 mitigation), and that default locks in the first time *any* HTTPS connection is made in the process, before this SDK gets a chance to run. The SDK does clear it automatically when proxy credentials are supplied, but that only works if the SDK's proxied call happens to be the very first HTTPS connection in the JVM, which is not the common case in a real application. If you use an authenticated proxy, set this **before your application makes any other HTTPS call**:
    - Command line: `-Djdk.http.auth.tunneling.disabledSchemes=`
    - Environment variable (Java 9+): `JDK_JAVA_OPTIONS=-Djdk.http.auth.tunneling.disabledSchemes=`
    - Environment variable (Java 8): `_JAVA_OPTIONS=-Djdk.http.auth.tunneling.disabledSchemes=` or `JAVA_TOOL_OPTIONS=-Djdk.http.auth.tunneling.disabledSchemes=`

    If this is not set in time, the SDK throws a `SecretsManagerException` with this exact remediation in the message rather than surfacing a bare 407, so the failure is loud and actionable, not a silent/confusing auth error.
  - Proxy credentials are supplied via a default `java.net.Authenticator` scoped to the configured proxy host, re-asserted on every proxied connection. Applications that install their own default `Authenticator` should pass proxy credentials through that mechanism instead
  - The legacy `cachingPostFunction` helper does not carry the proxy; use the `proxyUrl` option with the default query path

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
