# Changelog

All notable changes to the KSM ServiceNow External Credential Resolver are documented here.

## [1.0.0] - 2026-07-17

### Added
- FQCN resolver class `com.keepersecurity.secretsManager.CredentialResolver` for Yokohama (Patch 7+) and newer MID Servers. Setting the FQCN on the External Credential Resolver configuration allows the Keeper JAR to coexist with other vendors' resolvers (CyberArk, HashiCorp, Delinea, etc.) on the same MID Server — which is not possible when every resolver JAR ships the shared `com.snc.discovery.CredentialResolver` class name.
- Two JAR variants per ServiceNow release: `fqcn` (Yokohama Patch 7+/Zurich/Australia — ships only `com.keepersecurity.secretsManager.CredentialResolver`) and `legacy` (Utah/Vancouver/Washington DC/Xanadu — ships `com.snc.discovery.CredentialResolver`).
- **PAM User (`pamUser`) records**: username/password are read from the record's standard Login/Password fields, the same as Login records.
- JUnit test suite (24 tests) covering credential resolution logic, field-label diagnostics, and a PAM record regression.
- Compatibility matrix and FQCN registration guide in README.
- Yokohama (Patch 7+), Zurich, and Australia MID Server support.
- Actionable diagnostics for mislabeled Keeper fields, written to `agent.log` (informational only - the checks never throw or block a working credential): the resolver warns for every `mid_`-prefixed custom field whose suffix is not a recognized key name in the resolver's response map - catching the common mistake of using a ServiceNow form/column name (ex. `mid_private_key`, `mid_password`) instead of the interface's key name (`mid_privkey`, `mid_pswd`) - and when an unprefixed custom field's label exactly matches a recognized key name. Once per lookup it logs the recognized key names without the configurable prefix (which is stated once; a "did you mean ...?" hint is added for close typos), record-type aware. The key names are resolved at runtime from the `IExternalCredential` interface (`snc-automation-api.jar`), with a built-in static list as fallback.

### Fixed
- `config()` threw a raw `NullPointerException` (masking its own "ksmConfig not set" error) when the `ext.cred.keeper.ksm_config` MID parameter was missing; it now logs the actionable message without dereferencing the null config.
- PAM records shared to the KSM application caused the resolver to fail with `Serializer for subclass 'pamSettings' is not found in the polymorphic scope of 'KeeperRecordField'`. Root cause: the SDK dependency was pinned as `16.6.4+` — a Gradle prefix wildcard that resolved to 16.6.4, which predates the `pamSettings` field type. The dependency is now pinned to `17.3.0`, which registers all PAM field types and skips unparseable records instead of failing the whole batch. (KSM-610, IMP-3033)

### Security
- Hardened the GHA publish workflow against shell injection via `workflow_dispatch` tag inputs: expression values are now passed through intermediate `env:` variables instead of being inlined directly in `run:` shell blocks. (KSM-680)
- Restricted the Test-ServiceNow CI workflow's `GITHUB_TOKEN` to least privilege (`contents: read`).

### Dropped
- Rome, San Diego, and Tokyo ServiceNow release support (past end of life).

## [0.1.0] - 2024-09-17

### Added
- Credential caching option (`ext.cred.keeper.use_ksm_cache = "true"` in `config.xml`). Cached data is stored encrypted in `ksm_cache.dat` in the MID Server's work folder and refreshed at most once every 5 minutes.
- Throttle handling with random backoff for large KSM applications (up to ~3000 credential requests per 10 seconds without caching).
- Vancouver ServiceNow release support.

### Fixed
- Windows file locking error (`java.io.IOException: The process cannot access the file because another process has locked a portion of the file`) on MID Servers running on Windows.

## [0.0.1] - 2024-09-17

### Added
- Initial ServiceNow MID Server External Credential Resolver implementation.
- Credential lookup by record UID or `type:title` format.
- Support for login, text, hidden, and custom field types mapped to ServiceNow's `discovery_credential` table columns (fields prefixed with `mid_`).
