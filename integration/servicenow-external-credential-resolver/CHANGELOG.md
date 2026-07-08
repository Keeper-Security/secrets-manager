# Changelog

All notable changes to the KSM ServiceNow External Credential Resolver are documented here.

## [1.0.0] - Unreleased

### Added
- FQCN resolver class `com.keepersecurity.discovery.KeeperCredentialResolver` for Xanadu and newer MID Servers. Setting the FQCN on the External Credential Resolver configuration allows the Keeper JAR to coexist with other vendors' resolvers (CyberArk, HashiCorp, Delinea, etc.) on the same MID Server — which is not possible when every resolver JAR ships the shared `com.snc.discovery.CredentialResolver` class name.
- Two JAR variants per ServiceNow release: `fqcn` (Xanadu/Yokohama/Zurich — ships only `KeeperCredentialResolver`) and `legacy` (Utah/Vancouver/Washington DC — ships `com.snc.discovery.CredentialResolver`).
- JUnit test suite (13 tests) covering credential resolution logic and a PAM record regression.
- Compatibility matrix and FQCN registration guide in README.
- Yokohama (Patch 7+) and Zurich MID Server support.

### Fixed
- PAM records shared to the KSM application caused the resolver to fail with `Serializer for subclass 'pamSettings' is not found in the polymorphic scope of 'KeeperRecordField'`. Root cause: the SDK dependency was pinned as `16.6.4+` — a Gradle prefix wildcard that resolved to 16.6.4, which predates the `pamSettings` field type. The dependency is now pinned to `17.2.0`, which registers all PAM field types and skips unparseable records instead of failing the whole batch. (KSM-610, IMP-3033)

### Security
- Hardened the GHA publish workflow against shell injection via `workflow_dispatch` tag inputs: expression values are now passed through intermediate `env:` variables instead of being inlined directly in `run:` shell blocks. (KSM-680)

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
