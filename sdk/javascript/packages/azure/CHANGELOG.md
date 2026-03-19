# Changelog

All notable changes to the Keeper Secrets Manager JavaScript Azure Key Vault Storage will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0]

### Added

- KSM-706 - Initial release — `AzureKeyValueStorage` for encrypting KSM configuration files with Azure Key Vault
  - Supports RSA key types with WrapKey and UnWrapKey permissions
  - Authenticate with `AzureSessionConfig` (tenant ID, client ID, client secret) or environment-based `DefaultAzureCredential`
  - `changeKey(newKeyId)` method to rotate the vault key without re-initializing storage
  - `decryptConfig(autosave)` to export configuration back to plaintext for migration or backup
  - Configurable log levels via `LoggerLogLevelOptions` (`trace`, `debug`, `info`, `warn`, `error`, `fatal`)
  - Requires `@keeper-security/secrets-manager-core` v17.3.0

### Fixed

- KSM-835 - Fixed `delete()` silently no-opping and `contains()` always returning `false`
  - `key in Object.keys(config)` was checking array indices instead of object property names; fixed to `key in config`
- KSM-844 - Fixed encryption and decryption errors being silently swallowed — invalid credentials, bad key IDs, and failed key rotation now throw as expected
  - `encryptBuffer()` and `decryptBuffer()` in `utils.ts` now rethrow Azure KMS `wrapKey`/`unwrapKey` failures instead of returning empty values
  - `saveConfig()` in `AzureKeyValueStorage.ts` now rethrows errors instead of logging and continuing, making the full error propagation chain work end-to-end
  - `saveString()`, `saveBytes()`, and `saveObject()` now propagate Azure KMS errors to the caller
  - `changeKey()` rollback path (key and crypto client restoration) is now reachable when encryption with the new key fails

### Security

- Upgraded `pino` to v10 — resolves CVE-2025-57319 (fast-redact regular expression injection, HIGH)
- Upgraded `jws` to v3.2.3 — resolves CVE-2025-65945 (HIGH)
