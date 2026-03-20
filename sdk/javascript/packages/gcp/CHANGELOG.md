# Changelog

All notable changes to the Keeper Secrets Manager JavaScript GCP KMS Storage will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0]

### Added

- Initial release — `GCPKeyValueStorage` for encrypting KSM configuration files with Google Cloud KMS
  - Supports symmetric (ENCRYPT_DECRYPT, RAW_ENCRYPT_DECRYPT) and asymmetric (ASYMMETRIC_DECRYPT) key types
  - Authenticate with `GCPKSMClient` using service account credentials or application default credentials
  - `changeKey(newGcpKeyConfig)` method to rotate the KMS key without re-initializing storage
  - `decryptConfig(autosave)` to export configuration back to plaintext for migration or backup
  - Configurable log levels via `LoggerLogLevelOptions` (`trace`, `debug`, `info`, `warn`, `error`, `fatal`)
  - Requires `@keeper-security/secrets-manager-core` v17.3.0

### Fixed

- KSM-847 - Fixed encryption and decryption errors being silently swallowed — invalid credentials, bad key IDs, and failed key rotation now throw as expected
  - `encryptBuffer()` and `decryptBuffer()` in `utils.ts` now rethrow GCP KMS failures instead of returning empty values
  - `saveConfig()` in `GCPKeyValueStore.ts` now rethrows errors instead of logging and continuing, making the full error propagation chain work end-to-end
  - `saveString()`, `saveBytes()`, and `saveObject()` now propagate GCP KMS errors to the caller
  - `changeKey()` rollback path (key and crypto client restoration) is now reachable when encryption with the new key fails
  - Removed dead `if (plaintext.length > 0)` guard in `decryptConfig()` — unreachable after `decryptBuffer()` now throws on failure
