# Changelog

All notable changes to the Keeper Secrets Manager JavaScript Oracle KMS Storage will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0]

### Added

- Initial release — `OciKeyValueStorage` for encrypting KSM configuration files with Oracle Cloud KMS
  - Supports symmetric (AES) and asymmetric (RSA) key types
  - Authenticate with `OCISessionConfig` using OCI configuration file or instance principal credentials
  - `changeKey(newKeyId, newKeyVersion)` method to rotate the KMS key without re-initializing storage
  - `decryptConfig(autosave)` to export configuration back to plaintext for migration or backup
  - Configurable log levels via `LoggerLogLevelOptions` (`trace`, `debug`, `info`, `warn`, `error`, `fatal`)
  - Requires `@keeper-security/secrets-manager-core` v17.3.0

### Fixed

- KSM-848 - Fixed encryption and decryption errors being silently swallowed — invalid credentials, bad key IDs, and failed key rotation now throw as expected
  - `encryptBuffer()` and `decryptBuffer()` in `utils.ts` now rethrow Oracle OCI KMS failures instead of returning empty values
  - `saveConfig()` in `OracleKeyValueStore.ts` now rethrows errors instead of logging and continuing, making the full error propagation chain work end-to-end
  - `saveString()`, `saveBytes()`, and `saveObject()` now propagate Oracle KMS errors to the caller
  - `changeKey()` rollback path (key and crypto client restoration) is now reachable when encryption with the new key fails
