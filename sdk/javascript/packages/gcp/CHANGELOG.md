# Changelog

All notable changes to the Keeper Secrets Manager JavaScript GCP KMS Storage will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0]

### Security

- KSM-1370 - `createConfigFileIfMissing()` no longer overwrites the config file on a transient `fs.access` failure (`EACCES`, `EPERM`, `ESTALE`). Only a genuinely missing file (`ENOENT`) triggers recreation.
- KSM-1450 - Config file writes now use restrictive file permissions (0600), including on a config file that already exists from an earlier SDK version. Writes go through an atomic temp-file-then-rename (also fixes KSM-1458).
- KSM-1455 - `loadConfig()` no longer treats a zero-length config file as an empty config and re-encrypts it back over the top, which destroyed the client ID, app key, and device private key. A zero-length file is a truncated or interrupted write, so `loadConfig()` now throws and leaves the file untouched for recovery.
- KSM-1457 - A blank `KSM_CONFIG_FILE` environment variable, or a blank `keyVaultConfigFileLocation` argument, now falls back to the next source instead of being used as the config file path. `??` falls back only on `null` and `undefined`, so an empty value (a common result of a Docker `--env-file` or a Kubernetes ConfigMap entry with no value) resolved to the current working directory, which `fs.access` reported as an existing config file.
- KSM-1459 - `saveConfig()` no longer skips the write when the config file was deleted while the process was running. A missing file now forces a full save of the current config, so `saveString()` and `saveStorage()` can no longer resolve successfully without persisting anything.
- KSM-1460 - A KMS failure while auto-encrypting a plaintext config file is no longer misreported as a damaged config file. `loadConfig()` now encrypts outside the try/catch that detects whether the file is plain JSON, so a KMS outage, a revoked permission, or a disabled key version propagates as the real KMS error instead of `Decryption failed : Invalid header`. Operators are no longer told to distrust an intact config file.
- KSM-1461 - A failed `changeKey()` now restores `keyType`, `isAsymmetric`, and `encryptionAlgorithm` alongside the key config and crypto client. Previously the old key was left paired with the new key's algorithm, and the next save encrypted the config into a file that no key could decrypt, permanently losing the client ID, app key, and device private key. `getKeyDetails()` also assigns no key metadata at all when it rejects an unsupported key purpose.

### Maintenance

- KSM-1218 - Updated axios, protobufjs, handlebars, js-yaml, and other dependencies to resolve open security advisories

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

- KSM-867 - Fixed `getKeyDetails()` silently swallowing errors — bad credentials, non-existent keys, and network failures now propagate to `init()` instead of continuing with uninitialized key metadata
- KSM-847 - Fixed encryption and decryption errors being silently swallowed — invalid credentials, bad key IDs, and failed key rotation now throw as expected
  - `encryptBuffer()` and `decryptBuffer()` in `utils.ts` now rethrow GCP KMS failures instead of returning empty values
  - `saveConfig()` in `GCPKeyValueStore.ts` now rethrows errors instead of logging and continuing, making the full error propagation chain work end-to-end
  - `saveString()`, `saveBytes()`, and `saveObject()` now propagate GCP KMS errors to the caller
  - `changeKey()` rollback path (key and crypto client restoration) is now reachable when encryption with the new key fails
  - Removed dead `if (plaintext.length > 0)` guard in `decryptConfig()` — unreachable after `decryptBuffer()` now throws on failure
- KSM-837 - Fixed `contains()` always returning false — `key in Object.keys(config)` checks array indices, not property names; corrected to `key in config`
- KSM-840 - Fixed `delete()` skipping keys with falsy values — truthy check `if (config[key])` replaced with `if (key in config)`
- KSM-849 - Fixed `getBytes()` returning undefined for keys storing a zero-length Uint8Array
