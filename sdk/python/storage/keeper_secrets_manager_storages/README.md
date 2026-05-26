# Keeper Secrets Manager Storage

The Keeper Secrets Manager Storage module for working with custom key-value storages, creating and managing configuration files. To be used with keeper-secrets-manager-core.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager

# Change Log

## 1.1.0

- Raised minimum Python version to 3.9.2. Python 3.9.0 and 3.9.1 are excluded by the transitive `cryptography>=46.0.5` constraint pulled in via `keeper-secrets-manager-core>=17.2.0`. Users on Python 3.6 – 3.8 should pin to `keeper-secrets-manager-storage<1.1.0`; pip will auto-route them.
- Updated minimum `keeper-secrets-manager-core` dependency to 17.2.0
- Added `threading.RLock` to all backends — prevents data corruption under concurrent use
- Replaced MD5 with SHA-256 for change-detection hashing; fixed Azure AES-GCM nonce from 16 to 12 bytes (NIST SP 800-38D)
- Encrypt/decrypt failures now raise instead of silently corrupting storage state
- `delete_all()` removes the backing config file instead of writing an empty encrypted blob
- `__save_config` writes to disk before updating in-memory state — prevents divergence on write failure
- `decrypt_config()` default changed from `autosave=True` to `autosave=False` — stray calls no longer overwrite the encrypted file with plaintext
- `__load_config` check fixed from `if config:` to `if config is not None:` — a plaintext `{}` config is now correctly re-encrypted on first load
- `_get_instance_region` and `read_config` (AWS Secrets Manager provider) now raise on failure instead of silently returning empty values
- `AwsSecretStorage.__init__` now eagerly loads the config on construction, matching all other backends
- `AwsSecretStorage.__load_config()` now raises when the underlying AWS Secrets Manager call fails — previously the exception from `read_config` was logged but not propagated, leaving `config = {}` with no error
- Non-UTF8 bytes that are not a valid encrypted blob now raise a clear `"is not a valid encrypted config file"` exception across all encrypted backends (nfast, AWS KMS, Azure KeyVault)
- HsmNfast and AwsKms now raise `"is not a valid encrypted config file"` when decryption produces empty output — previously HsmNfast leaked a bare `JSONDecodeError` and AwsKms logged silently without raising, unlike Azure

## 1.0.2

- Reverted mandatory boto3 dependency; boto3 remains optional via lazy import

## 1.0.1

- Added new storage type storage type for AWS Secrets Manager

## 1.0.0
- Initial release
