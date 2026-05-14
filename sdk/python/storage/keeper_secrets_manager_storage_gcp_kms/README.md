# GCP KSM
Keeper Secrets Manager integrates with GCP KMS in order to provide protection for Keeper Secrets Manager configuration files.  With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

## Features
* Encrypt and Decrypt your Keeper Secrets Manager configuration files with GCP KMS
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection.  Works with all Keeper Secrets Manager Python SDK functionality

## Prerequisites
* Supports the Python Secrets Manager SDK
* Requires `google-cloud-kms` package
* These are permissions required for service account:
  * Cloud KMS CryptoKey Decrypter
  * Cloud KMS CryptoKey Encrypter
  * Cloud KMS CryptoKey Public Key Viewer
  * Cloud KMS Viewer (provides `cloudkms.cryptoKeys.get`, required for key introspection on init)

## Setup

1. Install KSM Storage Module

The Secrets Manager GCP KSM module can be installed using pip

> `pip3 install keeper-secrets-manager-storage-gcp-kms`

> **Note**: v1.1.0+ requires Python 3.9+. Users on Python 3.6–3.8 should pin to `keeper-secrets-manager-storage-gcp-kms<1.1.0`.

2. Configure GCP Connection

By default the google-cloud-kms library will utilize the default connection session setup with the GCP CLI with the gcloud auth command.  If you would like to specify the connection details, the two configuration files located at `~/.config/gcloud/configurations/config_default` and ~/.config/gcloud/legacy_credentials/<user>/adc.json can be manually edited.

See the GCP documentation for more information on setting up an GCP session: https://cloud.google.com/sdk/gcloud/reference/auth

Alternatively, configuration variables can be provided explicitly as a service account file using the GcpSessionConfig data class and providing  a path to the service account json file.

You will need a GCP service account to use the GCP KMS integration.

For more information on GCP service accounts see the GCP documentation: https://cloud.google.com/iam/docs/service-accounts

3. Add GCP KMS Storage to Your Code

Now that the GCP connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use GcpKmsKeyvalueStorage as your Secrets Manager storage in the SecretsManager constructor.

The storage will require a GCP Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by GCP KMS.
```
    from keeper_secrets_manager_storage_gcp_kms import GCPKeyConfig, GCPKeyValueStorage, GCPKMSClientConfig

    from keeper_secrets_manager_core import SecretsManager

    # example key : projects/<project>/locations/<location>/keyRings/<key>/cryptoKeys/<key_name>/cryptoKeyVersions/<key_version>
    gcp_key_config_1 = GCPKeyConfig("<key_resource_uri_1>")
    gcp_key_config_2 = GCPKeyConfig("<key_resource_uri_1>")

    gcp_session_config = GCPKMSClientConfig().create_client_from_credentials_file('<gcp_credentials_config_file_location.json>')
    config_path = "<ksm_config.json>"
    one_time_token = "<token>"

    storage = GCPKeyValueStorage(config_path, gcp_key_config_1, gcp_session_config)
    storage.change_key(gcp_key_config_2) # if we want to change the key
    secrets_manager = SecretsManager(token=one_time_token,config=storage)
    all_records = secrets_manager.get_secrets()
    print(storage.decrypt_config(False))

    first_record = all_records[0]
    print(first_record)
```

You're ready to use the KSM integration 👍
Using the GCP KMS Integration

Once setup, the Secrets Manager GCP KMS integration supports all Secrets Manager Python SDK functionality. Your code will need to be able to access the GCP KMS APIs in order to manage the decryption of the configuration file when run.

## Change Log

### 1.1.0

**Requirements:**
- Minimum Python version raised to 3.9; users on Python 3.6–3.8 should pin to `<1.1.0`
- Minimum `keeper-secrets-manager-core` dependency raised to 17.2.1

**Security:**
- Fixed CVE-2026-0994: upgraded `protobuf` to ≥6.33.5 (JSON recursion DoS)
- Fixed CVE-2026-26007: upgraded `cryptography` to ≥46.0.5 (subgroup attack)
- Fixed AES-GCM nonce from 128-bit (PyCryptodome default) to 96-bit per NIST SP 800-38D; existing encrypted blobs remain readable
- Replaced MD5 with SHA-256 for config change detection

**Bug fixes:**
- `GCPKeyValueStorage` now raises on init when `cloudkms.cryptoKeys.get` is denied, instead of proceeding with the config file left unencrypted on disk
- KMS errors (permission denials, network failures, decryption failures) now propagate as exceptions instead of being silently swallowed or reported as misleading JSON parse errors
- `decrypt_config()` no longer writes plaintext credentials to disk when called without arguments (`autosave` default changed from `True` to `False`)
- `read_storage()` now returns a copy; mutations to the returned dict no longer silently corrupt internal state
- `delete()` of the last config key now persists correctly to disk
- `delete_all()` now removes the config file from disk; previously it attempted to re-encrypt an empty config, leaving credentials readable if KMS was unavailable
- `set()` now propagates `PermissionError` when the config file is read-only, preventing silent in-memory/on-disk state divergence
- `change_key()` rolls back cleanly on failure; a failed rotation no longer leaves the storage in an inconsistent state
- `GCPKeyValueStorage` is now thread-safe for concurrent `set()`, `delete()`, `change_key()`, and `decrypt_config()` calls (KSM-946)
- `key_version` on `GCPKeyConfig` applies only to encrypt and asymmetric operations; symmetric `client.decrypt` uses the unversioned CryptoKey name as required by the GCP API (the server selects the version from the ciphertext envelope)
- `load_config()` now always leaves `self.config` as a dict (never `None`) after parsing a plaintext `{}` bootstrap config; previously every subsequent `read`/`set`/`delete` crashed with `TypeError: 'NoneType' object is not iterable` (KSM-948)

### 1.0.1

- Fixed installation and import instructions in README

### 1.0.0

- Initial release