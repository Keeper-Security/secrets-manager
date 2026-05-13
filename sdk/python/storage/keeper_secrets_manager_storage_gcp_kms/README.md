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

- Raised minimum Python version to 3.9
- Updated minimum `keeper-secrets-manager-core` dependency to 17.2.1
- Fixed CVE-2026-0994: protobuf JSON recursion DoS (upgraded to `protobuf>=6.33.5`)
- Fixed CVE-2026-26007: cryptography subgroup attack (upgraded to `cryptography>=46.0.5`)
- Fixed silent failure when `cloudkms.cryptoKeys.get` is denied — `GCPKeyValueStorage` now raises on init instead of leaving the config file unencrypted on disk
- Fixed AES-GCM nonce to 96-bit/12-byte per NIST SP 800-38D (was 128-bit/16-byte PyCryptodome default); existing encrypted blobs remain readable
- Replaced MD5 with SHA-256 for config change detection
- Fixed `read_storage()` returning a live dict reference — caller mutations no longer silently corrupt internal state without triggering encryption (KSM-944)
- Fixed `decrypt_config()` default `autosave` from `True` to `False` — calling without arguments no longer writes plaintext credentials to disk (KSM-944)
- Fixed `delete()` of the last config key silently lost — key remained in memory and on disk after deletion due to interaction between the copy-isolation fix and an empty-dict falsy-check in the save path
- Documented GCP's version-from-envelope behavior on symmetric decrypt (KSM-945): `cryptoKeys.decrypt` accepts only the unversioned CryptoKey resource — the server reads the version from the ciphertext envelope (this is required for key rotation). `key_version` on `GCPKeyConfig` therefore applies only to encrypt and asymmetric paths. A prior attempt to "pin" the version on this path passed a `cryptoKeyVersions/...` resource to `client.decrypt`, which GCP rejects with `400 INVALID_ARGUMENT`; that change has been reverted to match the JS and Java siblings
- Fixed thread-safety: added `threading.RLock` to `GCPKeyValueStorage` — concurrent `set()` / `delete()` calls no longer race on the config dict or the encrypt-and-write sequence (KSM-946)
- Fixed `encrypt_buffer` silently swallowing KMS/network errors — failures now raise so callers see the error rather than proceeding with a plaintext credential file left on disk
- Fixed `create_config_file_if_missing` swallowing init errors — failures now propagate to the caller
- Fixed `change_key` incomplete rollback — all key-related attributes (`gcp_key_config`, `crypto_client`, `key_purpose_details`, `encryption_algorithm`, `is_asymmetric`) are now restored on failure; previously a failed rotation left the storage in an inconsistent state where encryption was routed through mismatched key config
- Fixed `load_config` misclassifying KMS/disk errors as JSON parse failures — the plain-JSON detection block now only catches `JSONDecodeError` and `UnicodeDecodeError`

### 1.0.1

- Fixed installation and import instructions in README

### 1.0.0

- Initial release