# Oracle KMS
Keeper Secrets Manager integrates with Oracle KMS in order to provide protection for Keeper Secrets Manager configuration files. With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

## Features
* Encrypt and Decrypt your Keeper Secrets Manager configuration files with Oracle KMS
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection. Works with all Keeper Secrets Manager Python SDK functionality

## Prerequisites
* Supports the Python Secrets Manager SDK
* Requires `oci` package
* These are permissions required for Oracle Cloud service account:
  * KMS CryptoKey Decrypter
  * KMS CryptoKey Encrypter
  * KMS CryptoKey Public Key Viewer

## Setup

1. Install KSM Storage Module

The Secrets Manager Oracle KMS module can be installed using pip

> `pip3 install keeper-secrets-manager-storage-oracle-kms`

2. Configure Oracle Cloud Connection

By default the oci library will utilize the default connection session setup located at `~/.oci/config`.

See the Oracle Cloud documentation for more information on setting up an OCI session: https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm

Alternatively, configuration variables can be provided explicitly using the `OCISessionConfig` data class and providing a path to the service account json file, profile name, and KSM endpoint name.

You will need an Oracle Cloud service account to use the Oracle KMS integration.

For more information on Oracle Cloud service accounts see the Oracle Cloud documentation: https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm

3. Add Oracle KMS Storage to Your Code

Now that the Oracle Cloud connection has been configured, you need to tell the Secrets Manager SDK to utilize the Oracle KMS as storage.

To do this, use `OracleKeyValueStorage` as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an Oracle Key ID, key version ID, as well as the name of the Secrets Manager configuration file which will be encrypted by Oracle KMS.

```python
from keeper_secrets_manager_storage_oracle_kms import OracleKeyValueStorage, OCISessionConfig
from keeper_secrets_manager_core import SecretsManager

config_file_location = "/home/<user>/.oci/config"
profile = "DEFAULT"
kms_crypto_endpoint = "https://<kmsendpoint>.oraclecloud.com"
kms_mgmt_endpoint = "https://<kmsendpoint>.oraclecloud.com"
key_id = '<key_id>'
key_version_id = "<key_version_id>"
config_path = "<path to config json>"
one_time_token = "<OTT>"

oci_session_config = OCISessionConfig(config_file_location, profile, kms_crypto_endpoint, kms_mgmt_endpoint)
storage = OracleKeyValueStorage(key_id=key_id, key_version=key_version_id, config_file_location=config_path, oci_session_config=oci_session_config, logger=None)

secrets_manager = SecretsManager(token=one_time_token, config=storage)
all_records = secrets_manager.get_secrets()
first_record = all_records[0]
print(first_record)
```

## Change Key

If you want to change the key from previous configuration, you can use the `change_key` method.

```python
storage = OracleKeyValueStorage(key_id=key_id, key_version=key_version_id, config_file_location=config_path, oci_session_config=oci_session_config, logger=None)

key_id_2 = "<second key id>"
key_version_id_2 = "<second key version>"

is_changed = storage.change_key(key_id_2, key_version_id_2)
print("Key is changed:", is_changed)
```

## Decrypt Config

You can use this method to decrypt the config file. This is not recommended for production use.

```python
storage = OracleKeyValueStorage(key_id=key_id, key_version=key_version_id, config_file_location=config_path, oci_session_config=oci_session_config, logger=None)

# Extract only plaintext
plaintext = storage.decrypt_config(False)
print(plaintext)

# OR extract plaintext and save config as plaintext
plaintext = storage.decrypt_config(True)
print(plaintext)
```

You're ready to use the KSM integration 👍

## Using the Oracle KMS Integration

Once setup, the Secrets Manager Oracle KMS integration supports all Secrets Manager Python SDK functionality. Your code will need to be able to access the Oracle KMS APIs in order to manage the decryption of the configuration file when run.