# Oracle Key Vault Integration
Keeper Secrets Manager integrates with Oracle KMS in order to provide protection for Keeper Secrets Manager configuration files.  With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

## Features
* Encrypt and Decrypt your Keeper Secrets Manager configuration files with oracle KMS
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection.  Works with all Keeper Secrets Manager Python SDK functionality

## Prerequisites
* Supports the Python Secrets Manager SDK
* Requires `oci` package
* User credentials to be used will need to have key vault permissions

## Setup

1. Install KSM Storage Module

The Secrets Manager OCI KSM module can be installed using pip

> `pip3 install keeper-secrets-manager-storage`

2. Configure OCI Connection

By default the oci library will utilize the default connection session setup located at `/home/<user>/.oci/config`.

See the OCI (documentation)[https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm] for more information on setting up an OCI session.

Alternatively, configuration variables can be provided explicitly as a service account file using the `OCISessionConfig` data class and providing  a path to the service account json file, profile name, and ksm endpoint name.

To use the integration to encrypt and decrypt the configuration, please use the following steps

1. Add Oracle KMS Storage to Your Code

Now that the connection has been configured, you need to tell the Secrets Manager SDK to utilize the OracleKMS as storage.

To do this, use `OracleKeyValueStorage` as your Secrets Manager storage in the SecretsManager constructor.

The storage will require a OCI Key ID, key version Id, as well as the name of the Secrets Manager configuration file which will be encrypted by Oracle KMS and OCI session configuration defined above.
```
from keeper_secrets_manager_storage.storage_oci_key_management import  OracleKeyValueStorage,OCISessionConfig
from keeper_secrets_manager_core import SecretsManager
config_file_location = "/home/<user>/.oci/config"
profile = "DEFAULT"
kms_crypto_endpoint = "https://<kmsendpoint>.oraclecloud.com"
kms_mgmt_endpoint = "https://<kmsendpoint>.oraclecloud.com"
key_id = '<key_id>'
key_version_id = "<key_version_id>"
config_path = "<path to config json>"
one_time_token = "<OTT>"
key_id_2 = "<second key id>"
key_version_id_2 = "<second key version>"
oci_session_config = OCISessionConfig(config_file_location, profile, kms_crypto_endpoint, kms_mgmt_endpoint)
storage = OracleKeyValueStorage(key_id=key_id, key_version=key_version_id, config_file_location=config_path, oci_session_config=oci_session_config,logger=None)
storage.change_key(key_id, key_version_id) # this is optional and only if you want to change the key from previous configuration
print(storage.config)
secrets_manager = SecretsManager(one_time_token,config=storage)
all_records = secrets_manager.get_secrets()
first_record = all_records[0]
print(first_record)
```

## Change Key

If you want to change the key from previous configuration, you can use the `change_key` method.

```
    storage = OracleKeyValueStorage(key_id=key_id, key_version=key_version_id, config_file_location=config_path, oci_session_config=oci_session_config,logger=None)
    
    key_id_2 = "<second key id>"
    key_version_id_2 = "<second key version>"

    isChanged = storage.change_key(key_id, key_version_id)
    print("Key is changed " + isChanged)
```

## Decrypt config

Note : Danger Zone :: You can use this method to decrypt the config file.  This is not recommended for production use.

```
    storage = OracleKeyValueStorage(key_id=key_id, key_version=key_version_id, config_file_location=config_path, oci_session_config=oci_session_config,logger=None)
    storage.decrypt_config()
```

You're ready to use the KSM integration 👍
Using the OCI KMS Integration

Once setup, the Secrets Manager OCI KMS integration supports all Secrets Manager Python SDK functionality. Your code will need to be able to access the Oracle KMS APIs in order to manage the decryption of the configuration file when run.