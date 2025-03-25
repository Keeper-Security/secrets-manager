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

## Setup

1. Install KSM Storage Module

The Secrets Manager GCP KSM module can be installed using pip

> `pip install google-cloud-kms`

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
    from storage.keeper_secrets_manager_storage.storage_gcp_kms import GCPKeyConfig, GCPKeyValueStorage,GCPKMSClientConfig
    from core.keeper_secrets_manager_core import SecretsManager

    gcp_key_config_1 = GCPKeyConfig("key_resource_uri_1")
    gcp_key_config_2 = GCPKeyConfig("key_resource_uri_2")

    gcp_session_config = GCPKMSClientConfig().create_client_from_credentials_file('<credentails_json_location>')
    config_path = "<KSM_config_location>"
    one_time_token = "US:kYKVGFJ2605-9UBF4VXd14AztMPXcxZ56zC9gr7O-Cw"

    storage = GCPKeyValueStorage(config_path, gcp_key_config_2, gcp_session_config)
    # storage.change_key(gcp_key_config_2) # if we want to change the key
    secrets_manager = SecretsManager(config=storage)
    all_records = secrets_manager.get_secrets()

    first_record = all_records[0]
    first_record_password = next(field.value[0] for field in first_record.data.fields if field.type == 'bankAccount')
    print(first_record_password)
```

You're ready to use the KSM integration 👍
Using the GCP KMS Integration

Once setup, the Secrets Manager GCP KMS integration supports all Secrets Manager Python SDK functionality. Your code will need to be able to access the GCP KMS APIs in order to manage the decryption of the configuration file when run.