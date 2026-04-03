# Oracle Key Management
Keeper Secrets Manager integrates with **Oracle Key Vault Management Service (OCI KMS)** to provide protection for Keeper Secrets Manager configuration files. With this integration, you can secure connection details on your machine while leveraging Keeper's **zero-knowledge encryption** for all your secret credentials.

## Features
* Encrypt and decrypt your Keeper Secrets Manager configuration files using **OCI KMS**.
* Protect against unauthorized access to your **Secrets Manager connections**.
* Requires only minor code modifications for immediate protection. Works with all Keeper Secrets Manager **JavaScript SDK** functionality.

## Prerequisites
* Supports the JavaScript Secrets Manager SDK.
* `oci-keymanagement` is bundled — no separate install required.
* OCI KMS Key needs `ENCRYPT` and `DECRYPT` permissions.

## Setup

1. Install KSM Storage Module

The Secrets Manager Oracle KSM module can be installed using npm

> `npm install @keeper-security/secrets-manager-oracle-kv`

2. Configure Oracle Connection

By default, the **oci-keymanagement** library will use the **default OCI configuration file** (`~/.oci/config`).

See the [OCI documentation](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm) for more details.

3. Add Oracle KMS Storage to Your Code

Now that the Oracle connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use `OciKeyValueStorage` as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an `Oracle config file location`, `Oracle configuration profile`(if there are multiple profile configurations) and the OCI `Oracle KMS endpoint` as well as the name of the `Secrets Manager configuration file` which will be encrypted by Oracle KMS.
```
    import { getSecrets, initializeStorage } from '@keeper-security/secrets-manager-core';
    import { OCISessionConfig, OciKeyValueStorage, LoggerLogLevelOptions } from "@keeper-security/secrets-manager-oracle-kv";

    const getKeeperRecordsOCI = async () => {

        const oracleConfigFileLocation = "/home/...../.oci/config";
        const oracleProfile = "DEFAULT";
        const kmsCryptoEndpoint = "https://<>-crypto.kms.<location>.oraclecloud.com";
        const kmsManagementEndpoint = "https://<>-management.kms.<location>.oraclecloud.com";

        const ociSessionConfig = new OCISessionConfig(oracleConfigFileLocation, oracleProfile, kmsCryptoEndpoint, kmsManagementEndpoint);
        const logLevel = LoggerLogLevelOptions.info;
        const configPath = "<Keeper config File Path>";

        // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use the encrypted config file
        const oneTimeToken = "<one time token>";

        const keyId = 'ocid1.key.oc1.iad.<>.<>';
        const keyVersionId = "ocid1.keyversion.oc1.iad.<>.<>";

        const storage = await new OciKeyValueStorage(keyId, keyVersionId, configPath, ociSessionConfig, logLevel).init();
        await initializeStorage(storage, oneTimeToken);

        const { records } = await getSecrets({ storage: storage });

        const firstRecord = records[0];
        const password = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'password');
        console.log(password.value[0]);
    };
    getKeeperRecordsOCI();
```
## Change Key

To change the Oracle KMS key used for encryption, call the `changeKey` method on the `OciKeyValueStorage` instance.
```javascript
const newKeyId = "ocid1.key.oc1.iad.<new_unique_id>";
const newKeyVersionId = "ocid1.keyversion.oc1.iad.<new_unique_id>";
const storage = await new OciKeyValueStorage(keyId, keyVersionId, configPath, ociSessionConfig).init();
await storage.changeKey(newKeyId, newKeyVersionId);
```

## Decrypt Config

You can decrypt the configuration file to migrate to a different cloud provider or to retrieve your raw credentials. Pass `true` to save the decrypted configuration back to the file, or `false` to return the plaintext without modifying the file.

Note: decrypting and saving as plaintext will compromise the security of the config file.
```javascript
const storage = await new OciKeyValueStorage(keyId, keyVersionId, configPath, ociSessionConfig).init();

// Returns plaintext only (file stays encrypted)
const plaintext = await storage.decryptConfig(false);

// OR: returns plaintext and saves config as plaintext
const saved = await storage.decryptConfig(true);
```


## Logging
We support logging for the Oracle Key Vault integration. Supported log levels are as follows
* trace
* debug
* info
* warn
* error
* fatal
  
All these levels should be accessed from the LoggerLogLevelOptions enum. If no log level is set, the default log level is info. We can set the logging level to debug to get more information about the integration.

You're ready to use the KSM integration Using the Oracle KMS Integration 👍

Once setup, the Secrets Manager Oracle KMS integration supports all Secrets Manager JavaScript SDK functionality.  Your code will need to be able to access the Oracle KMS APIs in order to manage the decryption of the configuration file when run. 