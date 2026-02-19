# Oracle Key Management
Keeper Secrets Manager integrates with **Oracle Key Vault Management Service (OCI KMS)** to provide protection for Keeper Secrets Manager configuration files. With this integration, you can secure connection details on your machine while leveraging Keeper's **zero-knowledge encryption** for all your secret credentials.

## Features
* Encrypt and decrypt your Keeper Secrets Manager configuration files using **OCI KMS**.
* Protect against unauthorized access to your **Secrets Manager connections**.
* Requires only minor code modifications for immediate protection. Works with all Keeper Secrets Manager **JavaScript SDK** functionality.

## Prerequisites
* Supports the JavaScript Secrets Manager SDK.
* Requires the **oci-keymanagement** package from OCI SDK.
* OCI KMS Key needs `ENCRYPT` and `DECRYPT` permissions.

## Setup

1. Install KSM Storage Module

The Secrets Manager oracle KSM module can be installed using npm

> `npm install @keeper-security/secrets-manager-oracle-kv`

2. Configure oracle Connection

By default, the **oci-keymanagement** library will use the **default OCI configuration file** (`~/.oci/config`).

See the [OCI documentation](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm) for more details.

3. Add oracle KMS Storage to Your Code

Now that the oracle connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use `OciKeyValueStorage` as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an `Oracle config file location`, `Oracle configuration profile`(if there are multiple profile configurations) and the OCI `Oracle KMS endpoint` as well as the name of the `Secrets Manager configuration file` which will be encrypted by Oracle KMS.
```
    import { OCISessionConfig, OciKeyValueStorage } from "@keeper-security/secrets-manager-oracle-kv";

    const getKeeperRecordsOCI = async () => {

        const oracleConfigFileLocation = "/home/...../.oci/config";
        const oracleProfile = "DEFAULT";
        const kmsCryptoEndpoint = "https://<>-crypto.kms.<location>.oraclecloud.com";
        const kmsManagementEndpoint = "https://<>-management.kms.<location>.oraclecloud.com";

        const ociSessionConfig = await new OCISessionConfig(oracleConfigFileLocation, oracleProfile, kmsCryptoEndpoint,kmsManagementEndpoint);
        const logLevel = LoggerLogLevelOptions.info;
        let config_path = "<Keeper config File Path>";

        const oneTimeToken = "<one time token>";

        const keyId = 'ocid1.key.oc1.iad.<>.<>';
        const keyVersionId = "ocid1.keyversion.oc1.iad.<>.<>";

        const storage = await new OciKeyValueStorage(keyId, keyVersionId, config_path, ociSessionConfig,logLevel).init();
        await initializeStorage(storage, oneTimeToken);

        const { records } = await getSecrets({ storage: storage });
        console.log(records);

        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    };
    console.log("start");
    getKeeperRecordsOCI();
```
## Change Key

To change the Oracle KMS key used for encryption, you can call the `changeKey` method on the `OciKeyValueStorage` instance.
```
    const storage = await new OciKeyValueStorage(keyId, keyVersionId, config_path2, ociSessionConfig).init();
    await storage.changeKey(keyId2, keyVersionId2);
```

## decrypt config

To decrypt the config file and save it again in plaintext, you can call the `decryptConfig` method on the `OciKeyValueStorage` instance.
Note: this will compromise the security of the config file.
```
    const storage = await new OciKeyValueStorage(keyId, keyVersionId, config_path, ociSessionConfig).init();
    await storage.decryptConfig(true); // Saves to file
    const decryptedConfig = await storage.decryptConfig(true); // returns the decrypted config
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