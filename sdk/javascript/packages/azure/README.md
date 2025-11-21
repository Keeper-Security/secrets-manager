***Azure Key Vault***

Protect Secrets Manager connection details with Azure Key Vault

Keeper Secrets Manager integrates with Azure Key Vault in order to provide protection for Keeper Secrets Manager configuration files. With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

Features

* Encrypt and Decrypt your Keeper Secrets Manager configuration files with Azure Key Vault
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection. Works with all Keeper Secrets Manager Javascript SDK functionality

Prerequisites

* Supports the Javascript Secrets Manager SDK
* Requires Azure packages: azure-identity and azure-keyvault-keys
* Works with just RSA key types

Setup
1. Install KSM Storage Module

The Secrets Manager HSM modules are located in the Keeper Secrets Manager storage module which can be installed using `npm`

> `npm install @keeper-security/secrets-manager-azure`

1. Configure Azure Connection

configuration variables can be provided as 

```
    import {AzureSessionConfig} from "@keeper-security/secrets-manager-azure";
    const tenant_id="<Some Tenant ID>" 
    const client_id="<Some Client ID>"
    const client_secret="<Some Client Secret>"

    const azureSessionConfig = new AzureSessionConfig(tenant_id, client_id, client_secret)
```

An authentication configuration is created using the **AzureSessionConfig** class, which requires the `tenant_id`, `client_id`, and `client_secret` parameters. This configuration is then used in the **AzureKeyValueStorage**.

You will need an Azure App directory App to use the Azure Key Vault integration.


For more information on Azure App Directory App registration and Permissions see the Azure documentation: https://learn.microsoft.com/en-us/azure/key-vault/general/authentication

1. Add Azure Key Vault Storage to Your Code

Now that the Azure connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use AzureKeyValueStorage as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an Azure Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by Azure Key Vault.

azure_keyvault_example_custom.ts 
```
    import { getSecrets, initializeStorage, localConfigStorage } from '@keeper-security/secrets-manager-core';
    import {AzureKeyValueStorage, AzureSessionConfig} from "@keeper/secrets-manager-azure";

    const getKeeperRecords = async () => {

        const tenant_id="<tenant_id>" 
        const client_id="<client_id>"
        const client_secret="<client-secret>"
        const azureSessionConfig = new AzureSessionConfig(tenant_id, client_id, client_secret)
        
        let config_path = "<path to client-config.json>"
        const logLevel = LoggerLogLevelOptions.info;

        // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use ksm-config.txt
        const oneTimeToken = "[One Time Token]";
        
        const keyId = 'https://<vault_name>.vault.azure.net/keys/<key_name>/<version>'
        const storage = await new AzureKeyValueStorage(keyId,config_path,azureSessionConfig,logLevel).init();
        await initializeStorage(storage, oneTimeToken);
        
        const {records} = await getSecrets({storage: storage});
        console.log(records)

        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    }
    getKeeperRecords()
```


## Change Key used to change the key configuration of the encrypted KSM configuration file.
```
    import { getSecrets, initializeStorage, localConfigStorage } from '@keeper-security/secrets-manager-core';
    import {AzureKeyValueStorage, AzureSessionConfig} from "@keeper/secrets-manager-azure";

    const getKeeperRecords = async () => {

        const tenant_id="<tenant_id>" 
        const client_id="<client_id>"
        const client_secret="<client-secret>"
        const azureSessionConfig = new AzureSessionConfig(tenant_id, client_id, client_secret)
        
        let config_path = "<path to client-config.json>"
        
        // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use ksm-config.txt
        const oneTimeToken = "[One Time Token]";
        
        const keyId = 'https://<vault_name>.vault.azure.net/keys/<key_name>/<version>'
        const keyId2 = "https://<vault_name>.vault.azure.net/keys/<key_name>/<version>"
        const storage = await new AzureKeyValueStorage(keyId2,config_path,azureSessionConfig).init();
        await storage.changeKey(keyId2);
        await initializeStorage(storage, oneTimeToken);
        
        const {records} = await getSecrets({storage: storage});
        console.log(records)

        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    }
    console.log("start")
    getKeeperRecords()
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

You're ready to use the KSM integration 👍
Using the Azure Key Vault Integration

Once setup, the Secrets Manager Azure Key Vault integration supports all Secrets Manager JavaScript SDK functionality. Your code will need to be able to access the Azure Key Vault APIs in order to manage the decryption of the configuration file when run. 
