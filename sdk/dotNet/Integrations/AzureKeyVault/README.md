***Azure Key Vault***

Protect Secrets Manager connection details with Azure Key Vault

Keeper Secrets Manager integrates with Azure Key Vault in order to provide protection for Keeper Secrets Manager configuration files. With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

Features

* Encrypt and Decrypt your Keeper Secrets Manager configuration files with Azure Key Vault
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection. Works with all Keeper Secrets Manager dotnet SDK functionality

Prerequisites

* Supports the Dotnet Secrets Manager SDK
* Supports dotnet version `net9.0`
* Requires Azure packages: `Azure.Identity` and `Azure.Security.KeyVault.Keys`
* Works with just RSA key types

Setup
1. Install KSM Storage Module

The Secrets Manager HSM modules are located in the Keeper Secrets Manager storage module which can be installed using `dotnet`

> `dotnet add package Keeper.SecretsManager.AzureKeyVault`

1. Configure Azure Connection

configuration variables can be provided as 

```
    using AzureKeyVault;
    var tenant_id="<Some Tenant ID>" 
    var client_id="<Some Client ID>"
    var client_secret="<Some Client Secret>"

    var azure_session_config = new AzureSessionConfig(tenant_id, client_id, client_secret);
```

An authentication configuration is created using the **AzureSessionConfig** class, which requires the `tenant_id`, `client_id`, and `client_secret` parameters. This configuration is then used in the **AzureKeyValueStorage**.

You will need an Azure App directory App to use the Azure Key Vault integration.


For more information on Azure App Directory App registration and Permissions see the Azure documentation: https://learn.microsoft.com/en-us/azure/key-vault/general/authentication

1. Add Azure Key Vault Storage to Your Code

Now that the Azure connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use AzureKeyValueStorage as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an Azure Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by Azure Key Vault.

azure_keyvault_example_custom.cs
```
    using System;
using System.Linq;
using System.Threading.Tasks;
using SecretsManager;
using AzureKeyVault;
using Microsoft.Extensions.Logging;

public class Program
{
    private static async Task getOneIndividualSecret()
    {
        bool changeKey = false;
        bool decryptConfiguration = false;
        var tenant_id = "<TENANT_ID>";
        var client_secret = "<CLIENT_SECRET>";
        var client_id = "<CLIENT_ID>";

        var keyId = "<KEY_ID>";
        var keyId2 = "<KEY_ID_2>";

        var path = "ksmConfigDotnet.json";
        var dotnet_access_token = "<ACCESS_TOKEN>";
        var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Debug);
            builder.AddConsole();
        });

        var logger = loggerFactory.CreateLogger<AzureKeyValueStorage>();

        var azure_session_config = new AzureSessionConfig(tenant_id, client_id, client_secret);
        AzureKeyValueStorage azure_storage = new AzureKeyValueStorage(keyId, path, azure_session_config, logger);
        SecretsManagerClient.InitializeStorage(azure_storage, dotnet_access_token);
        
        if (changeKey)
        {
            azure_storage.ChangeKeyAsync(keyId2).Wait();
        }
        if (decryptConfiguration)
        {
            await azure_storage.DecryptConfigAsync();
        }
        var options = new SecretsManagerOptions(azure_storage);
                    var records_1 = await SecretsManagerClient.GetSecrets(options);
        records_1.Records.ToList().ForEach(record => Console.WriteLine(record.RecordUid + " - " + record.Data.title));
    }

    static async Task Main()
    {
        await getOneIndividualSecret();
    }
}
```


## Change Key 
This function is used to change the key configuration of the encrypted KSM configuration file.
```
    azure_storage.ChangeKeyAsync(keyId2).Wait();
```

## decrypt config

To decrypt the config file and save it again in plaintext, you can call the `DecryptConfigAsync` method on the `OciKeyValueStorage` instance.
Note: this will compromise the security of the config file.
```
    const storage = await new OciKeyValueStorage(keyId, keyVersionId, config_path, ociSessionConfig).init();
    storage.DecryptConfigAsync(true).wait(); // Saves to file
    const decryptedConfig = await storage.decryptConfig(false); // returns the decrypted config
```


## Logging
We support logging for the Oracle Key Vault integration. Supported log levels are as follows
* Trace
* Debug
* Information
* Warning
* Error
* Critical
* None
below is how we can use a logger of desired level, If none are selected then logger with information as default level will be selected
```
    using Microsoft.Extensions.Logging;

    var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Debug);
            builder.AddConsole();
        });
    var logger = loggerFactory.CreateLogger<AzureKeyValueStorage>();
    AzureKeyValueStorage azure_storage = new AzureKeyValueStorage(keyId, path, azure_session_config, logger);

```


You're ready to use the KSM integration 👍
Using the Azure Key Vault Integration

Once setup, the Secrets Manager Azure Key Vault integration supports all Secrets Manager dotNet SDK functionality. Your code will need to be able to access the Azure Key Vault APIs in order to manage the decryption of the configuration file when run. 
