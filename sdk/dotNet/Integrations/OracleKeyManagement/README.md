# Oracle Key Management
Keeper Secrets Manager integrates with **Oracle Key Vault Management Service (OCI KMS)** to provide protection for Keeper Secrets Manager configuration files. With this integration, you can secure connection details on your machine while leveraging Keeper's **zero-knowledge encryption** for all your secret credentials.

## Features
* Encrypt and decrypt your Keeper Secrets Manager configuration files using **OCI KMS**.
* Protect against unauthorized access to your **Secrets Manager connections**.
* Requires only minor code modifications for immediate protection. Works with all Keeper Secrets Manager **dotnet SDK** functionality.

## Prerequisites
* Supports the dotNet Secrets Manager SDK.
* Supports dotnet version `net9.0`
* Requires the **OCI.DotNetSDK.Keymanagement** package from OCI SDK.
* OCI KMS Key needs `ENCRYPT` and `DECRYPT` permissions.

## Setup

1. Install KSM Storage Module

The Secrets Manager oracle KSM module can be installed using dotnet nuget package manager.

> `dotnet add package Keeper.SecretsManager.OracleKeyManagement`

2. Configure oracle Connection

By default, the **OCI.DotNetSDK.Keymanagement** library will use the **default OCI configuration file** (`~/.oci/config`).

See the (OCI documentation)[https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm] for more details.

3. Add oracle KMS Storage to Your Code

Now that the oracle connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use `OracleKeyValueStorage` as your Secrets Manager storage in the SecretsManager constructor.

The storage will require an `Oracle config file location`, `Oracle configuration profile`(if there are multiple profile configurations) and the OCI `Oracle KMS endpoint` as well as the name of the `Secrets Manager configuration file` which will be encrypted by Oracle KMS.
```
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;
    using OracleKeyManagement;
    using SecretsManager;

    public class Program
    {
        private static async Task getOneIndividualSecret()
        {
            Console.WriteLine("execution started");
            bool changeKey = false;
            bool decryptConfiguration = false;

            var OCIConfigFileLocation = "location";
            var profile = "DEFAULT";
            var kmsCryptoEndpoint = "crypto_endpoint";
            var kmsManagementEndpoint = "management_endpoint";

            var ociSessionConfig1 = new OciSessionConfig(OCIConfigFileLocation, profile, kmsCryptoEndpoint, kmsManagementEndpoint); 

            var path = "oci_ksm_conf_test.json";

            string keyId1 = "key1";
            string keyId2 = "key2";

            string keyVersionId1 = "key1version";
            string keyVersionId2 = "key2version";

            
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.SetMinimumLevel(LogLevel.Debug);
                builder.AddConsole();
            });

            var logger = loggerFactory.CreateLogger<OracleKeyValueStorage>();
            var oracle_storage = new OracleKeyValueStorage(keyId2,keyVersionId2,path,ociSessionConfig1,logger );
            
            var dotnet_access_token = "<accesstoken>";


            SecretsManagerClient.InitializeStorage(oracle_storage, dotnet_access_token);

            if (changeKey)
            {
                oracle_storage.ChangeKeyAsync(keyId1,keyVersionId1,null).Wait();
            }
            if (decryptConfiguration)
            {
                var conf = await oracle_storage.DecryptConfigAsync(true);
                Console.WriteLine(conf);
            }
            var options = new SecretsManagerOptions(oracle_storage);
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

To change the Oracle KMS key used for encryption, you can call the `ChangeKeyAsync` method on the `OracleKeyValueStorage` instance.
```
    var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.SetMinimumLevel(LogLevel.Debug);
                builder.AddConsole();
            });

    var logger = loggerFactory.CreateLogger<OracleKeyValueStorage>();
    var oracle_storage = new OracleKeyValueStorage(keyId2,keyVersionId2,path,ociSessionConfig1,logger );
```

## decrypt config

To decrypt the config file and save it again in plaintext, you can call the `DecryptConfigAsync` method on the `OracleKeyValueStorage` instance.
Note: this will compromise the security of the config file.
```
    var conf = await oracle_storage.DecryptConfigAsync(true);
    Console.WriteLine(conf);
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
    var logger = loggerFactory.CreateLogger<OracleKeyValueStorage>();
    var oracle_storage = new OracleKeyValueStorage(keyId2,keyVersionId2,path,ociSessionConfig1,logger );
```

You're ready to use the KSM integration Using the Oracle KMS Integration 👍

Once setup, the Secrets Manager Oracle KMS integration supports all Secrets Manager dotNet SDK functionality.  Your code will need to be able to access the Oracle KMS APIs in order to manage the decryption of the configuration file when run. 