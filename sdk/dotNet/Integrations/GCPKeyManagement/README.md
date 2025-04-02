# GCP KSM
Keeper Secrets Manager integrates with GCP KMS in order to provide protection for Keeper Secrets Manager configuration files.  With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

## Features
* Encrypt and Decrypt your Keeper Secrets Manager configuration files with GCP KMS
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection.  Works with all Keeper Secrets Manager dotnet SDK functionality

## Prerequisites
* Supports the dotnet Secrets Manager SDK
* Supports dotnet version `net9.0`
* Requires `Google.Cloud.Kms.V1` package
* These are permissions required for service account:
  * Cloud KMS CryptoKey Decrypter
  * Cloud KMS CryptoKey Encrypter
  * Cloud KMS CryptoKey Public Key Viewer

## Setup

1. Install KSM Storage Module

The Secrets Manager GCP KSM module can be installed using the NuGet package manager.

> `dotnet add package Keeper.SecretsManager.GCPKeyManagement`

2. Configure GCP Connection

By default the Google.Cloud.Kms.V1 library will utilize the default connection session setup with the GCP CLI with the gcloud auth command.  If you would like to specify the connection details, the two configuration files located at `~/.config/gcloud/configurations/config_default` and `~/.config/gcloud/legacy_credentials/<user>/adc.json` can be manually edited.

See the GCP documentation for more information on setting up an GCP session (https://cloud.google.com/sdk/gcloud/reference/auth)[here]

Alternatively, configuration variables can be provided explicitly as a service account file using the GcpSessionConfig data class and providing  a path to the service account json file.

You will need a GCP service account to use the GCP KMS integration.

For more information on GCP service accounts see the (https://cloud.google.com/iam/docs/service-accounts)[GCP documentation]

3. Add GCP KMS Storage to Your Code

Now that the GCP connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use GcpKmsKeyValueStorage as your Secrets Manager storage in the SecretsManager constructor.

The storage will require a GCP Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by GCP KMS.
```
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using SecretsManager;
    using GCPKeyManagement;
    using Microsoft.Extensions.Logging;

    public class Program
    {
        private static async Task getOneIndividualSecret()
        {
            Console.WriteLine("execution started");

            string key1ResourceName = "<KEY1ResourceURL>";
            string key2ResourceName = "<Key2ResourceURL>";
            string gcpConfigFilePath = "<GCP config file path>";

            var keyConfig1 = new GCPKeyConfig(key1ResourceName);
            var keyConfig2 = new GCPKeyConfig(key2ResourceName);

            var gcpSessionConfig = new GCPKMSClient().CreateClientFromCredentialsFile(gcpConfigFilePath);

            bool changeKey = true;
            bool decryptConfiguration = true;

            var path = "gcp_ksm_conf.json";
            var dotnet_access_token = "[One_Time_Token]";

            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.SetMinimumLevel(LogLevel.Debug);
                builder.AddConsole();
            });

            var logger = loggerFactory.CreateLogger<GCPKeyValueStorage>();

            var gcp_storage = new GCPKeyValueStorage(keyConfig2, gcpSessionConfig, path,logger);
            
            SecretsManagerClient.InitializeStorage(gcp_storage, dotnet_access_token);
            
            if (changeKey)
            {
                gcp_storage.ChangeKeyAsync(keyConfig1).Wait();
            }
            if (decryptConfiguration)
            {
                var conf = await gcp_storage.DecryptConfigAsync(false);
                Console.WriteLine(conf);
            }
            var options = new SecretsManagerOptions(gcp_storage);
            var records_1 = await SecretsManagerClient.GetSecrets(options);
            records_1.Records.ToList().ForEach(record => Console.WriteLine(record.RecordUid + " - " + record.Data.title));
        }

        static async Task Main()
        {
            await getOneIndividualSecret();
        }
    }
```
 ### Change key

You can change the key used to encrypt and decrypt your configuration file by calling the changeKey method on the storage object.
```
  var gcp_storage = new GCPKeyValueStorage(keyConfig2, gcpSessionConfig, path,logger);
  gcp_storage.ChangeKeyAsync(keyConfig1).Wait();
```

### Decrypt config
We can decrypt the configuration file and revert it back to plaintext and save it in default location if needed.
```
  var conf = await gcp_storage.DecryptConfigAsync(false);
  Console.WriteLine(conf);
```

## Logging
We support logging for the Google Key Vault integration. Supported log levels are as follows
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
    var logger = loggerFactory.CreateLogger<GCPKeyValueStorage>();
    GCPKeyValueStorage gcp_storage = new GCPKeyValueStorage(keyId, path, gcpSessionConfig, logger);
```
You're ready to use the KSM integration 👍
Using the GCP KMS Integration

Once setup, the Secrets Manager GCP KMS integration supports all Secrets Manager DotNet SDK functionality. Your code will need to be able to access the GCP KMS APIs in order to manage the decryption of the configuration file when run.