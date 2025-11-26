# AWS KSM
Keeper Secrets Manager integrates with AWS KMS in order to provide protection for Keeper Secrets Manager configuration files.  With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

## Features
* Encrypt and Decrypt your Keeper Secrets Manager configuration files with AWS KMS.
* Protect against unauthorized access to your Secrets Manager connections.
* Requires only minor changes to code for immediate protection. Works with all Keeper Secrets Manager dotnet SDK functionality.

## Prerequisites
* Supports the dotNet Secrets Manager SDK.
* Requires `AWSSDK.KeyManagementService` package.
* Supports dotnet version `net9.0`
* Key needs `Encrypt` and `Decrypt` permissions.

## Setup

1. Install KSM Storage Module

The Secrets Manager AWS KSM module can be installed using dotnet.

> `dotnet add package Keeper.SecretsManager.AWSKeyManagement`

2. Configure AWS Connection

By default the aws-sdk library will utilize the default connection session setup with the AWS CLI with the aws configure command. If you would like to specify the connection details, the two configuration files located at `~/.aws/config` and `~/.aws/credentials` can be manually edited.

See the AWS documentation for more information on setting up an AWS session [here](https://docs.aws.amazon.com/cli/latest/reference/configure/)

Alternatively, configuration variables can be provided explicitly as an access key using the AwsSessionConfig data class and providing  `awsAccessKeyId` , `awsSecretAccessKey` and  `region` variables.

You will need an AWS Access Key to use the AWS KMS integration.

For more information on AWS Access Keys see the [AWS documentation](https://aws.amazon.com/premiumsupport/knowledge-center/create-access-key/)

3. Add AWS KMS Storage to Your Code

Now that the AWS connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use `AWSKeyValueStorage` as your Secrets Manager storage in the `SecretsManager` constructor.

The storage will require an AWS Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by AWS KMS.
```
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using SecretsManager;
    using Org.BouncyCastle.Tls.Crypto.Impl;
    using AWSKeyManagement;
    using System.IO;

    public class Program
    {
        private static async Task getOneIndividualSecret()
        {
            bool changeKey = false;
            bool decryptConfiguration = true;
            var accessKeyId ="<ACCESS_KEY_ID>" ;
            var secretAccessKey = "<SECRET_ACCESS_KEY>";
            var regionName = "<AWS_REGION_STRING";

            var keyId = "<KEY_ID_1>";
            var keyId2 = "<KEY_ID_2>";
            var keyId3 = "<KEY_ID_3>";

            var path = "<KEEPER_CONFIG_FILE_PATH>";
            var dotnet_access_token = "<ONE_TIME_TOKEN>";

            var awsSessionConfig = new AWSSessionConfig(accessKeyId,secretAccessKey,regionName);
            var awsSessionConfig2 = new AWSSessionConfig();

            var aws_storage = new AWSKeyValueStorage(keyId, path, awsSessionConfig);
            
            SecretsManagerClient.InitializeStorage(aws_storage, dotnet_access_token);
            
            if (changeKey)
            {
                aws_storage.ChangeKeyAsync(keyId3).Wait();
            }
            if (decryptConfiguration)
            {
                var conf = await aws_storage.DecryptConfigAsync(false);
                Console.WriteLine(conf);
            }
            var options = new SecretsManagerOptions(aws_storage);
            var records_1 = await SecretsManagerClient.GetSecrets(options);
            records_1.Records.ToList().ForEach(record => Console.WriteLine(record.RecordUid + " - " + record.Data.title));
        }

        static async Task Main()
        {
            await getOneIndividualSecret();
        }
    }
```

## Change Key operation and using default credentials from AWS
```
    using Microsoft.Extensions.Logging;

    var awsSessionConfig2 = new AWSSessionConfig();
    var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Debug);
            builder.AddConsole();
        });

    var logger = loggerFactory.CreateLogger<AWSKeyValueStorage>();

    var aws_storage = new AWSKeyValueStorage(keyId, path, awsSessionConfig2,logger);

```

## Decrypt config operation
we can decrypt config and save locally the decrypted file original config
```
    var conf = await aws_storage.DecryptConfigAsync(false);
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

    var logger = loggerFactory.CreateLogger<AWSKeyValueStorage>();
    var aws_storage = new AWSKeyValueStorage(keyId, path, awsSessionConfig2,logger);
```

You're ready to use the KSM integration Using the AWS KMS Integration 👍

Once setup, the Secrets Manager AWS KMS integration supports all Secrets Manager dotNet SDK functionality.  Your code will need to be able to access the AWS KMS APIs in order to manage the decryption of the configuration file when run. 