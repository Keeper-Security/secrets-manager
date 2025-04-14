# AWS KSM
Keeper Secrets Manager integrates with AWS KMS in order to provide protection for Keeper Secrets Manager configuration files.  With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

## Features
* Encrypt and Decrypt your Keeper Secrets Manager configuration files with AWS KMS.
* Protect against unauthorized access to your Secrets Manager connections.
* Requires only minor changes to code for immediate protection. Works with all Keeper Secrets Manager Javascript SDK functionality.

## Prerequisites
* Supports the JavaScript Secrets Manager SDK.
* Requires `@aws-sdk/client-kms` package.
* Key needs `Encrypt` and `Decrypt` permissions.

## Setup

1. Install KSM Storage Module

The Secrets Manager AWS KSM module can be installed using npm.

> `npm install @keeper-security/secrets-manager-aws`

2. Configure AWS Connection

By default the @aws-sdk library will utilize the default connection session setup with the AWS CLI with the aws configure command. If you would like to specify the connection details, the two configuration files located at `~/.aws/config` and `~/.aws/credentials` can be manually edited.

See the AWS documentation for more information on setting up an AWS session [here](https://docs.aws.amazon.com/cli/latest/reference/configure/)

Alternatively, configuration variables can be provided explicitly as an access key using the AwsSessionConfig data class and providing  `awsAccessKeyId` , `awsSecretAccessKey` and  `region` variables.

You will need an AWS Access Key to use the AWS KMS integration.

For more information on AWS Access Keys see the [AWS documentation](https://aws.amazon.com/premiumsupport/knowledge-center/create-access-key/)

3. Add AWS KMS Storage to Your Code

Now that the AWS connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use `AWSKeyValueStorage` as your Secrets Manager storage in the `SecretsManager` constructor.

The storage will require an AWS Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by AWS KMS.
```
    import {AWSKeyValueStorage,AWSSessionConfig,LoggerLogLevelOptions} from "@keeper-security/secrets-manager-aws";

    const getKeeperRecordsAWS = async () => {

        const accessKeyId ="<YOUR AWS ACCESS KEY>>";
        const secretAccessKey = "<YOUR AWS SECRET_ACCESS_KEY>";
        const regionName = "<YOUR AWS REGION>";
    
        const awsSessionConfig = new AWSSessionConfig(accessKeyId, secretAccessKey, regionName);
            
        // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use ksm-config.txt
        const oneTimeToken = <one time token>;
        const logLevel = LoggerLogLevelOptions.Debug;
        const keyId = 'arn:aws:kms:ap-south-1:<accountName>:key/<keyId>';
        const storage = await new AWSKeyValueStorage(keyId,config_path,awsSessionConfig,logLevel).init();
        
        await initializeStorage(storage, oneTimeToken);
        
        // Using token only to generate a config (for later usage)
        // requires at least one access operation to bind the token
        
        const {records} = await getSecrets({storage: storage});
        console.log(records);
    
        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    }
    console.log("start");
    getKeeperRecordsAWS();
```

## Change Key operation and using default credentials from AWS
```
    import {AWSKeyValueStorage,AWSSessionConfig} from "@keeper-security/secrets-manager-aws";

    const getKeeperRecordsAWS = async () => {

        const awsSessionConfig2 = new AWSSessionConfig();
        let config_path = "<path to client-config-aws.json>";        
        const oneTimeToken = "US:kYKVGFJ2605-9UBF4VXd14AztMPXcxZ56zC9gr7O-Cw";
        const keyId = 'arn:aws:kms:ap-south-1:<accountName>:key/<keyId>';
        const keyId2 = "arn:aws:kms:<cloud-region>:<accountNumber>:key/<keyId2>"
        const storage = await new AWSKeyValueStorage(keyId,config_path).init();
        await storage.changeKey(keyId2);
        await initializeStorage(storage, oneTimeToken);
    
        const {records} = await getSecrets({storage: storage});
        console.log(records);
    
        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    }
    console.log("start");
    getKeeperRecordsAWS();
```

## Decrypt config operation
we can decrypt config and save locally the decrypted file original config
```
    const storage = await new AWSKeyValueStorage(keyId,config_path).init();
    await storage.decryptConfig();    
```

## Logging
We support logging for the AWS KSM integration. Supported log levels are as follows
* trace
* debug
* info
* warn
* error
* fatal
All these levels should be accessed from the LoggerLogLevelOptions enum. If no log level is set, the default log level is info. We can set the logging level to debug to get more information about the integration.

You're ready to use the KSM integration Using the AWS KMS Integration 👍

Once setup, the Secrets Manager AWS KMS integration supports all Secrets Manager JavaScript SDK functionality.  Your code will need to be able to access the AWS KMS APIs in order to manage the decryption of the configuration file when run. 