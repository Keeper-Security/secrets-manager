# GCP KSM
Keeper Secrets Manager integrates with GCP KMS in order to provide protection for Keeper Secrets Manager configuration files.  With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

## Features
* Encrypt and Decrypt your Keeper Secrets Manager configuration files with GCP KMS
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection.  Works with all Keeper Secrets Manager Javascript SDK functionality

## Prerequisites
* Supports the JavaScript Secrets Manager SDK
* Requires `@google-cloud/kms` package
* These are permissions required for service account:
  * Cloud KMS CryptoKey Decrypter
  * Cloud KMS CryptoKey Encrypter
  * Cloud KMS CryptoKey Public Key Viewer

## Setup

1. Install KSM Storage Module

The Secrets Manager GCP KSM module can be installed using npm

> `npm install @keeper-security/secrets-manager-gcp`

2. Configure GCP Connection

By default the @google-cloud/kms library will utilize the default connection session setup with the GCP CLI with the gcloud auth command.  If you would like to specify the connection details, the two configuration files located at `~/.config/gcloud/configurations/config_default` and `~/.config/gcloud/legacy_credentials/<user>/adc.json` can be manually edited.

See the GCP documentation for more information on setting up an GCP session [here](https://cloud.google.com/sdk/gcloud/reference/auth)

Alternatively, configuration variables can be provided explicitly as a service account file using the GcpSessionConfig data class and providing  a path to the service account json file.

You will need a GCP service account to use the GCP KMS integration.

For more information on GCP service accounts see the [GCP documentation](https://cloud.google.com/iam/docs/service-accounts)

3. Add GCP KMS Storage to Your Code

Now that the GCP connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use GcpKmsKeyValueStorage as your Secrets Manager storage in the SecretsManager constructor.

The storage will require a GCP Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by GCP KMS. We need to make sure that key version is present in key ID provided.
```
    import {GCPKeyValueStorage,GCPKeyConfig,GCPKSMClient,LoggerLogLevelOptions} from "@keeper-security/secrets-manager-gcp";

    const getKeeperRecordsGCP = async () => {

        // example key : projects/<project>/locations/<location>/keyRings/<key>/cryptoKeys/<key_name>/cryptoKeyVersions/<key_version>
        const keyConfig2  = new GCPKeyConfig("<key_version_resource_url_1>");
        const keyConfig = new GCPKeyConfig("key_version_resource_url_2");
        console.log("extracted key details")
        const gcpSessionConfig = new GCPKSMClient().createClientFromCredentialsFile('<gcp_credentials_json_location>')
        console.log("extracted gcp session config")
        let config_path = "<path to client-config-gcp.json>"
        let logLevel = LoggerLogLevelOptions.<log level>;

        // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use ksm-config.txt
        const oneTimeToken = "<one time token>";
        
        const storage = await new GCPKeyValueStorage(config_path,keyConfig2,gcpSessionConfig,logLevel).init();
        await initializeStorage(storage, oneTimeToken);
        
        const {records} = await getSecrets({storage: storage});
        console.log(records)

        const firstRecord = records[0];
        const firstRecordPassword = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'bankAccount');
        console.log(firstRecordPassword.value[0]);
    }
    console.log("start")
    getKeeperRecordsGCP()
```
 ### Change key

You can change the key used to encrypt and decrypt your configuration file by calling the changeKey method on the storage object.
```
  const storage = await new GCPKeyValueStorage(configPath,keyConfig,gcpSessionConfig).init();
  await storage.changeKey(keyConfig2);
```

### Decrypt config
We can decrypt the configuration file and revert it back to plaintext and save it in default location if needed.
```
  const storage = await new GCPKeyValueStorage(configPath,keyConfig,gcpSessionConfig).init();
  await storage.decryptConfig(true);
```

## Logging
We support logging for the AWS KSM integration. Supported log levels are as follows
* trace
* debug
* info
* warn
* error
* fatal

All these levels should be accessed from the `LoggerLogLevelOptions` enum. If no log level is set, the default log level is `info`. We can set the logging level to debug to get more information about the integration.
`
You're ready to use the KSM integration 👍
Using the GCP KMS Integration

Once setup, the Secrets Manager GCP KMS integration supports all Secrets Manager JavaScript SDK functionality. Your code will need to be able to access the GCP KMS APIs in order to manage the decryption of the configuration file when run.
