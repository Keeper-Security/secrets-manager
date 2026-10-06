# GCP KSM
Keeper Secrets Manager integrates with GCP KMS in order to provide protection for Keeper Secrets Manager configuration files.  With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

## Features
* Encrypt and Decrypt your Keeper Secrets Manager configuration files with GCP KMS
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection.  Works with all Keeper Secrets Manager Javascript SDK functionality

## Prerequisites
* Supports the JavaScript Secrets Manager SDK
* `@google-cloud/kms` is bundled — no separate install required
* These are permissions required for service account:
  * Cloud KMS CryptoKey Decrypter (`roles/cloudkms.cryptoKeyDecrypter`)
  * Cloud KMS CryptoKey Encrypter (`roles/cloudkms.cryptoKeyEncrypter`)
  * Cloud KMS CryptoKey Public Key Viewer (`roles/cloudkms.publicKeyViewer`)
  * Cloud KMS Viewer (`roles/cloudkms.viewer`) — needed for `cloudkms.cryptoKeys.get`, which none of the three roles above include

## Behavior Notes (v1.1.0)

* **Node.js 22 or later is required.** Earlier versions are no longer supported.
* **The directory holding the config file must be writable, not only the config file itself.** Writes create a temporary file alongside the config file and rename it into place, which needs permission to create and rename entries in that directory. A deployment that mounts a writable config file inside a read-only directory now fails with `EACCES` on every `init()`, `saveString()`, `saveBytes()`, `saveObject()`, and `delete()`.
* **A config path that has a hard-linked peer is now replaced rather than written through, and a config path that is a symbolic link is refused.** A hard-linked backup stops tracking the config. This is silent: the write reports success and raises no error. A write to a symbolic link rejects with an error that names the path. Point your config file location, or `KSM_CONFIG_FILE`, at the real file rather than at a link.
* **A config path that is a symbolic link is refused on read as well as on write.** `init()` and `decryptConfig()` both throw a clear error naming the path instead of reading through the link, including when the link is dangling (its target does not exist yet). The save methods (`saveString()`, `saveBytes()`, `saveObject()`, `saveStorage()`, `delete()`, and `deleteAll()`) reject the same way. Point your config file location, or `KSM_CONFIG_FILE`, at the real file.
* **A zero-length config file is now a hard error instead of being treated as an empty config.** A zero-length file means an interrupted or truncated write, not "no config yet". `init()` and `decryptConfig()` now both throw and leave the file untouched, so you can restore it from a backup rather than have it silently re-encrypted over the top (which would have destroyed the client ID, app key, and device private key).
* **Every public method except `init()` rejects until `init()` finishes.** The rejection is a `GCPKeyValueStorageError` that names `init()`. A failed `init()` leaves the instance unusable. Before 1.1.0, a call such as `isEmpty()` or `saveString()` on an instance that never ran `init()` worked against an empty config. Call and await `init()` once before any other method.
* **A config file that parses as JSON but is not an object of string values is now a hard error.** `init()` rejects and leaves the file untouched when the file holds `null`, an array, a number, or an object with a non-string value. Restore the file from a backup, or delete it to create a new configuration.
* **Config file writes land at file mode `0600`** (owner read/write only), including correcting a pre-existing file's mode from an earlier SDK version.
* **The config directory is created at mode `0700`** (owner read/write/execute only) the first time the SDK creates it. An already-existing directory is left at whatever mode it already had.
* **A config file that a different user owns, or that group or world users can write, is refused on read (POSIX only).** `init()` and `decryptConfig()` throw an error that names the path and the reason. The process user and root count as owners. The check runs before any write, so the SDK does not first correct the mode of an existing file. Version 1.0.0 created the config file with the process umask and no explicit mode. A umask of `002` gives mode `0664`, and a file at that mode fails this check. Run `chmod 600` on the file, and make sure the account that runs your application owns it, before you upgrade.
* **On Windows, the file mode and ownership protections above do not apply.** Node.js does not apply POSIX file modes on Windows, so the `0600` and `0700` modes have no effect there. The config read does not check file ownership or mode. Another local user who can create files in the config directory can plant a config file where none exists yet, and the SDK uses it. A config file that already exists cannot be replaced this way. The mode of a plaintext file written by `decryptConfig(true)` does not apply either, so who can read it depends on the access list of the directory. Limit the directory as shown in [Restricting the config directory on Windows](#restricting-the-config-directory-on-windows), and set `KSM_CONFIG_FILE` to an absolute path inside it. A symbolic link at the config path is still refused on read and write. Windows has no `O_NOFOLLOW`, so the read-side refusal runs as a check just before the open, and a link swapped in between the two steps is not caught. Anyone who can replace the config file can win that race, so limiting who can write to the config directory is the control that matters.
* **A save can fail with `EPERM` on Windows if another process, or antivirus software, holds the config file open at that moment.** The SDK replaces the config by renaming a temporary file over it, and Windows refuses that rename while the file is open elsewhere. The existing config file is left intact and the error reaches your code, so retry the save. Await `init()` once per instance before you call other methods, and do not call it twice at the same time.
* **This package no longer imports `google-auth-library` directly**, so it now installs and loads correctly under Yarn's default Plug'n'Play linker (Yarn 3 and later, run through `yarn node` rather than a bare `node`) and under pnpm with `hoist: false` set in `pnpm-workspace.yaml`. By default, the GCP KMS client uses the Application Default Credentials (ADC), described below, unless you call `createClientFromCredentialsFile()` or `createClientUsingCredentials()`. `getToken()` now returns a valid access token on the ADC path too, which previously silently returned `undefined` and could send a `RAW_ENCRYPT_DECRYPT` key down the wrong crypto path. A `RAW_ENCRYPT_DECRYPT` key with no usable token now raises a named error instead of silently taking the wrong path, and a failed token request now raises only the error message, never the underlying auth-library error object, which can carry credential material.

### Restricting the config directory on Windows

A directory inherits its access list from its parent, and the `0700` mode has no effect on Windows. Under a user profile, the inherited list already limits access to that user, SYSTEM, and Administrators. Elsewhere it can be wider. For example, `BUILTIN\Users` can add files to many non-profile directories, and `Authenticated Users` can modify files under the root of `C:\`.

To create a directory that only the account that runs your application, SYSTEM, and Administrators can use, run this once in an elevated PowerShell before the first `init()`. Replace the account with the one that runs your application, which may not be the account you are logged in with:

```powershell
$account = "DOMAIN\app-account"
New-Item -ItemType Directory -Path C:\keeper\config | Out-Null
icacls C:\keeper\config /inheritance:r /grant:r "${account}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
```

`*S-1-5-18` is SYSTEM and `*S-1-5-32-544` is Administrators. The SID form works on every Windows language, where the group names are translated.

Then set `KSM_CONFIG_FILE`, or the config file location you pass to the constructor, to an absolute path inside that directory, such as `C:\keeper\config\client-config.json`. Files the SDK creates there inherit the same access. Run `icacls C:\keeper\config` to check the result. It must list only the application account, SYSTEM, and Administrators.

## Setup

1. Install KSM Storage Module

The Secrets Manager GCP KSM module can be installed using npm

> `npm install @keeper-security/secrets-manager-gcp`

2. Configure GCP Connection

By default the @google-cloud/kms library will utilize the default connection session setup with the GCP CLI with the gcloud auth command.  If you would like to specify the connection details, the two configuration files located at `~/.config/gcloud/configurations/config_default` and `~/.config/gcloud/legacy_credentials/<user>/adc.json` can be manually edited.

See the GCP documentation for more information on setting up a GCP session [here](https://cloud.google.com/sdk/gcloud/reference/auth)

Alternatively, configuration variables can be provided explicitly as a service account file using `GCPKSMClient` and its `createClientFromCredentialsFile()` method with a path to the service account JSON file.

You will need a GCP service account to use the GCP KMS integration.

For more information on GCP service accounts see the [GCP documentation](https://cloud.google.com/iam/docs/service-accounts)

3. Add GCP KMS Storage to Your Code

Now that the GCP connection has been configured, you need to tell the Secrets Manager SDK to utilize the KMS as storage.

To do this, use `GCPKeyValueStorage` as your Secrets Manager storage in the SecretsManager constructor.

The storage will require a GCP Key ID, as well as the name of the Secrets Manager configuration file which will be encrypted by GCP KMS. We need to make sure that key version is present in key ID provided.
```
    import { getSecrets, initializeStorage } from '@keeper-security/secrets-manager-core';
    import {GCPKeyValueStorage,GCPKeyConfig,GCPKSMClient,LoggerLogLevelOptions} from "@keeper-security/secrets-manager-gcp";

    const getKeeperRecordsGCP = async () => {

        // example key : projects/<project>/locations/<location>/keyRings/<key>/cryptoKeys/<key_name>/cryptoKeyVersions/<key_version>
        const keyConfig = new GCPKeyConfig("<key_version_resource_url>");
        const gcpSessionConfig = new GCPKSMClient().createClientFromCredentialsFile('<gcp_credentials_json_location>')
        // Falls back to the KSM_CONFIG_FILE environment variable if this is null, undefined,
        // or blank, and to a default location if KSM_CONFIG_FILE is also unset or blank.
        const configPath = "<path to client-config-gcp.json>"
        const logLevel = LoggerLogLevelOptions.info;

        // oneTimeToken is used only once to initialize the storage
        // after the first run, subsequent calls will use the encrypted config file
        const oneTimeToken = "<one time token>";

        const storage = await new GCPKeyValueStorage(configPath, keyConfig, gcpSessionConfig, logLevel).init();
        await initializeStorage(storage, oneTimeToken);

        const {records} = await getSecrets({storage: storage});

        const firstRecord = records[0];
        const password = firstRecord.data.fields.find((x: { type: string; }) => x.type === 'password');
        console.log(password.value[0]);
    }
    getKeeperRecordsGCP()
```
### Change Key

You can change the key used to encrypt and decrypt your configuration file by calling the `changeKey` method on the `GCPKeyValueStorage` instance.
```javascript
const newKeyConfig = new GCPKeyConfig("<new_key_version_resource_url>");
const storage = await new GCPKeyValueStorage(configPath, keyConfig, gcpSessionConfig).init();
await storage.changeKey(newKeyConfig);
```

### Decrypt Config

You can decrypt the configuration file to migrate to a different cloud provider or to retrieve your raw credentials. Pass `true` to save the decrypted configuration back to the file, or `false` to return the plaintext without modifying the file.
```javascript
const storage = await new GCPKeyValueStorage(configPath, keyConfig, gcpSessionConfig).init();

// Returns plaintext only (file stays encrypted)
const plaintext = await storage.decryptConfig(false);

// OR: returns plaintext and saves config as plaintext
const saved = await storage.decryptConfig(true);
```

**Warning**: `decryptConfig(true)` writes the client ID, app key, and device private key to disk **in plaintext** at the config file's path, replacing the encrypted file. Anything that can read that file, including backups, snapshots, and container image layers, can read those credentials until you re-encrypt it. The write does land at file mode `0600` (owner read/write only), which limits exposure to other local users on the same machine, but the data itself is plaintext on disk.

To return to an encrypted config, construct a new `GCPKeyValueStorage` against the same path and call `.init()` on it.
`loadConfig()` detects the plaintext config file and re-encrypts it in place before `init()` returns.
Do not call `init()` again on the instance that called `decryptConfig(true)`.
That instance does not re-encrypt the file, and the file stays in plaintext.

## Logging
We support logging for the GCP KMS integration. Supported log levels are as follows
* trace
* debug
* info
* warn
* error
* fatal

All these levels should be accessed from the `LoggerLogLevelOptions` enum. If no log level is set, the default log level is `info`. We can set the logging level to debug to get more information about the integration.

You're ready to use the KSM integration 👍
Using the GCP KMS Integration

Once setup, the Secrets Manager GCP KMS integration supports all Secrets Manager JavaScript SDK functionality. Your code will need to be able to access the GCP KMS APIs in order to manage the decryption of the configuration file when run.
