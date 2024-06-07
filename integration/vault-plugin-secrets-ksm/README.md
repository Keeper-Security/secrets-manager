# Hashicorp Vault - Keeper Secrets Manager Plugin

KSM is a secrets engine plugin for [HashiCorp Vault](https://www.vaultproject.io/). It allows access to records in Keeper vault.

## Installation

Prerequisites:

- A basic understanding of [Hashicorp Vault](https://www.hashicorp.com/products/vault). Read this guide to [get started with Vault](https://learn.hashicorp.com/tutorials/vault/getting-started-install).
- [Hashicorp Vault Command Line](https://www.vaultproject.io/docs/install) Installed
- A running Vault server.

## Usage

Download archive with the [latest release](https://github.com/Keeper-Security/secrets-manager/releases/latest) for your platform and copy the plugin binary to the vault server plugin folder. Register and enable plugin in the Vault.  

```
vault plugin register -command=vault-plugin-secrets-ksm.exe -sha256=<SHA256> secret vault-plugin-secrets-ksm
vault secrets enable -path=ksm vault-plugin-secrets-ksm
```

**Note:** Do not run Vault in `dev` mode in production. The `dev` server allows you to configure the plugin directory as a flag, and automatically registers plugin binaries in that directory. In production, plugin binaries must be manually registered.

Configure plugin (once)
```
vault write ksm/config ksm_config=<Base64Config>
```

Once KSM is enabled and configured the plugin responds to the following commands:
```
# List available records in Keeper Vault
$ vault list ksm/records

# Retrieve secret from the KSM engine
$ vault read ksm/record uid=<UID>
Key      Value
---      -----
title    sm_test_record
type     login

# Retrieve TOTP from a secret
vault read -format=json ksm/record/totp uid=<UID>

# Update existing secret
vault write -format=json ksm/record uid=<UID> data=@updated_record.json

# Create new secret
vault write -format=json ksm/record/create folder_uid=<FolderUID> data=@record_data.json

# Delete existing secret
vault delete ksm/record uid=<UID>
```

## License
[MIT License](./LICENSE)
