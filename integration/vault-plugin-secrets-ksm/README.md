# Vault Keeper Secrets Manager Plugin

KSM is a secrets engine plugin for [HashiCorp Vault](https://www.vaultproject.io/). It allows access to records in a Keeper vault.

## Usage

Download archive with the [latest release](https://github.com/Keeper-Security/secrets-manager/releases/latest) for your platform and copy it to the corresponding plugin folder. Register and enable plugin in the Vault.  

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
$ vault read ksm/secrets

# Retrieve secret from the KSM engine
$ vault read ksm/record uid=<UID>
Key      Value
---      -----
title    sm_test_record
type     login
```

## License
[MIT License](./LICENSE)
