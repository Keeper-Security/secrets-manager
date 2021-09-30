# Keeper PowerShell SecretManagement Extension

## Installation

Pre-requisites are installed Microsoft.PowerShell.SecretManagement module, plus one of the extension vaults from [Microsoft SecretManagement](https://www.powershellgallery.com/packages?q=Tags%3A%22SecretManagement%22). The extension vault is used to store Keeper configuration, and we recommend that you use an extension that stores the secrets locally. [Microsoft.Powershell.SecretStore](https://www.powershellgallery.com/packages/Microsoft.PowerShell.SecretStore) and [SecretManagement.KeyChain](https://www.powershellgallery.com/packages/SecretManagement.KeyChain) are the good candidates for the job.

```PowerShell
Install-Module Microsoft.PowerShell.SecretManagement, SecretsManagement.Keeper, SecretManagement.KeyChain
```
Then, if you don't have a vault already, create a vault that would be used to store [Keeper Secrets Manager](https://docs.keeper.io/secrets-manager/secrets-manager) configuration (you will be using the name of this vault to register Keeper Vault): 

```PowerShell
Register-SecretVault -Name KeyChain2 -ModuleName SecretManagement.KeyChain
```

## Vault Registration

```PowerShell
Register-KeeperVault -Name Keeper -OneTimeToken US:UlpJ83zXbuT3qaVc7VC3lXkAAOzVyHV6Zv-xPBNgzT0 -LocalVaultName KeyChain2
```
Registers a SecretManagement Vault, similarly as if registering with 

*Register-SecretVault -Name Keeper -ModuleName SecretManagement.Keeper*

In addition to the vault registration with SecretManagement, **Register-KeeperVault** also converts the one time token into [Keeper Secrets Manager](https://docs.keeper.io/secrets-manager/secrets-manager) config, which is subsequentially stored in the vault specified by the **LocalVaultName** parameter.

If you register Keeper Vault with **Register-SecretVault**, you won't be able to get Keeper secrets since the configuration will be missing.

If **LocalVaultName** parameter is missing, **Register-KeeperVault** will put the [Keeper Secrets Manager](https://docs.keeper.io/secrets-manager/secrets-manager) config into a Microsoft.PowerShell.SecretStore vault, if one is registered with SecretsManagement.

## Getting secret info

```PowerShell
Get-SecretInfo -Vault Keeper
```
This will print something like
```
Name           Type      VaultName
----           ----      ---------
Home SSH       Hashtable Keeper
ACME Login     Hashtable Keeper
```
where Name column will contain the titles of the records shared to the [Keeper Secrets Manager](https://docs.keeper.io/secrets-manager/secrets-manager) client specified at the registration time by the OneTimeToken. 

## Getting a secret

```PowerShell
Get-Secret "ACME Login" -AsPlainText
```
This will print something like
```
Name                           Value
----                           -----
login                          user2
password                       123
Files                          {file1.json, file2.zip}
```
If you want to access a specific field, you can specify the field directly using dot notation:

```PowerShell
Get-Secret "ACME Login.password" -AsPlainText
```

## Setting a secret

```PowerShell
Set-Secret "ACME Login.password" "456" -AsPlainText
```
Currently, setting a secret can only set a single field on a Keeper record. It also cannot create new records, and is only capable of updating existing ones.

## Removing a secret
Removing individual secrets using Powershell is not supported. If you do not need the secret anymore, remove if from the [Keeper Secrets Manager](https://docs.keeper.io/secrets-manager/secrets-manager) application, or unregister the SecretManagement.Keeper Vault with  

```PowerShell
Remove-Secret ALL -Vault "Keeper"
```
**Remove-Secret ALL** is a "magic" command that will unregister the specified vault from SecretsManagement and remove the configuration from the local vault.

## Downloading a file

To download a file, use dot notation while specifying the file title in square brackets, and pipeline the binary output to the Set-Content Cmdlet:

```PowerShell
Get-Secret R2.files[file1.json] | Set-Content -Path ./file1.json -AsByteStream
```
