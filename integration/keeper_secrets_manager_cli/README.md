# Keeper Secrets Manager CLI

The Keeper Secrets Manager command line interface

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/secrets-manager-command-line-interface

# Change History

## 1.1.1

* KSM-429 - Add `--profile-name` to `ksm profile import` command

## 1.1.0
* KSM-395 - New feature to load configurations from AWS Secrets Manager

## 1.0.17
* KSM-392 - Ability to update fields where the label is a blank string (`""`)
* Pinned KSM Core version to 16.5.1

## 1.0.16

* KSM-362 - Synchronize secrets to GCP
* Dropped support for Python 3.6 (EOL 2021-12-23)

## 1.0.15

* Update pinned KSM SDK version. The KSM SDK has been updated to use OpenSSL 3.0.7 which fixes CVE-2022-3602, CVE-2022-3786.

## 1.0.14

* Accept JSON via the KSM_CONFIG environmental variable. K8S secrets will show up as JSON in the environmental variable.
* Add `--raw` parameter to `secret get` command. When using `--query` this flag will remove the double quotes around 
the value, if a string.
* Add `sync` command to sync Vault secrets to AWS and Azure secret managers.

## 1.0.13

* For the Windows and macOS application create the keeper.ini file in the user's "HOME" directory.

## 1.0.12

* Fix problem with the same temp file being opened when exporting profile. Was causing a `Permission denied` error.

## 1.0.11

* Fix missing linefeed when selecting `immutable` for k8s token init.

## 1.0.10

* Prevent keeper.ini from being created when using config from environment variables.
* Fixed problem with params that use '=' from converting the value to lowercase.
* Throw exception is record(s) do not exist for `get`

## 1.0.9

* Fixed environment variables starting with "keeper", that are not notation, from throwing an error.
