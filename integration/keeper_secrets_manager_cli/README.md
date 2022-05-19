# Keeper Secrets Manager CLI

The Keeper Secrets Manager command line interface

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/secrets-manager-command-line-interface

# Change History

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
