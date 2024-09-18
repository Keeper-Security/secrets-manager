# Keeper Secrets Manager Python SDK

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/python-sdk

# Change Log

## 16.6.6
* KSM-552 - Stop generating UIDs that start with "-"

## 16.6.5
* KSM-529 - Handle broken encryption in records and files

## 16.6.4
* KSM-488 - Remove unused package dependencies

## 16.6.3
* KSM-479 - Remove dependency on `distutils` due to Python 3.12 removing it

## 16.6.2
* KSM-463 - Python SDK - Fix a bug when fields is null
* KSM-458 - Python SDK - Remove core's dependency on the helper module. Fixes [issue 488](https://github.com/Keeper-Security/secrets-manager/issues/488)

## 16.6.1
* KSM 444 - Python - Added folderUid and innerFolderUid to Record

## 16.6.0
* KSM-413 - Added support for Folders
* KSM-434 - Improved Passkey field type support

## 16.5.4
* KSM-405 - Added new script field type and oneTimeCode to PAM record types
* KSM-410 - New field type: Passkey
* KSM-394 - Ability to load configuration from AWS Secrets Manager using AWS AIM role in EC2 instance or AWS IAM user
* KSM-416 - Fix OS detection bug
* KSM-400 - Unpinned few dependencies

## 16.5.3
* KSM-393 - Fix file permissions on localized Windows OS

## 16.5.2
* KSM-375 - Make HTTPError to be more informative
* KSM-376 - Support for PAM record types
* KSM-381 - Transactions
* Fixed [Issue 441](https://github.com/Keeper-Security/secrets-manager/issues/441) - Bug caused by space in username

## 16.5.1
* KSM-371 - Fix Windows Config file permissions issue
* KSM-370 - Upgrade to latest cryptography>=39.0.1 library

## 16.5.0
* KSM-313 - Improved Keeper Notations. New parser, new escape characters, Notation URI, search records by title and other meta data values in the record
* KSM-319 - `KEY_CLIENT_KEY` in configurations is missing in certain situations
* KSM-356 - Ability to create of the new custom field

## 16.4.2
* Fix to support dynamic client version

## 16.4.1
* Upgrading and pinning `cryptography` dependency to 38.0.3

## 16.4.0
* Record deletion
* KSM-305 - Support for Canada and Japan data centers
* KSM-308 - Improve password generation entropy
* KSM-240 - Config file permission checking (Create new client-config.json with locked down permission/ACL mode. Print STDERR warning if client-config.json ACL mode is too
  open. To disable ACL mode checking and setting, set environmental variable `KSM_CONFIG_SKIP_MODE` to `TRUE`. To prevent
  warnings of the client-config.json being too open, set environmental variable `KSM_CONFIG_SKIP_MODE_WARNING` to `TRUE`.
  For Unix, `client-config.json` is set to `0600` mode. For Windows, `client-config.json` has only the user that created
  the `client-config.json` and the **Administrator** group.)



## 16.3.5

* Removed non-ASCII characters from source code. Added Python comment flag to allow non-ASCII to source code, just in
case.
* Allow `enforceGeneration`, `privacyScreen`, and `complexity` in record fields when creating a record.
* Record creation validation. Making sure that only legitimate record field types, notes section, and title of the record can be saved

## 16.3.4

* Provide better exception messages when the config JSON file is not utf-8 encoded.
