# Keeper Secrets Manager Python SDK

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/python-sdk

# Change Log

## 16.3.5

* Create new client-config.json with only owner ACL mode. Print STDERR warning if client-config.json ACL mode is too
open.
* Removed non-ASCII characters from source code. Added Python comment flag to allow non-ASCII to source code, just in
case.

## 16.3.4

* Provide better exception messages when the config JSON file is not utf-8 encoded.