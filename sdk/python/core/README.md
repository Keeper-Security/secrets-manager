# Keeper Secrets Manager Python SDK

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/python-sdk

# Change Log

## 16.3.5

* Allow `enforceGeneration`, `privacyScreen`, and `complexity` in record fields when creating a record.
* Record creation validation. Making sure that only legitimate record field types, notes section, and title of the record can be saved

## 16.3.4

* Provide better exception messages when the config JSON file is not utf-8 encoded.
