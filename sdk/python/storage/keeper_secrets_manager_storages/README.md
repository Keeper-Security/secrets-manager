# Keeper Secrets Manager Storage

The Keeper Secrets Manager Storage module for working with custom key-value storages, creating and managing configuration files. To be used with keeper-secrets-manager-core.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager

# Change Log

## 1.0.3

- Add boto3>=1.20.0 as explicit dependency (required for IMDSFetcher in AWS storage provider)
- Raise minimum Python version from 3.6 to 3.9
- Fixes ImportError when storage_aws_secret.py tries to import IMDSFetcher from botocore.utils

## 1.0.2

- Bug fixes and improvements

## 1.0.1

- Added new storage type storage type for AWS Secrets Manager

## 1.0.0
- Initial release
