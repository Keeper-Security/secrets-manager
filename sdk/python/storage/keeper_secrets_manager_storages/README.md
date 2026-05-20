# Keeper Secrets Manager Storage

The Keeper Secrets Manager Storage module for working with custom key-value storages, creating and managing configuration files. To be used with keeper-secrets-manager-core.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager

# Change Log

## 1.1.0

- Raised minimum Python version to 3.9.2. Python 3.9.0 and 3.9.1 are excluded by the transitive `cryptography>=46.0.5` constraint pulled in via `keeper-secrets-manager-core>=17.2.0`. Users on Python 3.6 – 3.8 should pin to `keeper-secrets-manager-storage<1.1.0`; pip will auto-route them.
- Updated minimum `keeper-secrets-manager-core` dependency to 17.2.0

## 1.0.2

- Reverted mandatory boto3 dependency; boto3 remains optional via lazy import

## 1.0.1

- Added new storage type storage type for AWS Secrets Manager

## 1.0.0
- Initial release
