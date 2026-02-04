# Keeper Secrets Manager Storage

The Keeper Secrets Manager Storage module for working with custom key-value storages, creating and managing configuration files. To be used with keeper-secrets-manager-core.

## Installation

### Basic Installation (File, In-Memory, Azure Key Vault Storage)

```bash
pip install keeper-secrets-manager-storage
```

### With AWS Secrets Manager Support

```bash
pip install keeper-secrets-manager-storage[aws]
```

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager

# Change Log

## 1.0.3

- **BREAKING CHANGE**: boto3 is now an optional dependency
  - AWS Secrets Manager storage requires: `pip install keeper-secrets-manager-storage[aws]`
  - Non-AWS users can install without boto3 to avoid unnecessary dependencies
- Updated keeper-secrets-manager-core dependency to >=17.1.0
- Improved error messages when boto3 is not installed

## 1.0.2

- Bug fixes and improvements

## 1.0.1

- Added new storage type storage type for AWS Secrets Manager

## 1.0.0
- Initial release
