# Keeper Secrets Manager Python SDK Example

Sample project demonstrating how to extract shared secrets from Keeper using Python SDK

Prerequisites:

- Python 3.6 or higher
- One or more one-time access tokens obtained from the owner of the secret.

Install dependency:

```shell
pip3 install -r requirements.txt
```

Usage:

```shell
python3 hello-ksm-read.py
```

The One-Time Access Token is used once to initialize the SDK configuration. After the SDK configuration is initialized, the One-Time Access Token can be removed.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/python-sdk
