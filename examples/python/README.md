# Keeper Secrets Manager Python SDK Example

Sample project that shows how to extract shared secrets from Keeper using the Python SDK.

Prerequisites:

- Python 3.9 or higher
- One or more one-time access tokens from the owner of the shared secret.

Install dependency:

```shell
pip3 install -r requirements.txt
```

Usage:

```shell
python3 hello-ksm-read.py
```

The SDK uses the One-Time Access Token once to initialize its configuration. After initialization, you can remove the token.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/python-sdk
