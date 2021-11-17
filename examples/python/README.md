# Python example

Sample project demonstrating how to extract shared secrets from Keeper using Python SDK

Prerequisites:

- Python 3.6 or higher
- One or more client keys obtained from the owner of the secret. Client keys are one-time use.

Install dependency:

```shell
pip3 install -r requirements.txt
```

Usage:

```shell
python3 hello-ksm-read.py
```

You need to use client key only once per config name. After config has been initialized, the client key becomes obsolete and can be omitted.

