# Keeper Secrets Manager Python SDK

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/python-sdk

**Python Requirements**: Python 3.9 or higher

## Custom Server Public Key (Isolated Deployments)

For deployments where the server public key is not shipped with the SDK,
a caller-supplied EC P-256 public key can be supplied via any of three
paths (precedence is programmatic > one-time token > pre-existing config):

```python
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage

# Programmatic — wins over the other two if all are present
sm = SecretsManager(
    token='REGION:ONE_TIME_TOKEN',
    server_public_key='url-safe-base64-EC-P256-public-key',
    server_public_key_id='your-key-id',
    config=FileKeyValueStorage(),
)
```

The one-time-token form embeds the key material directly:
`REGION:clientKey:keyId:serverPublicKeyBase64` (4 colon-separated
segments). The config-file form sets `serverPublicKey` and
`serverPublicKeyId` in the JSON config before the first call.

For deployment-specific details (region prefixes, key id assignments)
see the official docs link above.

# Change Log

See [CHANGELOG.md](CHANGELOG.md) for the full version history.
