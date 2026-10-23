## Keeper Secrets Manager JavaScript SDK

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/javascript-sdk

See [CHANGELOG.md](CHANGELOG.md) for version history.

### Request timeout

Node and browser network requests have a five-minute default timeout (`300000` ms). Each request attempt uses a fixed deadline that includes response headers and the entire response body.

Override it with `SecretManagerOptions.requestTimeoutMs`. The optional per-call `timeoutMs` argument on `downloadFile`, `downloadThumbnail`, and `uploadFile` takes precedence over that option. Set a longer value when a transfer needs more than five minutes.

Timeout values must be finite numbers of at least `1` ms. Fractional values are floored and values above `2147483647` ms are clamped. Runtimes without `AbortController` do not enforce the deadline.
