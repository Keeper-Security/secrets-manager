# Keeper Secrets Manager Helper

The Keeper Secrets Manager helper for creating and managing records. To be used with keeper-secrets-manager-core.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager

## Recent Changes

### Version 1.1.3
- KSM-1119 - Fixed `FieldType.__init__` crashing with `IndexError` when a complex field (address, name, host, paymentCard, etc.) is returned by the server with an empty value list. Attribute variables are now left as `None` instead of attempting to index into `[]`.

### Version 1.0.7
- Updated dependency: `keeper-secrets-manager-core>=17.1.0` (includes fixes for CVE-2026-23949 and CVE-2026-24049)
