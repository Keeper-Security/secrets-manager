# Keeper Secrets Manager Helper

The Keeper Secrets Manager helper for creating and managing records. To be used with keeper-secrets-manager-core.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager

## Recent Changes

### Version 1.2.0
- **Breaking**: The minimum Python version is now 3.10 (KSM-1214). This matches `keeper-secrets-manager-core` 18.0.0. Python 3.9 users stay on 1.1.2, and pip selects that version automatically.
- Updated dependency: `keeper-secrets-manager-core>=18.0.0`.
- KSM-1119 - Fixed `FieldType.__init__` crashing with `IndexError` when a complex field (address, name, host, paymentCard, etc.) is returned by the server with an empty value list. Attribute variables are now left as `None` instead of attempting to index into `[]`.
- KSM-1807 - `str()` of a field no longer prints its value. The value shows as `***`. The `Password` string form also has its missing closing parenthesis.

### Version 1.0.7
- Updated dependency: `keeper-secrets-manager-core>=17.1.0` (includes fixes for CVE-2026-23949 and CVE-2026-24049)
