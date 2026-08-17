# Keeper Secrets Manager Helper

The Keeper Secrets Manager helper for creating and managing records. To be used with keeper-secrets-manager-core.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager

## Recent Changes

### Version 1.1.3
- KSM-1119 - Fixed `FieldType.__init__` crashing with `IndexError` when a complex field (address, name, host, paymentCard, etc.) is returned by the server with an empty value list. The SDK now leaves attribute variables as `None` instead of indexing into `[]`.
- KSM-1127 - Fixed `PamSettings.connection` schema missing `database` and `dbConnectionMethod` fields. Both fields are now present in the `pamDatabase` connection schema, so template generation and record construction can use them.
- KSM-1140 - Added `allowSupplyHost` to `PamSettings` (field level, alongside `connection`). Added audio control and browser session fields to `PamRemoteBrowserSettings.connection`: `disableAudio`, `disableCopy`, `disablePaste`, `audioChannels`, `audioBps`, `audioSampleRate`, `sessionPersistence`, `allowFileUploads`, `allowFileDownloads`, `ignoreInitialSslCert`, `recordingIncludeKeys`.

### Version 1.0.7
- Updated dependency: `keeper-secrets-manager-core>=17.1.0` (includes fixes for CVE-2026-23949 and CVE-2026-24049)
