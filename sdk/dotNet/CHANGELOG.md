# Changelog

All notable changes to the Keeper Secrets Manager .NET SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- KSM-879 - Added automatic throttle retry with exponential backoff. On HTTP 403 `{"error":"throttled"}`, `PostQuery` now retries up to 5 times with exponentially increasing delays (11s, 22s, 44s, 88s, 176s) plus ±25% jitter, honoring `retry_after` from the response when present; a typed `KeeperThrottleException` is thrown once retries are exhausted. `KeeperHttpResponse` now carries the HTTP `StatusCode` so the retry is gated on 403. Existing key-rotation retry behavior is unchanged.

## [17.1.2]

### Fixed

- KSM-822 - Ensure `"custom": []` is always included in RecordCreate V3 API payload even when no custom fields are set
  - Changed `KeeperRecordData.custom` default from `null` to empty array so the serializer always includes the field
  - Aligns .NET SDK record creation with Commander and Vault behavior
- KSM-843 - Fixed `ObjectDisposedException` in `LocalConfigStorage.SaveToFile()` when writing config to file
  - `stream.Close()` was called before `writer.Dispose()`, causing the writer's flush-on-dispose to fail
  - Switched to explicit `using` blocks so the writer flushes and disposes before the stream closes
  - Regression introduced in v17.1.0 (KSM-698 file permissions fix); resolves GitHub issue #966
- KSM-865 - Fixed `DownloadThumbnail` returning full file content instead of thumbnail
  - Was passing `file.Url` to the internal download call instead of `file.ThumbnailUrl` (copy-paste bug)
- KSM-864 - Fixed `GetSecrets` silently dropping records when boolean fields contain integer values
  - `required`, `privacyScreen`, and `enforceGeneration` were declared as non-nullable `bool`
  - Records created by older clients or Commander send `0`/`1` integers or quoted strings for these fields
  - Changed to `bool?` with `FlexibleBoolConverter` to accept JSON booleans, integers, and quoted strings
- KSM-873 - Fixed `Get-SecretInfo` / `Get-Secret` round-trip silently returning null (PowerShell)
  - `GetSecretsInfo()` was returning names in the format `"UID title"` which `GetSecret()` could not resolve
  - Now returns the record title as the name (falls back to UID when title is null or empty)
- KSM-863 - Removed bundled `System.Management.Automation.dll` from PowerShell module package
  - This DLL conflicts with PowerShell's own copy, causing `Import-Module` to fail on some environments
  - Removed from the file list in `build.ps1`; PowerShell already provides this assembly at runtime
- KSM-874 - Removed `Set-KeeperVault` ghost export from PowerShell module manifest
  - Function was listed in `FunctionsToExport` in `SecretManagement.Keeper.Extension.psd1` but never implemented
  - Any call to `Set-KeeperVault` produced a hard terminating error
- KSM-875 - Fixed `FieldValue()` throwing `NullReferenceException` or `IndexOutOfRangeException` on records with null or empty value arrays
  - Added null/length guard before accessing `value[0]`; returns `null` when the value array is absent
  - Callers can now safely iterate all fields on any record type, including PAM and gateway records

## [17.1.1] - 2026-02-03

### Fixed

- KSM-767 - Fixed PowerShell 7.5.4 compatibility by downgrading System.Text.Json from 10.0.1 to 9.0.9

## [17.1.0] - 2025-12-17

### Added

- KSM-741 - Added transmission public key #18 for Gov Cloud Dev support

### Fixed

- KSM-724 - Fixed duplicate UID issue with GetNotation when record shortcuts exist (resolves #881)
- KSM-698 - Fixed file permissions for client-config.json and cache.dat (secure 600 permissions on Unix/macOS, restricted ACLs on Windows)
- KSM-674 - Fixed parsing of lastModified file data field

## [17.0.0] - 2025-10-10

### Added

- KSM-535 - Added proxy support
- KSM-625 - KSM .Net SDK Add GraphSync links
- KSM-633 - KSM .Net SDK Add links2Remove parameter for files removal

### Changed

- KSM-570 - KSM SecretManagement.Keeper Increase Min PowerShell version to 6.0

### Fixed

- KSM-659 - .NET SDK: Handle broken records, files, and folders

## [16.6.7]

### Added

- KSM-557 - Added new and updated PAM field types

### Fixed

- KSM-550 - Stop generating UIDs that start with "-"

## [16.6.6]

### Added

- KSM-360 - GHA to build and release strong named assemblies
- KSM-490 - Switch some internal classes to public - for use in plugins
- KSM-517 - Add support for netstandard2.0 target

### Changed

- KSM-515 - Update to Bouncy Castle 2.4.0
- KSM-536 - Update to System.Text.Json 8.0.4

### Fixed

- KSM-542 - Fix PowerShell module to allow dot in title

## [16.6.5]

### Changed

- KSM-484 - Update to latest Bouncy Castle version

### Fixed

- KSM-476 - fix public key parsing

## [16.6.4]

### Fixed

- KSM-466 - Fixed ExpiresOn conversion from UnixTimeMilliseconds. Closes [Issue #533](https://github.com/Keeper-Security/secrets-manager/issues/533)

## [16.6.3]

### Fixed

- KSM-462 - Fixed JSON serializer that replaces characters with accents. Closes [Issue #523](https://github.com/Keeper-Security/secrets-manager/issues/523)

## [16.6.2]

### Added

- KSM-456 - Added .NET 4.7 as an additional build target

## [16.6.1]

### Changed

- KSM-445 - Improved folder support

## [16.6.0]

### Added

- KSM-412 - Added support for Folders
- KSM-432 - Improved Passkey field type support
- KSM-383 - Support for record Transactions

### Changed

- KSM-418 - Upgraded .NET version to net48, netstandard2.1 to make sure we are supporting TLS13

## [16.5.1]

### Added

- KSM-408 - New field type: Passkey
- KSM-403 - New field type: script and modification to record types
- KSM-378 - Added support for PAM record types

## [16.4.0]

### Added

- KSM-307 - Support for Canada and Japan data center
- KSM-311 - Improved password generation entropy
- Record deletion
