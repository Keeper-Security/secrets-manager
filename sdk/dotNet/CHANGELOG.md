# Changelog

All notable changes to the Keeper Secrets Manager .NET SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
