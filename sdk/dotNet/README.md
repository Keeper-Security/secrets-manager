## Keeper Secrets Manager .NET (C#) SDK


# Change Log

## 18.0.0

**BREAKING CHANGE:** This release adds strong-naming to the Keeper.SecretsManager assembly.

* KSM-368 - Strong-named assembly support
* Assembly is now signed with a strong name, changing its identity
* All dependencies (BouncyCastle.Cryptography, System.Text.Json, etc.) are already strong-named
* No code changes required - existing code will work after recompilation
* Required for compatibility with .NET Framework projects that require strong-named assemblies

### Migration Guide

**For existing users upgrading from v17.x:**
1. Update your package reference to v18.0.0
2. Rebuild your project (recompilation required due to assembly identity change)
3. No code changes are necessary

**Why a major version bump?**
According to Microsoft's semantic versioning guidance, adding strong-naming changes an assembly's identity, which is a breaking change requiring a major version increment.

**For more information:**
- GitHub Issue: https://github.com/Keeper-Security/secrets-manager/issues/404
- Microsoft Documentation: https://learn.microsoft.com/en-us/dotnet/standard/library-guidance/strong-naming

## 17.0.0

* KSM-535 - Added proxy support
* KSM-625 - KSM .Net SDK Add GraphSync links
* KSM-570 - KSM SecretManagement.Keeper Increase Min PowerShell version to 6.0
* KSM-633 - KSM .Net SDK Add links2Remove parameter for files removal
* KSM-659 - .NET SDK: Handle broken records, files, and folders

## 16.6.7

* KSM-550 - Stop generating UIDs that start with "-"
* KSM-557 - Added new and updated PAM field types

## 16.6.6

* KSM-360 - GHA to build and release strong named assemblies
* KSM-490 - Switch some internal classes to public - for use in plugins
* KSM-515 - Update to Bouncy Castle 2.4.0
* KSM-536 - Update to System.Text.Json 8.0.4
* KSM-517 - Add support for netstandard2.0 target
* KSM-542 - Fix PowerShell module to allow dot in title

## 16.6.5

* KSM-476 - fix public key parsing
* KSM-484 - Update to latest Bouncy Castle version

## 16.6.4

* KSM-466 - Fixed ExpiresOn conversion from UnixTimeMilliseconds. Closes [Issue #533]

## 16.6.3

* KSM-462 - Fixed JSON serializer that replaces characters with accents. Closes [Issue #523](https://github.com/Keeper-Security/secrets-manager/issues/523)

## 16.6.2

* KSM-456 - Added .NET 4.7 as an additional build target

## 16.6.1

* KSM-445 - Improved folder support

## 16.6.0

* KSM-412 - Added support for Folders
* KSM-432 - Improved Passkey field type support
* KSM-383 - Support for record Transactions
* KSM-418 - Upgraded .NET version to net48, netstandard2.1 to make sure we are supporting TLS13

## 16.5.1

* KSM-408 New field type: Passkey
* KSM-403 New filed type: script and modification to record types
* KSM-378 Added support for PAM record types

## 16.4.0

* KSM-307 - Support for Canada and Japan data center
* KSM-311 - Improved password generation entropy
* Record deletion

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/.net-sdk
