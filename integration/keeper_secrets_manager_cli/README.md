# Keeper Secrets Manager CLI

The Keeper Secrets Manager command line interface

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/secrets-manager-command-line-interface

# Change History

## 1.5.0
- **Fix**: KSM-859 - `ksm profile setup -t aws` (EC2 instance credentials) stalled for several seconds on non-EC2 machines, since region lookup used botocore's default IMDS timeout, then surfaced a raw botocore error with no indication of the cause. Now fails fast with a 1-second IMDS timeout and a clear message naming the non-EC2 cause and pointing at `--fallback`.
- **Fix**: KSM-929 - CLI keyring detection silently returned no profiles when the OS keyring (e.g. gnome-keyring) was running but locked with no interactive session available to unlock it (e.g. over SSH). Now raises an actionable error naming the cause and pointing at `--ini-file`/`KSM_CONFIG` as a fallback.

## 1.4.0
- **Fix**: KSM-975 - Binary install keyring warning gave pip install advice that does not apply to a frozen binary; bracket syntax in the pip advice also caused zsh glob errors. Now detects `sys.frozen` to show binary-appropriate help text and single-quotes the bracket expression for zsh compatibility.
- **Fix**: KSM-1014 - The frozen-binary keyring-unavailable warning told users to download a non-existent `-keyring` version of the binary. Keyring ships as the selectable "OS Keyring Support" component inside the single installer on every OS, so the warning now directs users to re-run the installer and enable that component.
- **Fix**: KSM-980 - Binary install created `keeper.ini` in the current working directory instead of the user's home directory. Now detects `sys.frozen` in `Config.get_default_ini_file()` and uses `$HOME`/`%USERPROFILE%` for binary installs, matching the existing `launched_from_app` behaviour.
- **Fix**: KSM-981 - `ksm secret get` did not surface linked records (PAM credential records were invisible). Now passes `request_links=True` to the server so linked record UIDs are returned, includes a `links` array in JSON output, and shows a Links table in text output.
- **Fix**: KSM-1015 - links output made interpretable. Each link entry in JSON output gains a `decoded` object (plain link data parsed; `ai_settings`/`jit_settings` decrypted with the record key via the SDK's `KeeperRecordLink`), while the raw `recordUid`/`data`/`path` fields are preserved untouched. The text Links table now shows three columns - Linked Record UID (self-links labeled `(self)`), Path, and decoded Link Data - so PAM `meta` settings and AI/JIT configuration are distinguishable from links to other records. Requires keeper-secrets-manager-core >= 17.3.0.
- **Fix**: KSM-1003 - Binary install wrote `ksm_cache.bin` to the current working directory when caching was enabled (sibling to KSM-980). The CLI now sets `KSM_CACHE_DIR` to the same directory it resolves for `keeper.ini` before loading the SDK core, so the cache co-locates with the ini in `$HOME`/`%USERPROFILE%` for binary installs; pip/source installs are unchanged.
- **Fix**: KSM-1005 - `ksm shell` crashed on launch (`UpdateChecker.check() takes 1 positional argument but 3 were given`) on any fresh install after the `update-checker` 1.0.0 release made `check()` keyword-only. The CLI now calls it with keyword arguments (compatible with both 0.18.0 and 1.0.0, no version pin needed), and the `shell` startup update check is wrapped in try/except so a failed update check can never block the shell from starting.

## 1.3.0
- **Feature**: KSM-800 - OS-native keyring storage for CLI configuration
  - New profiles store configuration in the OS keyring by default (macOS Keychain, Windows Credential Manager, Linux Secret Service)
  - Existing `keeper.ini` profiles continue to work without migration
  - Added `--ini-file` flag to opt into explicit file-based storage
  - Added `keyring` as an optional dependency: `pip install keeper-secrets-manager-cli[keyring]`
- **Fix**: KSM-814 - `--ini-file` flag now respected by all profile and config subcommands: `profile list`, `profile active`, `profile export`, `profile import`, `profile init`, `profile setup`; `config show`, `config color`, `config cache`, `config record-type-dir`, `config editor`
- **Fix**: KSM-691 - keeper.ini now written with owner-only permissions (0600)
- **Breaking**: KSM-799, KSM-817 - Minimum Python raised from 3.7 to 3.10
- **Breaking**: KSM-817 - boto3 is now an optional dependency; AWS sync users must install the `[aws]` extra: `pip install keeper-secrets-manager-cli[aws]`
- **Dependency**: Updated keeper-secrets-manager-core to >=17.2.0 and keeper-secrets-manager-helper to >=1.1.0
- **Security**: KSM-761 - Fixed CVE-2026-23949 (jaraco.context path traversal vulnerability)
- **Fix**: Updated prompt-toolkit from ~=2.0 to >=3.0 (fixes dependency resolution conflicts)
- **Fix**: KSM-804 - Warn on stderr when keyring is active but empty and a keeper.ini file exists at CWD or standard locations, including hint to use `--ini-file`
- **Fix**: KSM-805 - SHA-256 integrity hash now persisted as a separate Keychain entry and verified on every load; tampered entries raise a `KsmCliIntegrityException` with a clear recovery hint
- **Fix**: KSM-810 - Added `ksm profile delete <name>` command; fixed keyring storage to clear the active profile pointer when the active profile is deleted, preventing a broken state on subsequent invocations
- **Fix**: KSM-702 - Record create payload now always includes `custom: []`; previously the key was silently omitted when no custom fields were set
- **Fix**: KSM-815 - Profile name is now validated before redeeming the one-time token; invalid names (containing whitespace or exceeding 64 characters) are rejected immediately, preventing the token from being consumed on a failed init
- **Fix**: KSM-818 - `ksm shell` no longer crashes on any command when click>=8.2 is installed; pinned click-repl to <0.3.0 (0.3.0 incompatible with click>=8.2)
- **Fix**: KSM-820 - `ksm secret get --json` now outputs custom fields under `"custom"` key (was `"custom_fields"`), matching the canonical V3 record format used by Commander and the Keeper Vault
- **Fix**: KSM-828 - Unit tests no longer write mock data to the real system keyring; added `KeyringConfigStorage.is_available` mock to all tests that call `Profile.init()` as scaffolding (`secret_test.py`, `exec_test.py`, `secret_inflate_test.py`)
- **Fix**: KSM-829 - Profile name validation before OTT redemption now uses the same strict pattern as keyring storage (`[a-zA-Z0-9_-]{1,64}`); previously the early check allowed path-traversal characters and special characters through, consuming the one-time token before the stricter validator fired
- **Fix**: KSM-831 - `--ini-file` no longer fails with `Missing import dependencies: boto3` for non-AWS profiles; `AwsConfigProvider` import is now deferred to the `aws` storage branch in `_load_config`, so users without the `[aws]` extra are unaffected
- **Fix**: KSM-832 - removed lkru utility integration; `is_available()` now correctly returns `False` when `keyring` is not installed or no Secret Service daemon is running, falling back to `keeper.ini` file storage in both cases
## 1.2.0
- KSM-649 Added AWS KMS JSON support for sync command
- KSM-465 Implemented ksm interpolate command for shell built-in compatibility

## 1.1.7
- KSM-668 Restored ? command to cli

## 1.1.6
- KSM-558 Fixed crashes with mutually required options in shell mode
- KSM-567 Added KSM_CLI_TOKEN environment variable
- KSM-568 Removed dependency on legacy distutils
- KSM-644 Added delete-attachment option
- Bumping KSM SDK to 17.0.0 and helper module to 1.0.6

## 1.1.5
- Bumping KSM SDK to 16.6.5

## 1.1.4

- KSM-507: Added `ksm secret delete` command
- KSM-508: Added search by title to `ksm secret list` command
- KSM-509: Added `ksm folder ...` commands

## 1.1.3

- KSM-496: Added upload file option
- KSM-495: Added query option to ksm secret list command
- KSM-494: Added folder support to secret list command
- KSM-493: Added CLI options to update title and notes
- KSM-492: Added clone option
- KSM-485: Added sub-folder support to ksm secret add command

## 1.1.1

* KSM-429 - Add `--profile-name` to `ksm profile import` command

## 1.1.0
* KSM-395 - New feature to load configurations from AWS Secrets Manager

## 1.0.17
* KSM-392 - Ability to update fields where the label is a blank string (`""`)
* Pinned KSM Core version to 16.5.1

## 1.0.16

* KSM-362 - Synchronize secrets to GCP
* Dropped support for Python 3.6 (EOL 2021-12-23)

## 1.0.15

* Update pinned KSM SDK version. The KSM SDK has been updated to use OpenSSL 3.0.7 which fixes CVE-2022-3602, CVE-2022-3786.

## 1.0.14

* Accept JSON via the KSM_CONFIG environmental variable. K8S secrets will show up as JSON in the environmental variable.
* Add `--raw` parameter to `secret get` command. When using `--query` this flag will remove the double quotes around 
the value, if a string.
* Add `sync` command to sync Vault secrets to AWS and Azure secret managers.

## 1.0.13

* For the Windows and macOS application create the keeper.ini file in the user's "HOME" directory.

## 1.0.12

* Fix problem with the same temp file being opened when exporting profile. Was causing a `Permission denied` error.

## 1.0.11

* Fix missing linefeed when selecting `immutable` for k8s token init.

## 1.0.10

* Prevent keeper.ini from being created when using config from environment variables.
* Fixed problem with params that use '=' from converting the value to lowercase.
* Throw exception is record(s) do not exist for `get`

## 1.0.9

* Fixed environment variables starting with "keeper", that are not notation, from throwing an error.
