# Keeper Secrets Manager CLI

The Keeper Secrets Manager command line interface

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/secrets-manager-command-line-interface

# Change History

## 1.5.0
- **Breaking / Security**: KSM-1168 - `ksm sync --type aws` with `--record`, `--folder`, or `--folder-recursive` now requires a `--prefix` argument. The prefix is prepended to every AWS secret name derived from a record title, confining the sync to a named namespace and preventing a Keeper user who can add records to a synced folder from targeting arbitrary secrets in the operator's AWS account. Users upgrading from 1.4.x must add `--prefix <value>` to existing sync commands (e.g. `--prefix keeper/`). Additionally, `--dry-run` output no longer includes the live destination secret value; it now reports `dstExists` and `dstDiffers` only.
- **Fix**: KSM-929 - CLI keyring detection silently returned no profiles when the OS keyring (e.g. gnome-keyring) was running but locked with no interactive session available to unlock it (e.g. over SSH). Now raises an actionable error naming the cause and pointing at `--ini-file`/`KSM_CONFIG` as a fallback.
- **Fix**: KSM-1155 - Every keyring storage failure path in `KeyringUtilityStorage` crashed with `TypeError: KeeperError.__init__() takes 2 positional arguments but 3 were given` instead of reporting the actual storage error, because the internal error helper passed the original exception as a second argument to `KeeperError`. The helper now raises `KeeperError` with the message and chains the original exception as the cause.
- **Fix**: KSM-1113 - Windows config search looked for `%APPDIR%\Keeper` (a Linux AppImage variable, not a Windows one), so `keeper.ini` placed in `%APPDATA%\Keeper` was never found; on Linux, the `/etc` search entry also resolved relative to the current working directory instead of `/etc`. Both paths are now resolved correctly.
- **Fix**: KSM-1107 - `ksm secret add clone` exited 0 even when the source UID did not exist, masking the failure from scripts. Now exits non-zero with an error message.
- **Dependency**: KSM-1114 - Removed the unmaintained `colorama` package. Terminal coloring now uses `click` (already a direct dependency via `click-help-colors`), so no new dependency is introduced. The Windows-only config-permission warning (which duck-types its color argument against colorama's `Fore`/`Style` shape) is now colored via a small `click.style()`-backed shim instead.
- **Fix**: KSM-1018 - The macOS installer crashed on every `ksm` command (`ImportError: Symbol not found: _SSL_get0_group_name`) because the bundled `libssl.3.dylib` predated OpenSSL 3.2.0, which `cryptography` now requires. Both x64 and arm64 macOS builds now bundle an up-to-date libssl, and the `cryptography` version pin used as a stopgap is no longer needed.
- **Fix**: KSM-1156 - `ksm shell` crashed at startup with `UnicodeEncodeError: 'charmap' codec can't encode characters` when stdout could not represent the Unicode box-drawing banner — e.g. cp1252 when output is piped or redirected on Windows, or a C-locale pipe on Linux. The shell now checks the active stdout encoding first and falls back to a plain-text banner, so it starts on any stdout encoding; UTF-8 terminals keep the full logo.
- **Fix**: KSM-1157 - `ksm shell` did not apply session global options to commands run inside the shell: every inner line re-resolved configuration from scratch, so `ksm --ini-file custom.ini shell` followed by `secret list` inside the shell ignored the ini file (and `--profile-name`, `--output`, `--color/--no-color`, `--cache/--no-cache`, `--log-level` were likewise dropped). Inner commands now inherit the session's global options; options typed on an inner line still override them, for that line only. Requires click >= 8.0 (now declared in `install_requires`).
- **Fix**: KSM-1105 - Windows installer's post-install launch of `ksm.exe` was blocked by endpoint security (EDR/AV) because InnoSetup's extracted Setup engine parent process in `%TEMP%` was unsigned. The post-install launch no longer trips endpoint security.
- **Fix**: KSM-1106 - macOS PKG installer ignored the Keyring and Cloud Sync component checkboxes in GUI mode, always installing both regardless of what the user selected. The installer now respects the selected components.
- **Fix**: KSM-1116 - Windows installer placed the CLI in `Program Files (x86)` on 64-bit systems instead of `Program Files`. The installer now correctly targets the 64-bit program directory.
- **Fix**: KSM-1118 - `ksm secret add clone` crashed with "list index out of range" when the source record contained any unpopulated complex field (name, address, host, etc.) — fields the server legitimately returns as `value: []`. Empty-value fields are now skipped before the create payload is assembled, so the clone completes correctly. Root cause in the Python helper library is tracked as KSM-1119.
- **Fix**: KSM-1126 - `ksm secret add file` (and `ksm secret add editor`) crashed with "list index out of range" on the same class of input: a record script containing an unpopulated complex field with `value: []`. Empty-value fields are now stripped before the create payload is assembled. Root cause in the Python helper library is tracked as KSM-1119.
- **Fix**: KSM-1135 - `ksm secret download` crashed with "Invalid URL 'None'" when called immediately after `ksm secret upload` in automation, because the vault may not yet have propagated the file download URL by the time the SDK returns. Now raises a clear error with a prompt to retry in a few seconds. Root cause in the Python SDK is tracked as KSM-1131.
- **Fix**: KSM-1136 - The empty-value field skip introduced for KSM-1118 also removed custom fields with `value: []` from `ksm secret add clone`, so empty custom fields were silently missing from the cloned record — unlike standard fields, custom fields are not part of the record type schema and are not recreated. Empty custom fields are now re-attached to the clone payload with their type, label and flags preserved, keeping the clone field-faithful. Regression within this release only; no shipped version affected.
- **Fix**: KSM-1162 - `ksm shell` on Windows corrupted backslash paths typed at the shell prompt before click ever parsed them. `click-repl` calls `shlex.split()` in POSIX mode, where backslash is an escape character, so a path like `C:\dir\file.ini` was silently reduced to `C:dirfile.ini`. The shell now replaces `click-repl`'s tokenizer on Windows for the duration of the REPL session with one that treats backslash as a literal character while still stripping quotes normally, so quoted paths with spaces also work.
- **Fix**: KSM-1163 - When `KSM_INI_DIR` was set and a `keeper.ini` also existed in the current working directory, the CWD file silently loaded instead of the operator-specified location. The CLI now emits a warning on stderr naming both paths and suggesting `--ini-file` when the conflict is detected; the CWD file continues to load to avoid breaking existing setups that rely on the current behavior. Set `KSM_INI_DIR_SKIP_CONFLICT_WARNING=TRUE` to suppress the warning.
- **Fix**: KSM-1163 - `keeper.ini` discovery probed relative `_NOTSET_/…/keeper.ini` paths when Windows environment variables (`USERPROFILE`, `APPDATA`, etc.) were unset on POSIX hosts, so a literal `_NOTSET_/` directory in the working directory could be accidentally loaded. Discovery now skips any search entry whose environment variable is unset.
- **Fix**: KSM-1161 - `ksm secret add file` (and `ksm secret add editor`) silently dropped custom fields with `value: []` from the created record. The KSM-1126 workaround strips empty-value fields before passing to the helper to avoid a helper crash; custom fields stripped this way are now re-attached to the create payload with their type, label, and flags preserved, keeping the record field-faithful. Standard fields are not affected (they are recreated from the record type schema). Root cause in the Python helper library is tracked as KSM-1119.
- **Fix**: KSM-1165 - `ksm shell` truncated any argument containing `#` at the `#` character on all platforms. The Windows-safe tokenizer introduced in KSM-1162 disabled the backslash escape character but left the default `commenters` list intact, so `#` and everything after it was silently dropped — notation references like `UID#field/path` failed inside the shell. `#` is now treated as a literal character.
- **Fix**: KSM-1158 - On Windows, upgrading from a 1.4.0 or earlier installation left the old x86 installation intact and still on `PATH` alongside the new 64-bit install. The installer now detects and removes any pre-existing x86 installation before placing the 64-bit binary.
- **Fix**: KSM-1159 - The Windows installer appended a duplicate `PATH` entry for the install directory on every install or upgrade because the InnoSetup `{app}` constant was not expanded before the PATH check ran. No duplicate is added on clean installs; the uninstaller now also removes all duplicate entries left by prior versions.
- **Fix**: KSM-1164 - The Windows PATH rewrite introduced by KSM-1159 wrote `REG_EXPAND_SZ` PATH entries back as `REG_SZ`, preventing Windows from expanding environment variable references (such as `%SystemRoot%\System32`) in those entries. The registry value type is now preserved when rewriting PATH.
- **Fix**: KSM-1160 - The Linux tarball `install.sh` had no platform-floor check and installed silently on hosts below the documented libc minima (musl < 1.2.5 / Alpine < 3.20, or glibc < 2.28), with the first `ksm` invocation crashing with a cryptic loader error. The script now checks the host libc version before installing and exits with an actionable error naming the detected version, the required minimum, and remediation steps. Set `KSM_SKIP_PREFLIGHT=1` to bypass. The shebang was also changed from `#!/bin/bash` to `#!/bin/sh` for compatibility with Alpine's default `ash` shell.
- **Fix**: KSM-1117 - The CLI Docker alpine image shipped a binary built against musl 1.2.5 while the image base was Alpine 3.19 (musl 1.2.4), so `ksm` crashed at load time in its own image. The alpine image now uses Alpine 3.22 (musl >= 1.2.5) as its base and the musl build stage is pinned to `python:3.12-alpine3.23`. Binary self-tests were added to the Docker build so a mismatched binary/base pairing fails the build instead of shipping silently.
- **Fix**: KSM-1120 - The CLI Docker images are published as multi-arch (`linux/amd64`, `linux/arm64`), but the mountable `/cli/glibc/ksm` and `/cli/musl/ksm` binaries were always the same amd64 ELF on both platforms, making the documented init-container pattern non-functional on arm64 hosts. The arm64 image legs now ship native arm64 binaries.
- **Fix**: KSM-1169 - `ksm sync` dry-run output no longer includes the live destination value for Azure and GCP; it reports whether the destination exists and whether it would change (`dstExists`/`dstDiffers`), matching the AWS behavior. Azure and GCP destination names given via `--map` are now validated against the Azure Key Vault and GCP Secret Manager naming rules before a write.
- **Fix**: KSM-1170 - `ksm sync --record`/`--folder` now prints a warning on stderr when a token resolves by record title or folder name/path rather than by UID, naming the resolved UID, since those identifiers are mutable. Resolution behavior is otherwise unchanged (ambiguous matches still error); prefer UIDs to pin scheduled syncs.
- **Fix**: KSM-1171 - `ksm init k8s` now builds the Kubernetes Secret manifest with a YAML serializer instead of string formatting, so `--name` and `--namespace` are always emitted as properly encoded scalars and cannot inject additional manifest content.

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
