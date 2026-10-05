# Keeper Secrets Manager Ansible

This module contains plugins that allow your Ansible automations to use Keeper Secrets Manager. 

* `keeper_cache_records` - Generate a cache to use with other actions.
* `keeper_copy` - Similar to `ansible.builtin.copy`. Uses the KSM vault for the source/content.
* `keeper_get` - Retrieve secrets from a record.
* `keeper_get_record` - Retrieve records as a dictionary.
* `keeper_set` - Update an existing record from Ansible information.
* `keeper_create` - Create a new record in a shared folder or in a subfolder.
* `keeper_create_folder` - Create a new folder in a shared folder or in a subfolder.
* `keeper_get_folder` - Look up a folder by name or path, and get its UID.
* `keeper_update_folder` - Rename a folder.
* `keeper_delete_folder` - Delete a folder.
* `keeper_init` - Initialize a KSM configuration from a one-time access token.
* `keeper_cleanup` - Remove the cache file, if being used.
* `keeper_lookup` - Retrieve secrets from a record using Ansible's lookup.
* `keeper_redact` - Stdout Callback plugin to redact secrets from logs.
* `keeper_password` - Generate a random password.
* `keeper_info` - Display information about plugin, record and field types.
* `keeper_remove` - Remove secrets from the Keeper Vault.

## Requirements

* Python 3.9.2 or later.
* ansible-core 2.15.13 or later, but not the 2.17 series.
* keeper-secrets-manager-core 17.3.0 or later, and keeper-secrets-manager-helper 1.1.2 or later.

We recommend Python 3.12 or later with ansible-core 2.20 or later.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/integrations/ansible-plugin

# Changes

## 1.5.0
* KSM-1559: Made `keeper_remove` idempotent and corrected its task results
  - A missing record, by UID or title, succeeds with `changed: false`
  - A confirmed delete reports `changed: true`, `record_uid`, and `record_title`
  - Duplicate titles fail with the matching UIDs; refused deletes fail with the server's response code and message
  - Lookup, validation, and delete failures are task results, so `failed_when`, `ignore_errors`, and `rescue` work
  - Check mode predicts the change without deleting records
  - Removal reads the current vault even when a registered cache is supplied, so stale caches cannot hide duplicate titles or report false no-ops
  - Behavior change: missing records no longer fail, and successful deletions now trigger change handlers
* **Fix**: `keeper_create` crashed with "Could not create record: list index out of range" when a playbook supplied an unpopulated complex field (address, name, host, etc.) with `value: []`. Empty-value fields are now treated as unpopulated, matching the behavior of the underlying vault schema. Root cause in the Python helper library is tracked as KSM-1119.
* **Breaking change**: KSM-1561: Raised the minimum ansible-core version to 2.15.13, and excluded the 2.17 series
  - ansible-base 2.10, ansible-core versions before 2.15.13, and ansible-core 2.17.x are no longer supported
  - Python 3.9 stays supported, from Python 3.9.2. A later release removes it
  - The new minimum removes ansible-core releases that are affected by CVE-2023-5115, CVE-2023-5764, CVE-2024-0690, CVE-2024-8775, and CVE-2024-9902
  - pip can no longer install the package with an unsupported ansible-core. For the Galaxy collection, an unsupported ansible-core shows a warning, and the collection still runs
  - The Tower Execution Environment now uses Python 3.12 and ansible-core 2.16 (2.16.19 or later), instead of Python 3.9 and ansible-core 2.15.13
  - CI tests the 2.15, 2.16, 2.18, 2.19, 2.20, and 2.21 series, and a test checks that every file that declares the ansible-core or Python requirement agrees
* KSM-845: Added `subfolder_uid` parameter to `keeper_create` for subfolder targeting
  - Records can now be created in a subfolder within a shared folder, rather than always at the shared folder root
  - `shared_folder_uid` remains required; `subfolder_uid` is optional and additive
  - Matches the `subfolder_uid` parameter name used by `keeper_create_folder` and by the Python SDK's `CreateOptions`
* KSM-1445: Added `keeper_create_folder` module for idempotent folder creation
  - Creates a folder directly in a shared folder, or nested inside an existing subfolder of that shared folder
  - Idempotent: if a folder with the given name already exists directly under the target parent, its UID is returned instead of creating a duplicate
* KSM-1478: Added `keeper_get_folder` module to look up a folder and get its UID
  - Finds a folder by name in a shared folder or in a subfolder, or by a path of names such as `Databases/Production`
  - With no start UID, the first name is the name of a shared folder, so a playbook can find a folder with no UID
  - Returns the folder UID, name, parent UID, and shared folder UID. `include_subfolders: yes` also returns every folder below it
  - Fails with a clear error if no folder matches, or if more than one folder matches. It never returns an empty result
* KSM-1479: Added `keeper_update_folder` module to rename a folder
  - Idempotent: if the folder already has the new name, it reports `changed: false` and sends no update
  - Fails with a clear error if the folder does not exist or is not shared to the KSM application
  - A new name with a space, a tab, or a newline at the start or the end fails the task, because a later lookup of the name would not find the folder
  - A rename to the name of another folder in the same parent works, with a warning, because a lookup of that name is then not unique
* KSM-1480: Added `keeper_delete_folder` module to delete a folder
  - Idempotent: if the folder does not exist, it reports `changed: false` and does not fail
  - Deletes only an empty folder, unless `force_deletion: yes` is set. A folder with records or subfolders fails the task
  - Reads the result that the server returns for the folder, so a delete that the server refuses fails the task
  - A folder that exists, but that keeper-secrets-manager-core cannot read, fails the task and is not deleted. It is not reported as not found. (keeper-secrets-manager-core 17.4.0 and later leave such a folder out of the folder list, with only a warning in the log)
  - The option is named `force_deletion`, not `force`, because `keeper_copy` in the same action group has a `force` option with a different meaning
* KSM-1478, KSM-1479, KSM-1480: The three new folder modules check their options
  - An unknown or misspelled option, an option set to null, or a value of the wrong type fails the task, instead of being ignored
  - A UID or a folder name must be a string. Put quotes around a number, or use the `string` filter (for example `"{{ year | string }}"`), because YAML can change the text of a number (`007` becomes `7`). A value that Ansible Vault encrypts is accepted
  - An option that a `module_defaults` entry for the action group of this collection sets, and that the module does not have, is ignored
  - A lookup, rename, or delete failure is a normal task failure, so `failed_when`, `ignore_errors`, and `rescue` work on it. An error in the KSM configuration still stops the task
  - `keeper_update_folder` and `keeper_delete_folder` support check mode
* **Security**: VM-1452 / CWE-502 — Replaced pickle with JSON for encrypted record cache serialization
  - Cache encrypt/decrypt no longer uses `pickle.loads`, removing insecure deserialization risk
  - Legacy or invalid registered caches are ignored; records are fetched from the vault until
    `keeper_cache_records` rebuilds a JSON cache
  - Existing playbook-registered caches are ephemeral; regenerate with `keeper_cache_records` after upgrade

## 1.4.0
* KSM-827: Fixed Tower Execution Environment Docker image missing system packages required by AAP
  - Added `openssh-clients`, `sshpass`, `rsync`, and `git` to `additional_build_packages` in `execution-environment.yml`
  - Resolves `[dumb-init] ssh agent: No such file or directory` error in Ansible Automation Platform
  - The `redhat/ubi9` base image (introduced Oct 2025) does not include these packages that the previous `ansible-runner` base provided
  - `openssh-clients`: provides `ssh-agent` required by AAP at container startup
  - `sshpass`: required for password-based SSH connections (`ansible_ssh_pass`)
  - `rsync`: required by `ansible.builtin.synchronize` module
  - `git`: required by `ansible.builtin.git` module
  - Added regression test to prevent recurrence
* KSM-816: Fixed `keeper_create` failing when the target shared folder contains no records
  - The plugin now uses the `get_folders` endpoint to resolve the folder encryption key,
    which returns all accessible folders regardless of whether they contain records
  - Previously, the plugin used `get_secrets` which only returns folder keys alongside
    records — empty shared folders were invisible, causing creation to fail
  - Closes [GitHub issue #934](https://github.com/Keeper-Security/secrets-manager/issues/934)
* KSM-811: Raised minimum Python version from 3.7 to 3.9
  - Aligns with the Python 3.9+ requirement of keeper-secrets-manager-core >= 17.2.0
  - Added classifiers for Python 3.12 and 3.13
* **Dependency Update**: Updated keeper-secrets-manager-core to >= 17.2.0 and keeper-secrets-manager-helper to >= 1.1.0

## 1.3.0
* KSM-781: Fixed Jinja2 templating for `keeper_config_file` and `keeper_cache_dir` variables
  - Variables like `{{ playbook_dir }}/keeper-config.yml` are now resolved before use
  - Lookup plugins (no action_module) are unaffected
* **Security**: KSM-762 - Fixed CVE-2026-23949 (jaraco.context path traversal) in SBOM generation workflow
  - Upgraded jaraco.context to >= 6.1.0 in SBOM generation workflow
  - Build-time dependency only, does not affect runtime or published packages
* KSM-714: Added notes field update support
  - Added `NOTES` to `KeeperFieldType` enum
  - Users can now update record notes via `keeper_set` tasks with `field_type: notes`
* KSM-768: Added notes field retrieval support
  - Added `notes` parameter to `keeper_get` action (boolean, default: no)
  - Users can now retrieve record notes via `keeper_get` tasks with `notes: yes`
  - Example: `keeper_get: uid: "XXX" notes: yes`
* KSM-770: Fixed bug in `keeper_get` with notes parameter
  - Fixed error "Cannot find key True" when using `notes: yes` with empty notes field
  - Notes field is now properly handled as singleton field (no lookup key required)
  - Added edge case test for missing notes field
* KSM-771: Fixed bug in `keeper_copy` with notes parameter
  - Fixed error "Unsupported parameters for copy module: notes" when using `keeper_copy` with `notes: yes`
  - Added cleanup of `notes` parameter before delegating to Ansible's built-in copy module
  - Added test for copying notes field to files
* KSM-772: Fixed bug in `keeper_set` with notes parameter
  - Fixed notes field being set to `None` instead of the provided value when using `keeper_set` with `notes: yes`
  - Changed `set_value()` method to use `value` parameter instead of `key` (which is None for singleton notes field)
  - Prevents silent data loss of existing notes content
  - Added test for setting notes field values
* KSM-773: Standardized `notes` parameter name across all actions (`keeper_create`, `keeper_set`, `keeper_copy`)
  - Renamed `note` to `notes` for consistency across all actions
* KSM-780: Fixed backward compatibility for `note` parameter in `keeper_create`
  - The `note` (singular) parameter is now accepted as a deprecated alias for `notes`
  - Playbooks using the old `note:` parameter will continue to work with a deprecation warning
  - The `note` alias will be removed in version 2.0.0
* **Dependency Update**: Updated Python SDK requirement to v17.1.0
  - Ensures compatibility with security fixes and latest features

## 1.2.6
* KSM-672: KSMCache class initializes cache file path before env vars are set. Closes ([issue #675](https://github.com/Keeper-Security/secrets-manager/issues/675))

## 1.2.5
* Updated plugin structure to support Ansible VS code extension ([Ansible VS Code extension](https://marketplace.visualstudio.com/items?itemName=redhat.ansible))

## 1.2.4
* Updated pinned KSM SDK version to 16.6.6.

## 1.2.3
* Updated pinned KSM SDK version to 16.6.4.

## 1.2.2
* Added action `keeper_get_record` to return record as a dictionary.
* Clean up comments.
* Updated pinned KSM SDK version to 16.6.3.

## 1.2.1
* Added action `keeper_remove` to remove secrets from the Keeper Vault
* Updated pinned KSM SDK version to 16.6.2.

## 1.2.0

* Added action `keeper_cache_records` to cache Keeper Vault records to reduce API calls.
* Added ability to get records by title for some actions.
* Added `array_index` and `value_key` to access individual values in complex values. Alternative to `notation`.
* Updated pinned KSM SDK version.

## 1.1.5

* Updated pinned KSM SDK version. The KSM SDK has been updated to use OpenSSL 3.0.7 which resolves CVE-2022-3602, CVE-2022-3786.

## 1.1.4

* Move check for custom record type in `keeper_create` plugin.
* Keeper Secret Manager SDK version pinned to 16.3.5 or greater. Allows extra field parameters
that come from Keeper Commander.

## 1.1.3

* Per PEP 263, added `# -*- coding: utf-8 -*-` to top of file to prevent errors on system that are not UTF-8.

## 1.1.2

* Added `keeper_create`, `keeper_password`, `keeper_info` action plugins.
* Fixed complex strings not regular expressions escaping properly for 
`keeper_redact`. 
* Added `keeper_app_owner_public_key` to the `keeper_init` plugin configuration
generation. `keeper_app_owner_public_key` also added to Ansible variables.

## 1.1.1
* Fixed misspelled collection name in `README.md`

## 1.1.0
* First Ansible Galaxy release
