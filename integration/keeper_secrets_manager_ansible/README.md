# Keeper Secrets Manager Ansible

This module contains plugins that allow your Ansible automations to use Keeper Secrets Manager. 

* `keeper_cache_records` - Generate a cache to use with other actions.
* `keeper_copy` - Similar to `ansible.builtin.copy`. Uses the KSM vault for the source/content.
* `keeper_get` - Retrieve secrets from a record.
* `keeper_get_record` - Retrieve records as a dictionary.
* `keeper_set` - Update an existing record from Ansible information.
* `keeper_init` - Initialize a KSM configuration from a one-time access token.
* `keeper_cleanup` - Remove the cache file, if being used.
* `keeper_lookup` - Retrieve secrets from a record using Ansible's lookup.
* `keeper_redact` - Stdout Callback plugin to redact secrets from logs.
* `keeper_password` - Generate a random password.
* `keeper_info` - Display information about plugin, record and field types.
* `keeper_remove` - Remove secrets from the Keeper Vault.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/integrations/ansible-plugin

# Changes

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
