![Ansible](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.ansible.yml/badge.svg) 

# Keeper Secrets Manager Collection

This collection allows you retrieve and update records in your Keeper Vault.

Additional documentation can be found on the [Keeper Secrets Manager Ansible](https://docs.keeper.io/secrets-manager/secrets-manager/integrations/ansible-plugin) 
document portal.

# Installation

Python 3.9.2 or later and ansible-core 2.15.13 or later, but not the 2.17 series, are required. We recommend Python
3.12 or later with ansible-core 2.20 or later.

The collection declares the ansible-core minimum in `meta/runtime.yml`. On an unsupported ansible-core, Ansible shows a
warning and still runs the collection. To stop with an error, set `collections_on_ansible_version_mismatch = error` in
the `[defaults]` section of `ansible.cfg`.

From version 1.5.0, the Tower Execution Environment image uses Python 3.12 and ansible-core 2.16 (2.16.19 or later).
Its managed nodes need Python 2.7, or Python 3.6 or later.

## Ansible Tower

In your playbook's source repository, add `keepersecurity.keeper_secrets_manager` to the
`requirement.yml` collections list.

There is an **Execution Environment** docker image location at
[https://hub.docker.com/repository/docker/keeper/keeper-secrets-manager-tower-ee](https://hub.docker.com/repository/docker/keeper/keeper-secrets-manager-tower-ee). 
This **Execution Environment** contains the Python SDK.

## Command Line

This collection requires the [keeper-secrets-manager-core](https://pypi.org/project/keeper-secrets-manager-core/) 
Python SDK. Use `pip` to install this module into the modules used by your installation of Ansible.

```shell
$ pip3 install -U keeper-secrets-manager-core
```
Then install the collection.

```shell
$ ansible-galaxy collection install keepersecurity.keeper_secrets_manager
```

# Plugins

If you wish, you can set the collections in your task and
just used the short name (ie keeper_copy)

```yaml
- name: Keeper Task
  collections: 
    - keepersecurity.keeper_secrets_manager
  
  tasks:
    - name: "Copy My SSH Keys"
      keeper_copy:
        notation: "OlLZ6JLjnyMOS3CiIPHBjw/field/keyPair[{{ item.notation_key }}]"
        dest: "/home/user/.ssh/{{ item.filename }}"
        mode: "0600"
      loop:
        - { notation_key: "privateKey", filename: "id_rsa" }
        - { notation_key: "publicKey",  filename: "id_rsa.pub" }
```
If you omit the `collections` , you will need to use the full plugin name.
```yaml
  tasks:
    - name: "Copy My SSH Keys"
      keepersecurity.keeper_secrets_manager.keeper_copy:
        notation: "OlLZ6JLjnyMOS3CiIPHBjw/field/keyPair[{{ item.notation_key }}]"
```

## Action

* `keepersecurity.keeper_secrets_manager.keeper_cache_records` - Generate a cache to use with other actions.
* `keepersecurity.keeper_secrets_manager.keeper_copy` - Copy file, or value, from your vault to a remote server.
* `keepersecurity.keeper_secrets_manager.keeper_get` - Get a value from a record.
* `keepersecurity.keeper_secrets_manager.keeper_get_record` - Get record as a dictionary.
* `keepersecurity.keeper_secrets_manager.keeper_set` - Set a value of an existing record in your vault.
* `keepersecurity.keeper_secrets_manager.keeper_create` - Create a new record.
* `keepersecurity.keeper_secrets_manager.keeper_create_folder` - Create a new folder.
* `keepersecurity.keeper_secrets_manager.keeper_get_folder` - Look up a folder by name or path, and get its UID.
* `keepersecurity.keeper_secrets_manager.keeper_update_folder` - Rename a folder.
* `keepersecurity.keeper_secrets_manager.keeper_delete_folder` - Delete a folder.
* `keepersecurity.keeper_secrets_manager.keeper_remove` - Remove a record from your vault.
* `keepersecurity.keeper_secrets_manager.keeper_password` - Generate a random password.
* `keepersecurity.keeper_secrets_manager.keeper_cleanup` - Clean up Keeper related files.
* `keepersecurity.keeper_secrets_manager.keeper_info` - Display information about plugin, record and field types.
* `keepersecurity.keeper_secrets_manager.keeper_init` - Init a one-time access token. Returns a configuration.

## Lookup

* `keepersecurity.keeper_secrets_manager.keeper` - Get a value from your vault via a lookup.

## Callback

* `keepersecurity.keeper_secrets_manager.keeper_redact` - Stdout callback plugin to redact secret values.

## keeper_init_token Role

Initializing a configuration from a one-time access token. Getting the 
token is explained in the
[One Time Access Token](https://docs.keeper.io/secrets-manager/secrets-manager/about/one-time-token) document.

Then create a simple playbook to initialize the token.

```yaml
- name: Initialize the Keeper one time access token.
  hosts: localhost
  connection: local
  collections: keepersecurity.keeper_secrets_manager

  roles:
    - keeper_init_token
```
Then run the playbook. Pass the token in using the extra var param (-e).
```shell
$ ansible-playbook keeper_init.yml -e keeper_token=US:XXX -e keeper_config_file=keeper-config.yml
```
When done there will be a file called `keeper-config.yml` which will contain the configuration
for your device.

```yaml
keeper_app_key: +U5Jao ... l5FmXymVI=
keeper_client_id: Fokc6j ... PlBwzAKlMUgFZHqLg==
keeper_hostname: US
keeper_private_key: MIGHf ... IcvCihUHyA7Oy
keeper_app_owner_public_key: AXY ... Nlaks==
keeper_server_public_key_id: '10'
```
The content of this YAML file can then be cut-n-pasted into a **group_vars**, **host_vars**, **all**
configuration file or even a playbook.

# Configuration notes

The plugins read the Keeper configuration from the file in `keeper_config_file`,
from the base64 `keeper_config` variable, or from `keeper_*` variables. They do
not read the `KSM_CONFIG` and `KSM_CONFIG_FILE` environment variables of the
Keeper SDK. With a configuration file, `keeper_hostname` and
`keeper_verify_ssl_certs_skip` have no effect: the hostname comes from the file,
and only `KSM_SKIP_VERIFY` can turn certificate verification off.

# Check mode

Use `ansible-playbook --check` or `check_mode: yes` on a play or task to preview
Keeper changes. `keeper_create`, `keeper_set`, `keeper_create_folder`,
`keeper_update_folder`, `keeper_delete_folder`, `keeper_remove`, and
`keeper_cleanup` perform their read-only checks and report `changed` without
changing the vault or writing or deleting local files. `keeper_init` is skipped
because redeeming a one-time token cannot be undone.

Use an initialized Keeper configuration for a dry run. Modules that read the vault
reject a configuration that has only a one-time token before connecting.
`keeper_password`, `keeper_info`, and `keeper_cleanup` never contact the vault, so
they also run with a token. Configurations are loaded into memory and the DR file
cache is not refreshed in check mode.

The `keeper` lookup follows `--check` on every ansible-core version. It follows a
play or task `check_mode` keyword only on ansible-core 2.19 and later. With an
older ansible-core, use `--check`, or read with `keeper_get` in a dry run.

New records and folders have no UID in check mode, so their `record_uid` or
`folder_uid` is null. An existing folder still returns its UID and `changed: false`.
Skip tasks that depend on newly created UIDs during a dry run, for example with
`when: created_record.record_uid is not none`. A `when: not ansible_check_mode`
condition does not see a play or task `check_mode` keyword. An empty or null
`subfolder_uid` means no subfolder, so a later task that runs for real with a null
UID from check mode uses the shared folder.

`keeper_set` returns `updated: false` and `keeper_cleanup` returns
`removed_ksm_cache: false` in check mode, even when they predict `changed: true`.
`keeper_cleanup` predicts from the cache file as it is before the run. In a real
run, the reads of earlier tasks can create the file first.

A task that reports `changed: true` notifies its handlers in check mode too.
Handlers run in check mode, but a handler with `check_mode: false` makes real
changes.

# Upgrading to 1.5.0

Version 1.5.0 changes how some existing tasks behave.
Check each item below against your playbooks before you upgrade.
The Changes section names the ticket for each change.

## Requirements

* ansible-core
  - Before: ansible-core 2.12.0 or later.
  - Now: ansible-core 2.15.13 or later, and not 2.17.x. The Python package refuses to install with an unsupported ansible-core. The Galaxy collection shows a warning and still runs.
  - To do: upgrade ansible-core before you upgrade the package.
* Python
  - Before: Python 3.9 or later.
  - Now: Python 3.9.2 or later.
* Keeper SDK
  - Before: keeper-secrets-manager-core 17.2.0 and keeper-secrets-manager-helper 1.1.0.
  - Now: keeper-secrets-manager-core 17.3.0 or later and keeper-secrets-manager-helper 1.1.2 or later.
  - To do: upgrade both packages. An execution environment that installs this collection needs the same versions.
* Tower Execution Environment
  - Before: Python 3.9 and ansible-core 2.15.13.
  - Now: Python 3.12 and ansible-core 2.16.19 or later in the 2.16 series.
  - To do: rebuild any image that you based on the old definition.

## Task results and handlers

* `keeper_create` and `keeper_init` now report `changed: true`. Before, they reported no change.
* `keeper_set` reports `changed: true` and `updated: true` only when it saves a new value. Before, it always set `updated: true` and never reported a change. A task that sets the value that the record already has now saves nothing and reports `changed: false`.
* `keeper_cleanup` reports a change only when the DR cache file exists. `removed_ksm_cache` is `false` when there is no file.
* `keeper_remove` reports `changed: true` with `record_uid` and `record_title` for a confirmed delete. It reports `changed: false` when the record does not exist.
* To do: review `when:` conditions on these results, `changed_when`, and `notify`. Handlers now run after these tasks, and the play recap counts change.

## keeper_remove

* A record that does not exist, by UID or by title, now succeeds with `changed: false`. Before, the task failed. Remove `ignore_errors` or `failed_when` workarounds that only tolerated a missing record. If a playbook used the failure to detect a missing record, test `changed` instead.
* A title that matches more than one record fails the task and lists the matching UIDs. A delete that the server refuses or does not confirm fails the task with the server response code and message.
* Failures are normal task results, so `failed_when`, `ignore_errors`, and `rescue` work.
* An unknown option, or an option of the wrong type, now fails the task. Before, it was ignored.
* The `cache` option is accepted but has no effect. A delete always reads the current vault, and a lookup by title reads every record. A loop of removals makes one full vault read for each task.
* Check mode no longer deletes records. Before, `--check` deleted them. Now it reports the predicted change.
* The result includes the decrypted `record_title`. Task results go to the console, callback plugins, and job history. Set `no_log: true` on the task if a title is sensitive.

## Check mode

* `keeper_init` is skipped in check mode, so the one-time token stays unused and no configuration file is written.
* A plugin that reads the vault, and the `keeper` lookup, now fail in check mode when the configuration has only a one-time token. Before, they redeemed the token. To do: run `keeper_init` without check mode first, or supply an initialized configuration. `keeper_password`, `keeper_info`, and `keeper_cleanup` never contact the vault and still run.
* A new record or folder returns a null `record_uid` or `folder_uid` in check mode. Skip tasks that depend on the new UID, for example with `when: created_record.record_uid is not none`.
* The DR cache file is not refreshed in check mode.

## Cache and outage behavior

* `keeper_set` and `keeper_remove` read the record from the vault. They never use the DR cache or a registered cache, because an old copy can select a renamed record or hide a needed save.
* During a Keeper outage, these two tasks now fail instead of using the DR cache.
* `keeper_set` accepts the `cache` option but ignores it.

## Variables and files

* `keeper_verify_ssl_certs_skip` and `keeper_force_config_write` now accept only boolean values: `true`, `false`, `yes`, `no`, `on`, `off`, `y`, `n`, `t`, `f`, `1`, and `0`, in any case. Any other value, including an empty string, fails the task. Before, any non-empty text counted as true, so `-e keeper_verify_ssl_certs_skip=false` turned certificate verification off. To do: replace other values with a boolean.
* Configuration files that the plugin writes, and the DR cache file, now have mode 0600. A DR cache file that other users can read is changed to 0600 when the plugin next saves it. Before, they had the umask mode, often 0644. To do: if another user or service account reads these files, change its access.
* `keeper_copy` with `--diff` shows a placeholder instead of the old and the new file content.
* `keeper_init` fails with a clear message for a token with more than two parts, such as an IL5 token. Before, it failed with an unpacking error.

# Changes

## 1.5.0
* KSM-1559: Made `keeper_remove` idempotent and corrected its task results
  - A missing record, by UID or title, succeeds with `changed: false`
  - A confirmed delete reports `changed: true`, `record_uid`, and `record_title`
  - Duplicate titles fail with the matching UIDs; refused deletes fail with the server's response code and message
  - Lookup, validation, and delete failures are task results, so `failed_when`, `ignore_errors`, and `rescue` work
  - Check mode predicts the change without deleting records
  - Removal reads the current vault even when a registered cache is supplied, so stale caches cannot hide duplicate titles or report false no-ops
  - **Breaking change**: missing records no longer fail, and successful deletions now trigger change handlers
  - **Breaking change**: check mode no longer deletes records. Before this change, `--check` deleted them
  - An unknown option now fails the task, instead of being ignored
  - The `cache` option is accepted but ignored
* KSM-1560: Prevented vault mutations and local file changes in Ansible check mode
  - Added read-only previews for `keeper_create`, `keeper_set`, `keeper_create_folder`, and `keeper_cleanup`
  - `keeper_init` is skipped in check mode, preserving the one-time token and leaving configuration files untouched
  - Initialized configurations are loaded into memory, unbound tokens are rejected, and the DR file cache is not refreshed in check mode
  - The `keeper` lookup follows `--check`, and a play or task `check_mode` keyword on ansible-core 2.19 and later
  - **Breaking change**: record creation and token initialization now report `changed: true` in normal runs. `keeper_set` reports `changed: true` only when the value changes, and does not save a value that the record already has. It reads the record from the vault, also when a registered cache is given. Cache cleanup reports changed only when a cache file exists, and `removed_ksm_cache` is false when there is no cache file. Handlers and play recap counts now reflect these operations
  - **Breaking change**: in check mode, modules that read the vault fail with a configuration that has only a one-time token. `keeper_password`, `keeper_info`, and `keeper_cleanup` still run
* **Security** (KSM-1560): Configuration files that the plugin writes, and the DR cache file, are created with mode 0600. Before, a configuration file that `keeper_init` or the Ansible variables created, and the DR cache with keeper-secrets-manager-core 17.3.0, got the umask mode (often 0644), so other local users could read the keys
* **Security** (KSM-1560): `keeper_copy` with `--diff` shows a placeholder instead of the old and the new file content. Before, the diff and the task result showed the secret, also with the `keeper_redact` callback
* **Security** (KSM-1560): `keeper_verify_ssl_certs_skip` and `keeper_force_config_write` read text values correctly. Before, `-e keeper_verify_ssl_certs_skip=false` or an INI inventory gave the text "false", which turned TLS certificate verification off, and `keeper_force_config_write=false` wrote the keys to a file. A value that is not a boolean now fails the task, and a warning shows when certificate verification is off
* **Fix** (KSM-1560): `keeper_copy` with `no_log: true` failed in check mode on ansible-core 2.15 to 2.20, because those versions replace the invocation of the task result with a text
* **Fix** (KSM-1560): A `keeper` lookup in a task name runs in the controller, and the `KSM_CACHE_DIR` value that it set reached every later task. So later tasks wrote the DR cache to the directory of the first task, not to their own `keeper_cache_dir`. The plugin now replaces or removes a value that it set for an earlier task. A `KSM_CACHE_DIR` that the user sets still wins over `keeper_cache_dir`
* **Fix** (KSM-1560): When a request to the Keeper server fails and the DR cache replaces it, a warning shows the type of the error, the cache file, and the time of the cached response. Before, the old data was used with no message, also for a TLS certificate error. Without a cache file, the error names both the failed request and the cache file. A failed save of the cache no longer replaces a fresh response with the old cached one
* **Fix** (KSM-1560): The documentation of `keeper_get`, `keeper_cache_records`, and the `keeper` lookup renders in ansible-doc, and the module documentation of `keeper_copy`, `keeper_create`, `keeper_get`, and `keeper_set` lists every option. The error messages of the `keeper` lookup and the field check name the right plugin. `keeper_init` fails with a clear message for a token with more than two parts, for example an IL5 token
* **Fix** (KSM-1559, KSM-1560): `keeper_remove` and `keeper_set` read the record from the vault, never from the DR cache. A cached copy can be older than the vault, so a title could select a record that was renamed, and the delete or the save went to that record. During an outage, these tasks now fail, as their delete or save would
* **Fix**: `keeper_create` crashed with "Could not create record: list index out of range" when a playbook supplied an unpopulated complex field (address, name, host, etc.) with `value: []`. Empty-value fields are now treated as unpopulated, matching the behavior of the underlying vault schema. Root cause in the Python helper library is tracked as KSM-1119.
* **Breaking change**: KSM-1561: Raised the minimum ansible-core version to 2.15.13, and excluded the 2.17 series
  - ansible-base 2.10, ansible-core versions before 2.15.13, and ansible-core 2.17.x are no longer supported
  - Python 3.9 stays supported, from Python 3.9.2. A later release removes it
  - The new minimum removes ansible-core releases that are affected by CVE-2023-5115, CVE-2023-5764, CVE-2024-0690, CVE-2024-8775, and CVE-2024-9902
  - pip can no longer install the Python package with an unsupported ansible-core. For this collection, an unsupported ansible-core shows a warning, and the collection still runs
  - The Tower Execution Environment now uses Python 3.12 and ansible-core 2.16 (2.16.19 or later), instead of Python 3.9 and ansible-core 2.15.13
  - CI tests the 2.15, 2.16, 2.18, 2.19, 2.20, and 2.21 series, and a test checks that every file that declares the ansible-core or Python requirement agrees
* KSM-1562: Enforced the SDK versions in execution environments
  - The Tower Execution Environment and the collection require keeper-secrets-manager-core 17.3.0 or later and keeper-secrets-manager-helper 1.1.2 or later
  - The collection includes a `requirements.txt` at its root, so `ansible-builder` installs both packages when it builds an image from the collection
  - A test checks that the SDK versions agree in `setup.py`, `requirements.txt`, and the execution environment files
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
  - Added `openssh-clients`, `sshpass`, `rsync`, and `git` to the EE image
  - Resolves `[dumb-init] ssh agent: No such file or directory` error in Ansible Automation Platform
* KSM-816: Fixed `keeper_create` failing when the target shared folder contains no records
  - Closes [GitHub issue #934](https://github.com/Keeper-Security/secrets-manager/issues/934)
* KSM-811: Raised minimum Python version from 3.7 to 3.9
  - Replaced `importlib_metadata` backport with stdlib `importlib.metadata` (available since Python 3.8)
* **Dependency Update**: Updated keeper-secrets-manager-core to >= 17.2.0 and keeper-secrets-manager-helper to >= 1.1.0

## 1.3.0
* KSM-781: Fixed Jinja2 templating for `keeper_config_file` and `keeper_cache_dir` variables
* KSM-714: Added notes field update support to `keeper_set`
* KSM-768: Added notes field retrieval support to `keeper_get`
* KSM-770: Fixed `keeper_get` error when `notes: yes` is used with an empty notes field
* KSM-771: Fixed `keeper_copy` error when `notes: yes` parameter is present
* KSM-772: Fixed `keeper_set` notes field being set to `None` instead of provided value
* KSM-773: Standardized `notes` parameter name across `keeper_create`, `keeper_set`, `keeper_copy`
* KSM-780: Added backward-compatible `note` alias (deprecated, will be removed in 2.0.0)
* **Dependency Update**: Updated Python SDK requirement to v17.1.0

## 1.2.6
* KSM-672: KSMCache class initializes cache file path before env vars are set. Closes ([issue #675](https://github.com/Keeper-Security/secrets-manager/issues/675))

## 1.2.5
* Updated plugin structure to support Ansible VS code extension ([Ansible VS Code extension](https://marketplace.visualstudio.com/items?itemName=redhat.ansible))

## 1.2.4
* Updated pinned KSM SDK version to 16.6.6.

## 1.2.3
* Updated pinned KSM SDK version to 16.6.4.

## 1.2.2
* Added action `keeper_get_record` to return entire record as dictionary.
* Clean up comments in code.
* Updated pinned KSM SDK version to 16.6.3.

## 1.2.1
* Added action `keeper_remove` to remove secrets from the Keeper Vault.
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
