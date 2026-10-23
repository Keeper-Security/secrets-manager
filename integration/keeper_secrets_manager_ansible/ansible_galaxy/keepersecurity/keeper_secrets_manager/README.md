![Ansible](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.ansible.yml/badge.svg) 

# Keeper Secrets Manager Collection

This collection allows you retrieve and update records in your Keeper Vault.

Additional documentation can be found on the [Keeper Secrets Manager Ansible](https://docs.keeper.io/secrets-manager/secrets-manager/integrations/ansible-plugin) 
document portal.

# Installation

The collection requires Python 3.9.2 or later and ansible-core 2.15.13 or later, except the 2.17 series. We test ansible-core 2.15.13 and the 2.16, 2.18, 2.19, 2.20, and 2.21 series. For the releases that upstream maintains, see the [ansible-core support matrix](https://docs.ansible.com/projects/ansible/latest/reference_appendices/release_and_maintenance.html).

The collection declares the ansible-core minimum in `meta/runtime.yml`. On an unsupported ansible-core, Ansible shows a
warning and still runs the collection. To stop with an error, set `collections_on_ansible_version_mismatch = error` in
the `[defaults]` section of `ansible.cfg`.

From version 1.5.0, the Tower Execution Environment image uses Python 3.12 and ansible-core 2.16 (2.16.19 or later).
Its managed nodes need Python 2.7, or Python 3.6 or later.

## Ansible Tower

In your playbook's source repository, add `keepersecurity.keeper_secrets_manager` to the
collections list of `collections/requirements.yml`.

There is an **Execution Environment** docker image location at
[https://hub.docker.com/r/keeper/keeper-secrets-manager-tower-ee](https://hub.docker.com/r/keeper/keeper-secrets-manager-tower-ee). 
The image contains this collection, keeper-secrets-manager-core, and keeper-secrets-manager-helper.

## Command Line

This collection requires [keeper-secrets-manager-core](https://pypi.org/project/keeper-secrets-manager-core/) 17.3.0 or later
and [keeper-secrets-manager-helper](https://pypi.org/project/keeper-secrets-manager-helper/) 1.1.2 or later.
Install them in the Python environment that runs Ansible. `ansible --version` shows that Python.

```shell
$ python3 -m pip install --upgrade 'keeper-secrets-manager-core>=17.3.0' 'keeper-secrets-manager-helper>=1.1.2'
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
        dest: "/home/user/.ssh/{{ item.filename }}"
        mode: "0600"
      loop:
        - { notation_key: "privateKey", filename: "id_rsa" }
        - { notation_key: "publicKey",  filename: "id_rsa.pub" }
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

The DR (disaster recovery) cache is the file `ksm_cache.bin`.
When `keeper_use_cache` is on, each successful record read from the Keeper server saves the response in this file.
When a later record request raises a transport exception, the plugin tries the saved response and warns when it uses it.
HTTP error responses still fail normally.
A user-set `KSM_CACHE_DIR` takes precedence. Otherwise `keeper_cache_dir` sets the directory. When neither is set, the file is in the working directory of `ansible-playbook`.
It is not the record cache that `keeper_cache_records` makes.

`keeper_cache_records` encrypts the record cache with `keeper_record_cache_secret`.
Use a long, random value.
The key also comes from the host name of the machine that runs the plugins. That machine is the Ansible controller or the AWX execution environment container.
A cache works only on the machine that made it.

In AWX and AAP, never set `keeper_use_cache`, `keeper_record_cache_secret`, `keeper_config_file`, or `keeper_cache_dir` from a launch-time extra variable or a survey answer.
Also do not let such a variable supply the value that a task passes to `cache`.
Extra variables override registered variables, so one with the same name as a registered cache replaces it.
Extra variables have the highest precedence, so they override the value that the playbook, the inventory, or a credential sets.
Keep `no_log: true` on the tasks that make or use the cache.

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
they also run with a token. Configurations are loaded into memory and the DR cache
file is not refreshed in check mode.

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
  - Before: ansible-core 2.12.0 or later for the Python package, and ansible-base 2.10 or later for the Galaxy collection.
  - Now: ansible-core 2.15.13 or later, and not 2.17.x. The Python package does not install ansible-core, so pip does not install or upgrade it. With an unsupported ansible-core, the Galaxy collection shows a warning and still runs, unless `collections_on_ansible_version_mismatch = error` is set.
  - To do: run `ansible --version`. If the version is not supported, explicitly install or upgrade a supported ansible-core in the same Python environment before you upgrade the package: `python3 -m pip install 'ansible-core>=2.15.13,!=2.17.*'`. pip changes nothing when the installed version is already supported.
* Python
  - Before: Python 3.9 or later.
  - Now: Python 3.9.2 or later.
* Keeper SDK
  - Before: keeper-secrets-manager-core 17.2.0 or later and keeper-secrets-manager-helper 1.1.0 or later.
  - Now: keeper-secrets-manager-core 17.3.0 or later and keeper-secrets-manager-helper 1.1.2 or later.
  - To do: pip upgrades both packages when it upgrades the Python package. For the Galaxy collection, run `python3 -m pip install --upgrade 'keeper-secrets-manager-core>=17.3.0' 'keeper-secrets-manager-helper>=1.1.2'`. An execution environment that installs this collection needs the same versions.
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
* A record that keeper-secrets-manager-core cannot read is not treated as missing. The task fails, and nothing is deleted.
* With keeper-secrets-manager-core 17.3.0, one record that it cannot read makes it skip every record that the server returns in the same shared folder. A lookup by UID requests only the selected record, so a readable record in that folder can still be removed.
* A remove by title fails when keeper-secrets-manager-core cannot read any record or folder of the application. That item can hold a record with the same title. To do: remove the record by its UID.
* A title that matches more than one record fails the task and lists the matching UIDs. A delete that the server refuses or does not confirm fails the task with the server response code and message.
* Failures are normal task results, so `failed_when`, `ignore_errors`, and `rescue` work.
* An unknown option, or an option of the wrong type, now fails the task. Before, it was ignored.
* A remove by title reads every record of the application. A loop of removals by title reads every record again for each item.
* Check mode no longer deletes records. Before, `--check` deleted them. Now it reports the predicted change.
* The result includes the decrypted `record_title`. Task results go to the console, callback plugins, and job history. Set `no_log: true` on the task if a title is sensitive.

## keeper_copy

* `keeper_copy` no longer returns `checksum`, `md5sum`, or `size`, and `invocation` no longer holds `checksum`. These values come from the copied secret, so a short secret can be found from them. The result keeps the change and error fields, `dest`, `path`, `src`, `mode`, `owner`, `group`, `uid`, `gid`, `state`, `backup_file`, and `diff`. To do: remove any `when:` condition or `register` use that reads the three values.
* A failed `validate:` of `keeper_copy` no longer returns `exit_status`, `stdout`, or `stderr`, and a failed copy no longer returns `traceback`. The validate command reads the secret file, so its output can show the content.
* `keeper_copy` with `--diff` shows a placeholder instead of the old and the new file content.

## Check mode

* `keeper_init` is skipped in check mode. Before, it redeemed the one-time token and wrote the configuration file.
* A plugin that reads the vault, and the `keeper` lookup, now fail in check mode when the configuration has only a one-time token. Before, they redeemed the token. To do: run `keeper_init` without check mode first, or supply an initialized configuration. `keeper_password`, `keeper_info`, and `keeper_cleanup` never contact the vault and still run.
* A new record or folder has a null `record_uid` or `folder_uid` in check mode. The Check mode section above shows how to skip tasks that depend on the new UID.

## keeper_set

* `keeper_set` updates one record. A UID that matches more than one live record now fails the task. Before, it updated the first one.
* A list with one item for `uid` or `title` counts as that item. A list with two or more items fails the task. To do: replace a list of two or more values with one task for each record.

## Cache and outage behavior

* `keeper_set` and `keeper_remove` read the record from the vault. They never use the DR cache or a registered cache, because an old copy can select a renamed record or hide a needed save.
* During a Keeper outage, these two tasks now fail instead of using the DR cache.
* `keeper_set` and `keeper_remove` accept the `cache` option, ignore it, and show a warning.
* Versions 1.2.0 to 1.4.0 serialize the registered cache with pickle. Version 1.5.0 uses JSON.
* A cache that version 1.4.0 or earlier made cannot be used. A task that gets one shows a warning and reads the records from the vault. To do: upgrade to 1.5.0, then make the cache again with `keeper_cache_records`.

## keeper_redact

* The callback hides a multiline value in `stdout`, `stderr`, and the line lists, with LF or CRLF line endings.
* It does not hide one line of the value on its own, the lines joined with another separator, a YAML dump, some of the lines, or the lines in a different order. To do: use `no_log: true` on a task that prints or transforms a multiline secret.

## Variables and files

* `keeper_verify_ssl_certs_skip` and `keeper_force_config_write` now accept only boolean values: `true`, `false`, `yes`, `no`, `on`, `off`, `y`, `n`, `t`, `f`, `1`, and `0`, in any case. Any other value, including an empty string, fails the task. Before, any non-empty text counted as true, so `-e keeper_verify_ssl_certs_skip=false` turned certificate verification off. To do: replace other values with a boolean.
* Configuration files that the plugin writes, and the DR cache file, now have mode 0600. A DR cache file that other users can read is changed to 0600 when the plugin next saves it. Before, they had the umask mode, often 0644. To do: if another user or service account reads these files, change its access.

## Logs and files from earlier versions

Version 1.5.0 does not change logs, job output, or files that earlier versions wrote.

* Earlier versions can show secret content in `keeper_copy` output with `--diff`, and in the output of a failed `validate:`. Output that `keeper_redact` did not hide can also show secrets. To do: change each secret that such output shows.
* A failed request through a proxy can show the proxy user name and password. To do: change a proxy password that such output shows.
* `keeper_copy` results show the SHA-1 and MD5 of the secret in `checksum` and `md5sum`. To do: change a short secret if a log shows these values.
* A configuration file that an earlier version wrote keeps its mode, often 0644. To do: run `chmod 600` on the file. If other local users had read access, remove that device from the KSM application and make a new configuration from a new one-time access token.

# Changes

## 1.5.0
Upgrading to 1.5.0 above lists what to change in existing playbooks.

### Added
* KSM-845, KSM-1673: Added the `subfolder_uid` option to `keeper_create` for subfolder targeting
  - Records can now be created in a subfolder at any depth under a shared folder, not only at the shared folder root
  - `shared_folder_uid` remains required, and `subfolder_uid` is optional
  - The name matches the `subfolder_uid` option of `keeper_create_folder` and of the Python SDK `CreateOptions`
  - The module checks the folder hierarchy before it prepares or creates the record. A `subfolder_uid` that is not inside `shared_folder_uid` fails the task, also in check mode, and no record is created
* KSM-1445, KSM-1646: Added the `keeper_create_folder` module for idempotent folder creation
  - Creates a folder directly in a shared folder, or inside an existing subfolder of that shared folder
  - If a folder with the given name already exists directly under the target parent, the module returns its UID and does not create a duplicate
  - `shared_folder_uid` must be a shared folder, not a subfolder. `subfolder_uid` must be a folder inside it. Any other value fails the task. This check runs in check mode and when the folder already exists
* KSM-1478, KSM-1674: Added the `keeper_get_folder` module to look up a folder and get its UID
  - Finds a folder by name in a shared folder or in a subfolder, or by a path of names such as `Databases/Production`
  - With no start UID, the first name is the name of a shared folder, so a playbook can find a folder with no UID
  - Returns the folder UID, name, parent UID, and shared folder UID. `include_subfolders: yes` also returns every folder below it
  - Fails with an error if no folder matches, or if more than one folder matches. It never returns an empty result
  - If keeper-secrets-manager-core could not read every folder, a lookup by name or path fails, even when one folder matches, because an unreadable folder can hold a second match. A lookup by the UID of a readable folder still works
* KSM-1479: Added the `keeper_update_folder` module to rename a folder
  - Idempotent: if the folder already has the new name, the module reports `changed: false` and sends no update
  - Fails with an error if the folder does not exist or is not shared to the KSM application
  - A rename to the name of another folder in the same parent works, with a warning. A lookup of that name is then not unique
  - Supports check mode
* KSM-1480, KSM-1675: Added the `keeper_delete_folder` module to delete a folder
  - Idempotent: if the folder does not exist, the module reports `changed: false` and does not fail
  - Deletes only an empty folder, unless `force_deletion: yes` is set. A folder with records or subfolders fails the task
  - Reads the result that the server returns for the folder, so a delete that the server refuses fails the task
  - If the server returns no status and keeper-secrets-manager-core could not read every folder, the task fails. The folder can be one that it could not read, so the module does not report it as deleted
  - A folder that exists, but that keeper-secrets-manager-core cannot read, fails the task and is not deleted. It is not reported as not found
  - The option is named `force_deletion`, not `force`, because `keeper_copy` in the same action group has a `force` option with a different meaning
  - Supports check mode
* KSM-1478, KSM-1479, KSM-1480, KSM-1647: The four new folder modules check their options
  - An unknown or misspelled option, an option set to null, or a value of the wrong type fails the task, instead of being ignored. Only a null `subfolder_uid` in `keeper_create_folder` is accepted. It means the shared folder
  - A UID or a folder name must be a string. Put quotes around a number, or use the `string` filter, for example `"{{ year | string }}"`. YAML can change the text of a number: `007` becomes `7`. A value that Ansible Vault encrypts is accepted
  - A folder name must not be blank. It must not start or end with whitespace, such as a space, a tab, or a newline. This rule applies to a new folder and to the new name in a rename. A YAML block scalar (`|` or `>`) adds a newline at the end, so use `|-` or `>-`
  - A `module_defaults` entry for the action group of this collection can set an option that a module does not have. The module ignores that option
  - A lookup, rename, or delete failure is a normal task failure, so `failed_when`, `ignore_errors`, and `rescue` work on it. `failed_when` does not apply to an error in the KSM configuration
* KSM-1664, KSM-1694: The folder actions and `keeper_create` hide folder names and paths in errors when `no_log: true` is set
  - This applies when `no_log` is set on the task, play, or block, or with `ANSIBLE_NO_LOG`
  - A failed folder action returns the message "The folder operation failed. Diagnostic details are hidden because no_log is enabled." Match on the `failed` result, not on this text
  - The keeper-secrets-manager-core log messages about folders do not show
  - The guidance for a wrong option or a renamed option still shows, without the value of the option
* KSM-1613: Added a warning when a task sets the `cache` option on `keeper_set` or `keeper_remove`
  - Both tasks always read the current vault, so the option has no effect

### Changed
* KSM-1559, KSM-1644: Made `keeper_remove` idempotent and corrected its task results
  - **Breaking change**: a missing record, by UID or title, succeeds with `changed: false`. Before, the task failed
  - **Breaking change**: a confirmed delete reports `changed: true` with `record_uid` and `record_title`, so it notifies handlers
  - **Breaking change**: check mode predicts the change and does not delete records. Before, `--check` deleted them
  - A record that keeper-secrets-manager-core cannot read fails the task, and nothing is deleted
  - Lookup, validation, and delete failures are task results, so `failed_when`, `ignore_errors`, and `rescue` work
  - The keeper_remove section under Upgrading to 1.5.0 lists the other changes
* KSM-1560: Prevented vault changes and local file changes in Ansible check mode
  - Added read-only previews for `keeper_create`, `keeper_set`, `keeper_create_folder`, and `keeper_cleanup`
  - `keeper_init` is skipped in check mode, so the one-time token stays unused and no configuration file is written
  - Initialized configurations load into memory, and the DR cache file is not refreshed
  - The `keeper` lookup follows `--check`, and a play or task `check_mode` keyword on ansible-core 2.19 and later
  - **Breaking change**: in normal runs, `keeper_create`, `keeper_init`, `keeper_set`, and `keeper_cleanup` report `changed` differently. Task results and handlers under Upgrading to 1.5.0 lists the details
  - **Breaking change**: in check mode, modules that read the vault fail with a configuration that has only a one-time token. `keeper_password`, `keeper_info`, and `keeper_cleanup` still run
* KSM-1559, KSM-1560: Made `keeper_remove` and `keeper_set` read the record from the vault, never from the DR cache
  - A DR cache that is older than the vault can hold a record under its old title. A title lookup then selected that record, and the delete or the save went to it
  - **Breaking change**: during a Keeper outage, these two tasks now fail instead of using the DR cache
* KSM-1561: Raised the minimum ansible-core version to 2.15.13 and excluded the 2.17 series
  - **Breaking change**: ansible-base 2.10, ansible-core versions before 2.15.13, and ansible-core 2.17.x are no longer supported
  - Python 3.9 stays supported, from Python 3.9.2. A later release removes it
  - The new minimum removes the ansible-core releases that CVE-2023-5115, CVE-2023-5764, CVE-2024-0690, CVE-2024-8775, and CVE-2024-9902 affect
  - For the Galaxy collection, an unsupported ansible-core shows a warning, and the collection still runs, unless `collections_on_ansible_version_mismatch = error` is set
  - The Tower Execution Environment now uses Python 3.12 and ansible-core 2.16 (2.16.19 or later), instead of Python 3.9 and ansible-core 2.15.13
* KSM-1562: Enforced the SDK versions in execution environments
  - The Tower Execution Environment and the collection require keeper-secrets-manager-core 17.3.0 or later and keeper-secrets-manager-helper 1.1.2 or later
  - The collection includes a `requirements.txt` at its root, so `ansible-builder` installs both packages when it builds an image from the collection
* KSM-1649: Removed ansible-core from the dependencies of the Python package
  - **Breaking change**: the Python package does not install ansible-core, so pip does not install or upgrade it, and pip does not check its version. Before, pip installed ansible-core with the package
  - Explicitly install or upgrade a supported ansible-core in the same Python environment (`ansible-core>=2.15.13,!=2.17.*`)
  - This change applies only to the Python package. The Tower Execution Environment image still includes ansible-core

### Security
* KSM-1560: Fixed the file mode of configuration files and the DR cache file
  - Earlier versions used the umask mode, often 0644, which let other local users read the keys
  - Configuration files that the plugin writes, and the DR cache file, now have mode 0600
  - This covers the configuration file that `keeper_init` writes, the configuration file that the plugin writes from `keeper_*` variables, and the DR cache file
* KSM-1560: Fixed `keeper_copy` showing the secret with `--diff`
  - The diff and the task result showed the old and the new file content, even with the `keeper_redact` callback
  - `keeper_copy` now shows a placeholder instead of the file content
* KSM-1636: Fixed `keeper_copy` returning hashes of the secret in its task result
  - The result held the SHA-1 of the secret, even in a failed copy. A hash of a short secret can be found by guessing, and the `keeper_redact` callback did not hide it
  - **Breaking change**: `keeper_copy` no longer returns `checksum`, `md5sum`, or `size`, and `invocation` no longer holds `checksum`
  - The result now keeps only a fixed list of keys, so a new key that ansible-core adds to the copy result is not shown
  - **Breaking change**: a failed `validate:` no longer returns `exit_status`, `stdout`, or `stderr`, and a failed copy no longer returns `traceback`
* KSM-1560: Fixed the text values of `keeper_verify_ssl_certs_skip` and `keeper_force_config_write`
  - `-e keeper_verify_ssl_certs_skip=false` or an INI inventory gave the text "false", which turned TLS certificate verification off. `keeper_force_config_write=false` wrote the keys to a file
  - Both variables now read boolean text correctly
  - A warning shows when certificate verification is off
  - **Breaking change**: a value that is not a boolean now fails the task
* KSM-1611: Fixed the proxy user name and password showing in task output and verbose logs
  - A failed request showed the proxy credential
  - A proxy URL that cannot be parsed fails with a message that asks you to percent-encode special characters in the proxy credentials
  - A proxy password with a character outside latin-1 fails with a message that says so
  - A bad Keeper server URL or file URL fails with its own message and does not blame the proxy
* KSM-1672: Fixed the download URL of an attachment showing in the error of a failed download
  - A failed attachment request could show the URL of the file in the task output
  - The error now names the operation and the type of the error, for example "The file download failed (SSLError)."
* KSM-1592, KSM-1638, KSM-1642, KSM-1667: Fixed the `keeper_redact` callback missing some secrets
  - The callback hides secret values that contain special characters, for example a multiline key
  - It hides a multiline value that a command prints as text or as a list of lines, with LF or CRLF line endings. A line of the value that is also ordinary text, such as `enabled`, stays visible in other output
  - It does not hide one line of a multiline value on its own, the lines joined with another separator, a YAML dump of the lines, some of the lines, or the lines in a different order. Use `no_log: true` on such tasks
  - It hides the values that `keeper_get`, `keeper_get_record`, and `keeper_password` return, including the content of a binary attachment
  - It also hides values of four or more characters when later tasks in the same run print them
  - It hides the SHA-1, MD5, and SHA-256 hashes of these values, because the built-in `copy` module prints the SHA-1 of its content. A hash that the controller cannot compute is not hidden. The secret value is still hidden
  - It hides `keeper_config`, `keeper_config_file`, `keeper_client_id`, `keeper_private_key`, `keeper_app_key`, `keeper_token`, and `keeper_record_cache_secret` when a task result shows the variable by name, for example with `debug: var=keeper_token`. It hides the full value, even when the value is a dictionary or a list
  - It does not hide these values under another name, for example in `msg: "{{ keeper_token }}"` or in a `set_fact` copy with a new name. Use `no_log: true` on such tasks
  - Task results from the Keeper actions no longer include an internal key for the callback
* KSM-1103: Replaced pickle with JSON for the encrypted record cache (CWE-502)
  - Cache encryption and decryption no longer use `pickle.loads`, which removes an insecure deserialization risk
  - Affected versions: 1.2.0 to 1.4.0. The fix is in 1.5.0
  - A legacy or invalid registered cache is ignored, and records come from the vault until `keeper_cache_records` rebuilds a JSON cache
  - A registered cache lasts for one playbook run. Make it again with `keeper_cache_records` after the upgrade

### Fixed
* KSM-1666: Fixed `keeper_set` updating the first record when a UID matched more than one live record
  - The task now fails
  - A list with one item, for `uid` or `title`, counts as that item. A list with two or more items fails the task, because an update needs one target
* KSM-1692: Fixed byte values in task results on Python 3.9 and 3.10 with ansible-core 2.15 and 2.16
  - A task that returned a byte value, for example a looped task that returns an attachment, could hang or fail on these controllers. Earlier versions, including 1.4.0, have the same problem
  - Newer Python and ansible-core versions are not affected
* KSM-1560: Fixed `keeper_copy` with `no_log: true` failing in check mode on ansible-core 2.15 to 2.20
  - Those versions replace the invocation of the task result with a text
* KSM-1560: Fixed the `KSM_CACHE_DIR` value of a `keeper` lookup reaching later tasks
  - A `keeper` lookup in a task name runs in the controller. The `KSM_CACHE_DIR` value that it set reached every later task
  - So later tasks wrote the DR cache to the directory of the first task, not to their own `keeper_cache_dir`
  - The plugin now replaces or removes a value that it set for an earlier task
  - A `KSM_CACHE_DIR` that the user sets still wins over `keeper_cache_dir`
* KSM-1560: Fixed the DR cache replacing a failed Keeper request with no message
  - A warning now shows the type of the error, the cache file, and the time of the cached response. Earlier versions showed no message, even for a TLS certificate error
  - Without a cache file, the error names both the failed request and the cache file
  - A failed save of the cache no longer replaces a fresh response with the old cached one
* KSM-1560: Fixed documentation and error messages
  - The documentation of `keeper_get`, `keeper_cache_records`, and the `keeper` lookup renders in ansible-doc
  - The module documentation of `keeper_copy`, `keeper_create`, `keeper_get`, and `keeper_set` lists every option
  - The error messages of the `keeper` lookup and the field check name the right plugin
  - `keeper_init` rejects a token with more than two parts with its own message. Before, it failed with an unpacking error
* KSM-1614: Fixed `ansible-doc -t callback keepersecurity.keeper_secrets_manager.keeper_redact` failing with a YAML error
  - One line of the callback documentation was not quoted. The documentation now renders
* KSM-1119, KSM-1645: Fixed `keeper_create` crashing with "Could not create record: list index out of range"
  - The crash happened when a playbook supplied an unpopulated complex field (address, name, host, and so on) with `value: []`
  - A field with `value: []` is now created unpopulated, the same as an empty field in the vault
  - A `false` or `0` value is kept as given
  - The crash comes from keeper-secrets-manager-helper. This release works around it

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
