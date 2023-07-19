# Keeper Secrets Manager Ansible

This module contains plugins that allow your Ansible automations to use Keeper Secrets Manager. 

* `keeper_cache_records` - Generate a cache to use with other actions.
* `keeper_copy` - Similar to `ansible.builtin.copy`. Uses the KSM vault for the source/content.
* `keeper_get` - Retrieve secrets from a record.
* `keeper_set` - Update an existing record from Ansible information.
* `keeper_init` - Initialize a KSM configuration from a one-time access token.
* `keeper_cleanup` - Remove the cache file, if being used.
* `keeper_lookup` - Retrieve secrets from a record using Ansible's lookup.
* `keeper_redact` - Stdout Callback plugin to redact secrets from logs.
* `keeper_password` - Generate a random password.
* `keeper_info` - Display information about plugin, record and field types.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/integrations/ansible-plugin

# Changes

## 1.2.0

* Added action `keeper_cache_records` to cache Keeper Vault records to reduce API calls.
* Added ability to get records by title for some actions.
* Added `array_index` and `value_key` to access individual values in complex values. Alternative to `notation`.
* Update pinned KSM SDK version.

## 1.1.5

* Update pinned KSM SDK version. The KSM SDK has been updated to use OpenSSL 3.0.7 which resolves CVE-2022-3602, CVE-2022-3786.

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
