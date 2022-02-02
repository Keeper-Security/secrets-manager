# Keeper Secrets Manager Ansible

This module contains plugins that allow your Ansible automations to use Keeper Secrets Manager. 

* `keeper_copy` - Similar to `ansible.builtin.copy`. Uses the KSM vault for the source/content.
* `keeper_get` - Retrieve secrets from a record.
* `keeper_set` - Update an existing record from Ansible information.
* `keeper_init` - Initialize a KSM configuration from a one-time access token.
* `keeper_cleanup` - Remove the cache file, if being used.
* `keeper_lookup` - Retrieve secrets from a record using Ansible's lookup.
* `keeper_redact` - Stdout Callback plugin to redact secrets from logs.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/integrations/ansible-plugin
