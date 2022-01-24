![Ansible](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.ansible.yml/badge.svg) 

| In development. Wait until version is 1.1.0. |
|----|

# Keeper Secrets Manager Collection

This collection allows you retrieve and update records in your Keeper Vault.

Additional documentation can be found one the [Keeper Secrets Manager Ansible](https://docs.keeper.io/secrets-manager/secrets-manager/integrations/ansible-plugin) 
document portal.

# Installation

This collection requires the [keeper-secrets-manager-core](https://pypi.org/project/keeper-secrets-manager-core/) 
Python SDK. Use pip to install this module into the modules used by your installation of Ansible.

```shell
$ pip3 install -U keeper-secrets-manager-core
```
Then install the collection.

```shell
$ ansible-galaxy collection install keepersecrity.keeper_secrets_manager
```

# Plugins

This is a list of action and lookup plugins. If you wish, you can set the
collections in your task and just used the short name (ie keeper_copy)

```yaml
- name: Keeper Task
  collections: keepersecurity.keeper_secrets_manager
  
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

* `keepersecurity.keeper_secrets_manager.keeper_copy` - Copy file, or value, from your vault to a remote server.
* `keepersecurity.keeper_secrets_manager.keeper_get` - Get a value from your vault.
* `keepersecurity.keeper_secrets_manager.keeper_set` - Set a value of an existing record in your vault.
* `keepersecurity.keeper_secrets_manager.keeper_cleanup` - Clean up Keeper related files.
* `keepersecurity.keeper_secrets_manager.keeper_init` - Init a one-time access token. Returns a configuration.

## Lookup

* `keepersecurity.keeper_secrets_manager.keeper` - Get a value from your vault via a lookup.

# Examples


