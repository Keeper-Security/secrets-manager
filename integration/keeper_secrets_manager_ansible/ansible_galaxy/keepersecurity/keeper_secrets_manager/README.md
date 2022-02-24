![Ansible](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.ansible.yml/badge.svg) 

# Keeper Secrets Manager Collection

This collection allows you retrieve and update records in your Keeper Vault.

Additional documentation can be found on the [Keeper Secrets Manager Ansible](https://docs.keeper.io/secrets-manager/secrets-manager/integrations/ansible-plugin) 
document portal.

# Installation

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

* `keepersecurity.keeper_secrets_manager.keeper_copy` - Copy file, or value, from your vault to a remote server.
* `keepersecurity.keeper_secrets_manager.keeper_get` - Get a value from your vault.
* `keepersecurity.keeper_secrets_manager.keeper_set` - Set a value of an existing record in your vault.
* `keepersecurity.keeper_secrets_manager.keeper_cleanup` - Clean up Keeper related files.
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
keeper_server_public_key_id: '10'
```
The content of this YAML file can then be cut-n-pasted into a **group_vars**, **host_vars**, **all**
configuration file or even a playbook.

