# Keeper Secrets Manager Ansible

## Overview

This module contains plugins that allow your Ansible automations to use Keeper Secrets
Manager. 

* keeper_copy - Similar to ansible.builtin.copy. Uses the KSM vault for the ource/content.
* keeper_get - Retrieve secrets from a record.
* keeper_set - Update an existing record from Ansible information.
* keeper_lookup - Retrieve secrets from a record using Ansible's lookup.

The full documentation can be found on [GitBook](https://app.gitbook.com/@keeper-security/s/secrets-manager/secrets-manager/integrations/ansible-plugin).

## Quick Start

Install, or update, the module.

    $ pip install -U keeper-secrets-manager-ansible

Create a configuration file.

    $ cd /path/to/your/ansible/root
    $ keeper_ansible --keeper_token XXXX
    Config file created at location client-config.json

Get plugins directory paths.

    $ keeper_ansible --config

    # Below are the directory paths to action and lookup plugins.
    ANSIBLE_ACTION_PLUGINS=.../site-packages/keeper_secrets_manager_ansible/plugins/action_plugins
    ANSIBLE_LOOKUP_PLUGINS=.../site-packages/keeper_secrets_manager_ansible/plugins/lookup_plugins

Either copy the paths into your ansible.cfg.

    [defaults]
    action_plugins = ../site-packages/keeper_secrets_manager_ansible/plugins/action_plugins
    lookup_plugins = .../site-packages/keeper_secrets_manager_ansible/plugins/lookup_plugins

Or do some DevOps magic

    $ export $(keeper_ansible --config)

Use some plugins in your playbooks tasks or roles. See full documentation for examples.

Then run your playbook.

    $ ansible-playbook my_playbook.yml