# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#


DOCUMENTATION = r'''
---
module: keeper_init

short_description: Initialize a Keeper configuration using the one-time access token.

version_added: "1.0.1"

description:
    - Use the extra variable 'keeper_token' to pass in the one time access token.
    - The token can only be used once, so there is not reason to put it into any configuration file.
    - The configuration file output location can be set using the extra variable 'keeper_config_file'.
    - If 'keeper_config_file' is not defined, the configuration file will be written to the current directory.
    - By default, the configuration file will be a YAML file. If the extension of the 'keeper_config_file' is JSON, a 
      JSON file will be created.
author:
    - John Walstra
options:
  token:
    description:
    - The one-time access token.
    - This token can only be used once.
    - Hard coding the token into a role or playbook is not advised.
    - Best to set via extra variable passed to the playbook.
    type: str
    required: yes
  filename:
    description:
    - File path and name where to write the configuration file.
    - By default, a YAML file is created with key used by Ansible.
    - If the extension is JSON, the standard JSON config will be created.
    - If not set, a YAML configuration 
    type: str
    required: no
  show_config:
    description:
    - File path and name where to write the configuration file.
    - By default, a YAML file is created with key used by Ansible.
    - If the extension is JSON, the standard JSON config will be created.
    - If not set, a YAML configuration 
    type: str
    required: no    
'''

EXAMPLES = r'''
- name: Init the token
  keeper_init:
    token: XX:XXXXXXX
    keeper_config_file: /tmp/keeper_config.yml
'''

RETURN = r'''
keeper_client_id:
  description: Client ID for the application.
  returned: success
  sample: i31TDFtdZE .... oiCQ
keeper_private_key:
  description: Private key for the application.
  returned: success
  sample: MIGHAgEAMB .... JMJRzpE
keeper_app_key:
  description: Application key for the application.
  returned: success
  sample: zhLwB .... LPGY
keeper_app_owner_public_key:
  description: Public key that allows creation of records.
  returned: success
  version_added: '1.1.2' 
  sample: zhLwB .... LPGY
keeper_server_public_key_id:
  description: Id of the public key to use when sending request.
  returned: success
  sample: 10
keeper_hostname:
  description: Hostname to use ending request.
  returned: success
  sample: keepersecurity.com
'''