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


DOCUMENTATION = r'''
---
module: keeper_get_records_cache

short_description: Get record by UID and/or Titles and return a encrypted serialization of the records.

version_added: "1.0.0"

description:
    - Retrieve Keeper records from the Vault using UIDs or Titles.
    - The records are then serialized and encrypted for the playbook run.
    - The encrypted serialization is only valid within the running playbook.
    - To store the encrypted serialized cache, use 'register' within the Task step.
    - For action that accept a cache, template the registered value into the cache variables.
    - To hide the cache string, set 'no_log: True' in the variables.
author:
    - John Walstra
options:
  uids:
    description:
    - The UID of the Keeper Vault records.
    type: list
    required: no
  titles:
    description:
    - The Title of the Keeper Vault records.
    type: list
    required: no
'''

EXAMPLES = r'''

- name: Generate a Keeper Record Cache secret
  keeper_password:
    length: 64
  register: keeper_record_cache_secret
  no_log: True

- name: Store the Keeper Record Cache secret into variables.
  set_fact:
    keeper_record_cache_secret: "{{ keeper_record_cache_secret.password }}"
  no_log: True

- name: Cache records. Will use keeper_record_cache_secret from above.
  keeper_cache_records:
    uids: 
      - XXX
      - YYYY
    titles:
      - My Machine Record
      - My Router Record
  register: my_records
  no_log: True
'''

RETURN = r'''
value:
  description: The serialized encrypted cache.
  returned: success
  sample: |
    {
      "cache": "XXXX .... XXXXX"
    }
'''
