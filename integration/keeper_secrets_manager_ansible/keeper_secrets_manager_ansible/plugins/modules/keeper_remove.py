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
module: keeper_remove

short_description: Remove a secret from the vault.

version_added: "1.2.1"

description:
    - Remove a secret from the vault.
author:
    - John Walstra
options:
  uid:
    description:
    - The UID of the Keeper Vault record.
    type: str
    required: no
  title:
    description:
    - The Title of the Keeper Vault record.
    type: str
    required: no
    version_added: '1.2.0'
  cache:
    description:
    - The cache registered by keeper_get_records_cache.
    - Used to lookup Keeper Vault record by title.
    type: str
    required: no
    version_added: '1.2.0'  
'''

EXAMPLES = r'''
- name: Remove secret using UID.
  keeper_remove:
    uid: XXX
- name: Remove secret using title.
  keeper_remove:
    title: XXXXXXXXX

'''

RETURN = r'''
existed:
  description: Indicates that the record did exist in the Vault.
  returned: success
  sample: |
    {
      "existed": True
    },
'''