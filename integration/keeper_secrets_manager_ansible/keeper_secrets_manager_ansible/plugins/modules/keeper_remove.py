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
    - A delete that the Keeper server refuses or does not confirm fails the task.
attributes:
  check_mode:
    support: full
    description: Looks up the record without sending a delete request. Server permissions are checked
      only in a real run.
notes:
  - Check mode requires an initialized Keeper configuration.
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
changed:
  description: Whether the Keeper server confirmed the delete, or whether a delete would be sent in check
    mode.
  returned: success
  type: bool
  sample: true
'''
