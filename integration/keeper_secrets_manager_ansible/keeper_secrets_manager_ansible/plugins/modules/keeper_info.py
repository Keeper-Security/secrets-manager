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
module: keeper_info

short_description: Get information about the Keeper plugins.

version_added: "1.1.2"

description:
    - Get information about the Keeper plugins.
author:
    - John Walstra
'''

EXAMPLES = r'''
- name: Get Keeper info
  keeper_info:
'''

RETURN = r'''
versions:
  description: The installed versions of the Keeper Python packages. A package that is not installed shows Unknown.
  returned: success
  type: dict
  sample:
    keeper-secrets-manager-core: 17.3.0
    keeper-secrets-manager-ansible: 1.5.0
    keeper-secrets-manager-helper: 1.1.2
record_type_list:
  description: The names of the record types.
  returned: success
  type: list
  elements: str
  sample: [record_type_1, record_type_N]
field_type_list:
  description: The names of the field types.
  returned: success
  type: list
  elements: str
  sample: [field_type_1, field_type_N]
'''