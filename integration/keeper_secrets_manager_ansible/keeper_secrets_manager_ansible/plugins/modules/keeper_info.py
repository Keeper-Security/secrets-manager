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
value:
  description: List of various Keeper related information.
  returned: success
  sample: |
    { 
        "record_type_list": ["record_type_1", "record_type_N" ],
        "field_type_list": ["field_type_1", "field_type_N" ],
    }
'''