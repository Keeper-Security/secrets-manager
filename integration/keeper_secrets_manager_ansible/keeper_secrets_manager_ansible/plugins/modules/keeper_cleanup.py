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
module: keeper_cleanup

short_description: Clean up any temporary files created by the Keeper Secrets Manager modules.

version_added: "1.0.1"

description:
    - Cleans up the cache file, if they exists.
author:
    - John Walstra
'''

EXAMPLES = r'''
- name: Clean up KSM Stuff
  keeper_cleanup:
'''

RETURN = r'''
removed_ksm_cache:
  description: Was the KSM Cache file removed?
  returned: success
  sample: true  
'''
