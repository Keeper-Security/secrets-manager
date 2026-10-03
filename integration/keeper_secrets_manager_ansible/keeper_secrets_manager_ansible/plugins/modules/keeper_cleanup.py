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
attributes:
  check_mode:
    support: full
    description: Reports whether the enabled DR cache file exists without removing it.
notes:
  - In check mode, changed shows whether the cache file exists before the run. In a real run, the
    reads of earlier tasks can create the file first.
'''

EXAMPLES = r'''
- name: Clean up KSM Stuff
  keeper_cleanup:
'''

RETURN = r'''
changed:
  description: Whether a cache file was removed, or would be removed in check mode.
  returned: success
  type: bool
  sample: true
removed_ksm_cache:
  description: Whether the cache file was removed. False in check mode or when the file is absent.
  returned: when the DR cache is enabled
  type: bool
  sample: true
'''
