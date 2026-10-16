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

from ansible.plugins.action import ActionBase
from keeper_secrets_manager_ansible import KeeperAnsible

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


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        # The cleanup removes only a local file, so no request reaches the vault.
        keeper = KeeperAnsible(task_vars=task_vars, action_module=self, requires_vault=False)
        return keeper.cleanup(check_mode=bool(self._task.check_mode))
