#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
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


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        keeper = KeeperAnsible(task_vars=task_vars)
        return keeper.cleanup()
