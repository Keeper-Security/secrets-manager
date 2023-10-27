# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from ansible.plugins.action import ActionBase
from ansible.errors import AnsibleError
from ansible.utils.display import Display
from keeper_secrets_manager_ansible import KeeperAnsible

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

display = Display()


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        keeper = KeeperAnsible(task_vars=task_vars, action_module=self)

        cache = self._task.args.get("cache")

        uid = self._task.args.get("uid")
        title = self._task.args.pop("title", None)
        if uid is None and title is None:
            raise AnsibleError("The uid and title are blank. keeper_get requires one to be set.")
        if uid is not None and title is not None:
            raise AnsibleError("The uid and title are both set. keeper_get requires one to be set, but not both.")

        keeper.remove_record(uids=uid, titles=title, cache=cache)

        return {}
