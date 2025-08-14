# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from ansible.plugins.action import ActionBase
from ansible.errors import AnsibleError
from keeper_secrets_manager_ansible import KeeperAnsible


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


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        keeper = KeeperAnsible(task_vars=task_vars, action_module=self)

        uid = self._task.args.get("uids")
        title = self._task.args.get("titles")

        if uid is None and title is None:
            raise AnsibleError("The uid and title are both blank. keeper_cache_records requires at "
                               "least on to be set. This will not cache your entire Keeper vault.")

        results = {
            "cache": keeper.get_records(uids=uid, titles=title, encrypt=True)
        }

        keeper.add_secret_values_to_results(results)

        return results
