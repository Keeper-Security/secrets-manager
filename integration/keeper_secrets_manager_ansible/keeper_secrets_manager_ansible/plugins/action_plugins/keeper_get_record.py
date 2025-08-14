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
module: keeper_get_record

short_description: Get the entire record as a dictionary.

version_added: "1.2.2"

description:
    - Copy record's fields, as a dictionary, into a variable.
    - Standard and custom fields will be included in the dictionary.
    - If a label exists for the field, the label will be used for the dictionary key.
    - If a label is not available, the field type will be used for the dictionary key.
    - If a duplicate label/type exists, the key will be appended with a number.
    - Value in the dictionary will be arrays since field can have multiple values.
    - Label keys will be normalized.
    - Only alphanumeric values and underscores will be used in the key.
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
  allow:
    description:
    - Only allow this list of keys to be in dictionary.
    - This list must match the keys in the dictionary returned by this action.
    type: list
    required: no
  cache:
    description:
    - The cache registered by keeper_get_records_cache
    type: str
    required: no
'''

EXAMPLES = r'''
- name: Get entire record
  keeper_get_record:
    uid: XXX
  register: my_record

'''

RETURN = r'''
value:
  description: The entire record as a dictionary.
  returned: success
  sample: |
    {
      "record": {
        "login": [
           "MY LOGIN"
        ],
        "password": [
           "XXXX"
        ],
        "phone": [
          {
            "number": "15551234",
            "type": "Home"
          },
          {
            "number": "15557890",
            "type": "Work"
          }
        ],
        "Custom_Field": [
            "CUSTOM VALUE"
        ]
      }
    }   
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
            raise AnsibleError("The uid and title are blank. keeper_get_record requires one to be set.")
        if uid is not None and title is not None:
            raise AnsibleError("The uid and title are both set. keeper_get_record requires one to be set, "
                               "but not both.")

        allow = self._task.args.get("allow", None)

        record_dict = keeper.get_dict(uid=uid, title=title, cache=cache, allow=allow)

        result = {
            "record": record_dict
        }

        keeper.add_secret_values_to_results(result)

        return result
