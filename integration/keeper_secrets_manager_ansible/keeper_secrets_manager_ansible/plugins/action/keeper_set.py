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
from ansible.errors import AnsibleError
from keeper_secrets_manager_ansible import KeeperAnsible

DOCUMENTATION = r'''
---
module: keeper_set

short_description: Set value in an existing the record

version_added: "1.0.0"

description:
    - Allows updating a record in an existing record in the Keeper Vault
    - Currently cannot add files to the record.
author:
    - John Walstra
attributes:
  check_mode:
    support: full
    description: Validates the record and field update without saving the record.
notes:
  - Check mode requires an initialized Keeper configuration.
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
    - The cache registered by keeper_get_records_cache
    - Accepted for compatibility. keeper_set reads the record from the vault, not from the cache, so an outdated
      cache cannot hide a needed save or bring back old values of other fields.
    - Using keeper_set will not update the cache. Use the keeper_get_records_cache action again to get a new cache.
    type: str
    required: no
    version_added: '1.2.0'  
  field:
    description:
    - The label, or type, of the standard field in record that contains the value.
    - If the value has a complex value, use notation to get the specific value from the complex value.
    type: str
    required: no
  custom_field:
    description:
    - The label, or type, of the user added customer field in record that contains the value.
    - If the value has a complex value, use notation to get the specific value from the complex value.
    type: str
    required: no
  file:
    description:
    - The file name of the file that contains the value.
    type: str
    required: no
  notes:
    description:
    - Set to update the notes field in the record.
    - The notes field contains text notes attached to the record.
    type: str
    required: no
    version_added: '1.3.0'
  value:
    description:
    - The new value of the field. A field with more than one value takes a list.
    type: str
    required: no
    version_added: '1.0.1'  
'''

RETURN = r'''
changed:
  description: Whether the record was saved, or would be saved in check mode. False when the record
    already has the value.
  returned: success
  type: bool
  sample: true
updated:
  description: Whether the record was saved. False in check mode, and when the record already has the
    value.
  returned: success
  type: bool
  sample: True
  version_added: '1.0.1'  
'''


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
            raise AnsibleError("The uid and title are blank. keeper_set requires one to be set.")
        if uid is not None and title is not None:
            raise AnsibleError("The uid and title are both set. keeper_set requires one to be set, but not both.")

        # Try to get either the field, custom_field, or file name.
        field_type_enum, field_key = keeper.get_field_type_enum_and_key(args=self._task.args)

        value = self._task.args.get("value")
        check_mode = bool(self._task.check_mode)

        try:
            changed = keeper.set_value(uid=uid, title=title, field_type=field_type_enum, key=field_key, value=value,
                                       cache=cache, check_mode=check_mode)
        except Exception as err:
            raise AnsibleError("Cannot update record: {}".format(str(err)))

        return {
            "changed": changed,
            "updated": changed and not check_mode
        }
