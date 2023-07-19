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
module: keeper_get

short_description: Get value(s) from the Keeper Vault

version_added: "1.0.0"

description:
    - Copy a value from the Keeper Vault into a variable.
    - If value is not a literal value, the structure will be retrieved.
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
    - The cache registered by keeper_get_records_cache
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
  allow_array:
    description:
    - Allow array of values instead of taking the first value.
    - If enabled, the value will be returned in array even if single value.
    - This does not work with notation since notation defines if an array is returned.
    - Setting this value 'yes' will cause array_index and value_key to be ignored.
    type: bool
    default: no
    required: no 
  array_index:
    description:
    - Used to retrieve items from an array value.
    - This is used for fields that have multiple values in an array.
    - Can be used with value_key.
    default: 0
    type: int
    required: no
    version_added: '1.2.0'
  value_key:
    description:
    - Used to retrieve items from an object value.
    - This is used for fields that have complex values.
    - The value is the name of the key in an object.
    type: str
    required: no
    version_added: '1.2.0'
  notation:
    description:
    - The Keeper notation to access record that contains the value.
    - Use notation when you want a specific value.
    - The 'cache' setting currently does not work with notation.
    - 
    - See https://docs.keeper.io/secrets-manager/secrets-manager/about/keeper-notation for more information/
    type: str
    required: no
    version_added: '1.0.1'  
'''

EXAMPLES = r'''
- name: Get login name
  keeper_copy:
    uid: XXX
    field: login
  register: my_login_value
- name: Get login name via notation
  keeper_copy:
    notation: XXX/field/login
  register: my_login_value
- name: Get custom field
  keeper_copy:
    uid: XXX
    custom_field: Custom Label
  register: my_custom_value
'''

RETURN = r'''
value:
  description: The secret value
  returned: success
  sample: |
    [
      {
        "ext": "6666",
        "number": "(555) 353-8686",
        "type": "Work"
      },
      {
        "ext": "5555",
        "number": "111-2223333",
        "region": "AD",
        "type": "Mobile"
      }
    ]      
'''

display = Display()


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        keeper = KeeperAnsible(task_vars=task_vars, action_module=self)

        cache = self._task.args.get("cache")

        if self._task.args.get("notation") is not None:
            if cache is not None:
                display.warning("cache and notation both set. currently notation cannot be used with the cache.")
            value = keeper.get_value_via_notation(self._task.args.get("notation"))
        else:
            uid = self._task.args.get("uid")
            title = self._task.args.pop("title", None)
            if uid is None and title is None:
                raise AnsibleError("The uid and title are blank. keeper_get requires one to be set.")
            if uid is not None and title is not None:
                raise AnsibleError("The uid and title are both set. keeper_get requires one to be set, but not both.")

            # Try to get either the field, custom_field, or file name.
            field_type_enum, field_key = keeper.get_field_type_enum_and_key(args=self._task.args)

            allow_array = self._task.args.get("allow_array", False)
            array_index = self._task.args.get("array_index", None)
            value_key = self._task.args.get("value_key", None)

            value = keeper.get_value(uid=uid, title=title, field_type=field_type_enum, key=field_key,
                                     allow_array=allow_array, array_index=array_index, value_key=value_key, cache=cache)

        keeper.stash_secret_value(value)

        result = {
            "value": value
        }

        keeper.add_secret_values_to_results(result)

        return result
