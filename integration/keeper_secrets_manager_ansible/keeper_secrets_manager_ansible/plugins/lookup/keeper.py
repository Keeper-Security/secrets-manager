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

from keeper_secrets_manager_ansible import KeeperAnsible
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

DOCUMENTATION = r'''
---
name: keeper

short_description: Get value(s) from the Keeper Vault

version_added: "1.0.0"

description:
    - Copy a value from the Keeper Vault into a variable.
    - If value is not a literal value, the structure will be retrieved.
author:
    - John Walstra
notes:
  - In check mode, the lookup loads the Keeper configuration into memory, does not refresh the DR cache, and
    fails with a configuration that has only a one-time token.
  - The lookup sees the --check option on every ansible-core version. It sees a play or task check_mode
    keyword only on ansible-core 2.19 and later.
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
  allow_array:
    description:
    - Allow array of values instead of taking the first value.
    - If enabled, the value will be returned all the values for a field.
    - This does not work with notation since notation defines if an array is returned.
    type: bool
    default: no
    required: no
    version_added: '1.0.1'
  notation:
    description:
    - The Keeper notation to access record that contains the value.
    - Use notation when you want a specific value.
    - See https://docs.keeper.io/secrets-manager/secrets-manager/about/keeper-notation for more information/
    type: str
    required: no
    version_added: '1.0.1'  
'''

EXAMPLES = r'''
- name: Get login name
  debug:
    msg: "{{ lookup('keeper', uid='XXX', field='login') }}"
- name: Get all phone numbers
  debug:
    msg: "{{ lookup('keeper', uid='XXX', custom_field='phone', allow_array='True') }}"
- name: Get all phone numbers via notation
  debug:
    msg: "{{ lookup('keeper', notation='XXX/custom_field/phone') }}"
'''

RETURN = '''
  _list:
    description: list of list of lines or content of record field(s)
    type: list
    elements: str
'''

display = Display()


class LookupModule(LookupBase):

    @staticmethod
    def _check_mode(variables):
        # A lookup has no task. ansible-core 2.19 and later have the current task in a private API, which also
        # knows a play or task check_mode keyword. Before 2.19, or when the lookup runs outside a task (for
        # example in a task name), only ansible_check_mode is available, and it shows only the --check option.
        try:
            from ansible._internal._task import TaskContext
            return bool(TaskContext.current().task.check_mode)
        except Exception:
            return bool((variables or {}).get("ansible_check_mode", False))

    def run(self, terms, variables=None, **kwargs):

        keeper = KeeperAnsible(task_vars=variables, task_attributes=kwargs, action_module=self,
                               check_mode=self._check_mode(variables))

        cache = kwargs.get("cache")

        if kwargs.get("notation") is not None:
            if cache is not None:
                display.warning("cache and notation both set. currently notation cannot be used with the cache.")
            value = keeper.get_value_via_notation(kwargs.get("notation"))
        else:
            uid = kwargs.get("uid")
            title = kwargs.pop("title", None)
            if uid is None and title is None:
                raise AnsibleError("The uid and title are blank. The keeper lookup requires one to be set.")
            if uid is not None and title is not None:
                raise AnsibleError("The uid and title are both set. The keeper lookup requires one to be set, "
                                   "but not both.")

            # Try to get either the field, custom_field, or file name.
            field_type_enum, field_key = keeper.get_field_type_enum_and_key(args=kwargs)

            allow_array = kwargs.get("allow_array", False)
            array_index = kwargs.get("array_index", None)
            value_key = kwargs.get("value_key", None)
            value = keeper.get_value(uid=uid, title=title, field_type=field_type_enum, key=field_key,
                                     allow_array=allow_array, array_index=array_index, value_key=value_key,
                                     cache=cache)

        if type(value) is not list:
            value = [value]

        return value
