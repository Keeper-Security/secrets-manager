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

from keeper_secrets_manager_ansible import KeeperAnsible
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

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
    - 
    - See https://docs.keeper.io/secrets-manager/secrets-manager/about/keeper-notation for more information/
    type: str
    required: no
    version_added: '1.0.1'  
'''

EXAMPLES = r'''
- name: Get login name
  debug:
    msg: "{{ lookup('keeper', uid='XXX', field='login') }}
- name: Get all phone numbers
  debug:
    msg: "{{ lookup('keeper', uid='XXX', custom_field='phone', allow_array='True') }}
- name: Get all phone numbers via notation
  debug:
    msg: "{{ lookup('keeper', notation='XXX/custom_field/phone') }}
'''

RETURN = '''
  _list:
    description: list of list of lines or content of record field(s)
    type: list
    elements: str
'''


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):

        keeper = KeeperAnsible(task_vars=variables)

        if kwargs.get("notation") is not None:
            value = keeper.get_value_via_notation(kwargs.get("notation"))
        else:
            uid = kwargs.get("uid")
            if uid is None:
                raise AnsibleError("The uid is blank. keeper_get requires this value to be set.")

            # Try to get either the field, custom_field, or file name.
            field_type_enum, field_key = keeper.get_field_type_enum_and_key(args=kwargs)

            allow_array = kwargs.get("allow_array", False)
            value = keeper.get_value(uid, field_type=field_type_enum, key=field_key, allow_array=allow_array)

        if type(value) is not list:
            value = [value]

        return value
