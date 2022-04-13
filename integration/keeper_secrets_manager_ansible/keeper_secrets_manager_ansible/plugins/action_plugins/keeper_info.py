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
from ansible.errors import AnsibleError
from keeper_secrets_manager_ansible import KeeperAnsible
from keeper_secrets_manager_helper.record_type import RecordType
from keeper_secrets_manager_helper.field_type import FieldType
from ansible.utils.display import Display
import importlib_metadata
import json

display = Display()

DOCUMENTATION = r'''
---
module: keeper_info

short_description: Get information about the Keeper plugins.

version_added: "1.1.2"

description:
    - Get information about the Keeper plugins.
author:
    - John Walstra
'''

EXAMPLES = r'''
- name: Get Keeper info
  keeper_info:
'''

RETURN = r'''
value:
  description: List of various Keeper related information.
  returned: success
  sample: |
    { 
        "record_type_list": ["record_type_1", "record_type_N" ],
        "field_type_list": ["field_type_1", "field_type_N" ],
    }
'''


class ActionModule(ActionBase):


    @staticmethod
    def get_versions():

        # Unit test do not know their version
        versions = {
            "keeper-secrets-manager-core": "Unknown",
            "keeper-secrets-manager-ansible": "Unknown",
            "keeper-secrets-manager-helper": "Unknown"
        }

        for module in versions:
            try:
                versions[module] = importlib_metadata.version(module)
            except importlib_metadata.PackageNotFoundError:
                pass

        return versions

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        KeeperAnsible(task_vars=task_vars)

        # If there are custom record type, load them
        keeper_record_types = task_vars.get("keeper_record_types")
        if keeper_record_types is not None:
            if isinstance(keeper_record_types, list) is False:
                raise AnsibleError("The Keeper record types is not a list.")
            for keeper_record_type in keeper_record_types:
                if isinstance(keeper_record_type, str) is True:
                    keeper_record_type = json.loads(keeper_record_type)
                RecordType.load_commander_record_types(keeper_record_type)

        result = {
            "versions": ActionModule.get_versions(),
            "record_type_list": list(RecordType.get_record_type_list()),
            "field_type_list": list(FieldType.get_field_type_list())
        }

        return result
