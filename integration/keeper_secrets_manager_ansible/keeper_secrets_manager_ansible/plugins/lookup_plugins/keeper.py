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


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):

        keeper = KeeperAnsible(task_vars=variables)

        uid = kwargs.get("uid", None)
        if uid is None:
            raise AnsibleError("The uid is blank. keeper lookup requires this value to be set.")

        # Try to get either the field, custom_field, or file name.
        field_type_enum, field_key = keeper.get_field_type_enum_and_key(args=kwargs)

        value = keeper.get_value(uid, field_type=field_type_enum, key=field_key)

        return [value]
