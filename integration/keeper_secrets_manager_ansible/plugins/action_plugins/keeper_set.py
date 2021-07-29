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


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        keeper = KeeperAnsible(task_vars=task_vars)

        uid = self._task.args.get("uid", None)
        if uid is None:
            raise AnsibleError("The uid is blank. keeper_set requires this value to be set.")

        # Try to get either the field, custom_field, or file name.
        field_type_enum, field_key = keeper.get_field_type_enum_and_key(args=self._task.args)

        value = self._task.args.get("value")

        keeper.set_value(uid, field_type=field_type_enum, key=field_key, value=value)

        return {}
