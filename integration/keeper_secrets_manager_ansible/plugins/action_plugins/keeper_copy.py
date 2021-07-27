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

from ansible.plugins.action.copy import ActionModule as ActionBase
from ansible.errors import AnsibleError
from keeper_secrets_manager_ansible import KeeperAnsible


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):

        if task_vars is None:
            task_vars = {}

        keeper = KeeperAnsible(task_vars=task_vars)

        uid = self._task.args.pop("uid", None)
        if uid is None:
            raise AnsibleError("The uid is blank. keeper_copy requires this value to be set.")

        # Try to get either the field, custom_field, or file name.
        field_type_enum, field_key = keeper.get_field_type_enum_and_key(args=self._task.args)

        # Make sure 'src' is not set. We are going to use 'content' instead.
        self._task.args.pop("src", None)

        # The built-in copy module won't like these, remove them.
        self._task.args.pop("field", None)
        self._task.args.pop("file", None)
        self._task.args.pop("custom_field", None)

        value = keeper.get_value(uid, field_type=field_type_enum, key=field_key)

        # Add the file content
        self._task.args["content"] = value

        # Call Ansible built-in copy
        result = super(ActionModule, self).run(tmp, task_vars)

        # Attempt to add back the keeper values for debug purposes.
        if type(result) is dict:
            invocation = result.get("invocation")
            if invocation is not None:
                module_args = invocation.get("module_args")
                if module_args is not None:
                    module_args['uid'] = uid

                    # Remove the src and content, if they exists, since they are not part of this
                    # plugin.
                    module_args.pop('src', None)
                    module_args.pop('content', None)

        return result
