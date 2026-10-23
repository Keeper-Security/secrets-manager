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
from keeper_secrets_manager_ansible import KeeperAnsible, _folder_failure, _private_folder_diagnostics, \
    _safe_diagnostic_error
from ansible.utils.display import Display

display = Display()

DOCUMENTATION = r'''
---
module: keeper_create_folder

short_description: Create a new Keeper folder

version_added: "1.5.0"

description:
    - Create a new folder in your vault, either directly in a shared folder or nested
      inside an existing subfolder of that shared folder.
    - Idempotent - if a folder with folder_name already exists directly under the target
      parent (shared_folder_uid, or subfolder_uid when given), that folder's UID is
      returned and no new folder is created.
author:
    - John Walstra (@jwalstra-keeper)
attributes:
  check_mode:
    support: full
    description: Looks for an existing folder and predicts creation without changing the vault.
notes:
  - Check mode requires an initialized Keeper configuration.
  - In check mode, folder_uid is null for a new folder and is the existing UID for a matching folder.
  - An empty or null subfolder_uid means no subfolder. A later task that runs for real with a null
    folder_uid from check mode creates its folder in the shared folder.
options:
  shared_folder_uid:
    description:
    - The UID of the top-level shared folder in your Keeper application.
    - Must be a shared folder UID, not a subfolder UID.
    type: str
    required: yes
  subfolder_uid:
    description:
    - The UID of an existing subfolder, nested under shared_folder_uid, to create the
      new folder in.
    - The subfolder must already exist and must live under the shared folder given
      in shared_folder_uid. It can be nested at any depth under the shared folder.
    - If omitted, the new folder is created directly in the shared folder.
    type: str
    required: no
  folder_name:
    description:
    - The name to give the new folder.
    - Must be a nonblank string without leading or trailing whitespace.
    - Quote numeric or boolean-looking names so YAML reads them as strings.
    - Use YAML strip chomping (|- or >-) to avoid a block scalar's trailing newline.
    type: str
    required: yes
'''

EXAMPLES = r'''
- name: Create a new folder directly in a shared folder
  keeper_create_folder:
    shared_folder_uid: XXX
    folder_name: My New Folder
  register: my_new_folder

- name: Create a new folder nested inside an existing subfolder
  keeper_create_folder:
    shared_folder_uid: XXX
    subfolder_uid: YYY
    folder_name: My New Nested Folder
  register: my_new_folder
'''

RETURN = r'''
changed:
  description: Whether a folder was created, or would be created in check mode.
  returned: success
  type: bool
  sample: true
folder_uid:
  description: The new or existing folder UID. Null for a new folder in check mode.
  returned: success
  type: str
  sample: XXXX
'''


class ActionModule(ActionBase):

    ARGUMENT_SPEC = dict(
        shared_folder_uid=dict(type="str", required=True),
        subfolder_uid=dict(type="str"),
        folder_name=dict(type="str", required=True),
    )

    @_private_folder_diagnostics
    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        try:
            args = dict(self._task.args)
            # A null subfolder from a preceding check-mode task means the shared folder.
            if args.get("subfolder_uid") is None:
                args.pop("subfolder_uid", None)
            args = KeeperAnsible.validate_task_args(
                "keeper_create_folder", args, self.ARGUMENT_SPEC,
                ignore=KeeperAnsible.group_default_options(self._task, self._templar))
            folder_name = str(args["folder_name"])
            if not folder_name.strip():
                raise _safe_diagnostic_error(
                    ValueError, "The folder_name is blank. keeper_create_folder requires this value to be set.")
            if folder_name != folder_name.strip():
                raise ValueError(
                    "The folder_name {!r} has leading or trailing whitespace. Remove it. In YAML, a block scalar "
                    "(| or >) keeps the newline at its end.".format(folder_name))
        except Exception as err:
            return _folder_failure(err)

        keeper = KeeperAnsible(task_vars=task_vars, action_module=self)

        try:
            folder_uid, changed = keeper.create_folder(
                folder_name,
                shared_folder_uid=args.get("shared_folder_uid"),
                subfolder_uid=args.get("subfolder_uid"),
                check_mode=bool(self._task.check_mode)
            )
        except Exception as err:
            raise AnsibleError("Could not create folder: {}".format(err))

        result = {
            "changed": changed,
            "folder_uid": folder_uid
        }

        return result
