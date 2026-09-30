# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

DOCUMENTATION = r'''
---
module: keeper_update_folder

short_description: Rename a Keeper folder

version_added: "1.5.0"

description:
    - Rename an existing folder or subfolder that is shared to your Keeper Secrets Manager application.
    - Idempotent. If the folder already has the new name, the task reports changed as false, and sends no
      update to the server. The names are compared exactly, and the comparison is case-sensitive.
    - A new name with a space, a tab, or a newline at the start or the end fails the task, because a later
      lookup of the name would not find the folder.
    - This module can only change the name of a folder. It cannot move a folder to a different parent
      folder, because Keeper Secrets Manager has no command that moves a folder.
    - Keeper allows two folders with the same name in the same parent folder. If the parent folder already
      has a folder with the new name, the module renames the folder and shows a warning.
    - In check mode, the module does all of its checks, but it does not rename the folder.
    - The module checks its options. An unknown or misspelled option, an option set to null, or a value
      of the wrong type fails the task. There is one exception. An option that a module_defaults entry
      for an action group of this collection sets, and that this module does not have, is ignored.
    - The task result and the error messages show folder names and UIDs, also when the values come from
      Ansible Vault. To keep them out of the output and the logs, set no_log to true on the task.
author:
    - Keeper Security
options:
  folder_uid:
    description:
    - The UID of the folder to rename.
    - To get the UID of a folder from its name, use keeper_get_folder.
    type: str
    required: yes
  new_folder_name:
    description:
    - The new name of the folder.
    type: str
    required: yes
'''

EXAMPLES = r'''
- name: Rename a folder
  keeper_update_folder:
    folder_uid: XXX
    new_folder_name: Production Databases
  register: renamed_folder

- name: Show the old and the new name
  debug:
    msg: "Renamed {{ renamed_folder.previous_folder_name }} to {{ renamed_folder.folder_name }}"
'''

RETURN = r'''
folder_uid:
  description: The UID of the folder.
  returned: success
  type: str
  sample: XXXX
folder_name:
  description: The name of the folder after the task. In check mode, the name that a real run gives the folder.
  returned: success
  type: str
  sample: Production Databases
previous_folder_name:
  description: The name of the folder before the task. The same as folder_name if the name did not change.
  returned: success
  type: str
  sample: Staging Databases
'''
