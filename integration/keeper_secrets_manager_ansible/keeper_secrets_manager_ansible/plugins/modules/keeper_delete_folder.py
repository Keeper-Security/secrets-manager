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
module: keeper_delete_folder

short_description: Delete a Keeper folder

version_added: "1.5.0"

description:
    - Delete an existing folder or subfolder that is shared to your Keeper Secrets Manager application.
    - Idempotent. If the folder does not exist, or if it is not shared to the application, the task reports
      changed as false and does not fail. So a second run after a delete does not fail.
    - By default, the module deletes only an empty folder. If the folder contains records or subfolders, the
      task fails and deletes nothing, unless force_deletion is true.
    - The module finds the folder in the folder list of the application, the same list that keeper_get_folder
      uses. A folder that is not in that list is treated as a folder that does not exist.
    - In check mode, the module does all of its checks, but it does not delete the folder.
    - The module checks its options. An unknown or misspelled option, an option set to null, or a value
      of the wrong type fails the task. There is one exception. An option that a module_defaults entry
      for an action group of this collection sets, and that this module does not have, is ignored.
    - The task result and the error messages show folder names and UIDs, also when the values come from
      Ansible Vault. To keep them out of the output and the logs, set no_log to true on the task.
attributes:
  check_mode:
    support: full
    description: Does all of its checks, but does not delete the folder.
notes:
  - Check mode requires an initialized Keeper configuration.
author:
    - Keeper Security
options:
  folder_uid:
    description:
    - The UID of the folder to delete.
    - To get the UID of a folder from its name, use keeper_get_folder.
    type: str
    required: yes
  force_deletion:
    description:
    - If true, delete the folder even if it contains records or subfolders. The records and the subfolders
      are deleted with the folder.
    - Ansible cannot undo this delete.
    - The name is not force, because keeper_copy has a force option with a different meaning, and a
      module_defaults entry for the action group of this collection gives its options to every module in it.
    - Do not set force_deletion in module_defaults. It would force every keeper_delete_folder task that the
      defaults apply to.
    type: bool
    default: no
    required: no
'''

EXAMPLES = r'''
- name: Delete an empty folder
  keeper_delete_folder:
    folder_uid: XXX

- name: Delete a folder and everything in it
  keeper_delete_folder:
    folder_uid: XXX
    force_deletion: yes

- name: Delete more than one folder
  keeper_delete_folder:
    folder_uid: "{{ item }}"
  loop:
    - XXX
    - YYY

# keeper_get_folder fails if the folder does not exist, for example on a second run after the delete.
# The failed_when on the lookup keeps the play idempotent: it ignores only the "No folder named" failure,
# and then the delete is skipped. Any other failure, such as two folders with the same name or a network
# error, still fails the task. Do not leave out folder_name here (for example with default(omit)): with
# no name, the lookup returns the shared folder itself.
- name: Find a folder by name
  keeper_get_folder:
    shared_folder_uid: XXX
    folder_name: Temporary
  register: temporary_folder
  failed_when:
    - temporary_folder is failed
    - "'No folder named' not in temporary_folder.msg"

- name: Delete the folder, if the lookup found it
  keeper_delete_folder:
    folder_uid: "{{ temporary_folder.folder_uid }}"
  when: temporary_folder.folder_uid is defined
'''

RETURN = r'''
folder_uid:
  description: The UID of the folder, from the folder_uid option.
  returned: success
  type: str
  sample: XXXX
folder_name:
  description:
  - The name of the deleted folder.
  - Null if the folder was not found.
  returned: success
  type: str
  sample: Temporary
msg:
  description: A message that says that the folder was not found, and that nothing was deleted.
  returned: when the folder was not found
  type: str
  sample: The folder XXXX was not found, or it is not shared to this KSM application. Nothing was deleted.
'''
