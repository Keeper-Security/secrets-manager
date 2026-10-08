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
module: keeper_get_folder

short_description: Look up a Keeper folder by name or path, and get its UID

version_added: "1.5.0"

description:
    - Look up an existing folder that is shared to your Keeper Secrets Manager application. Get its UID,
      name, parent UID, and shared folder UID.
    - Use the folder UID from this module with keeper_create, keeper_create_folder, keeper_update_folder,
      or keeper_delete_folder. Then you do not need to copy the UID from the Vault user interface.
    - The lookup starts at subfolder_uid if it is set, else at shared_folder_uid. If neither is set, the
      lookup starts at the top level. There, folder_name, or the first name in folder_path, is the name of
      a shared folder.
    - Folder names must match exactly. The match is case-sensitive. If no folder matches, or if more than
      one folder matches, the task fails. The task never gives an empty result.
    - With no folder_name and no folder_path, the module gets the start folder itself. That is also the
      result when a template leaves the name out, for example with default(omit). Keep this in mind before
      you give the result to keeper_update_folder or keeper_delete_folder.
    - This module does not change the vault. It runs in check mode with an initialized Keeper
      configuration.
    - The module checks its options. An unknown or misspelled option, an option set to null, or a value
      of the wrong type fails the task. There is one exception. An option that a module_defaults entry
      for an action group of this collection sets, and that this module does not have, is ignored.
    - The task result and the error messages show folder names and UIDs, also when the values come from
      Ansible Vault. To keep them out of the output and the logs, set no_log to true on the task.
author:
    - Keeper Security
options:
  shared_folder_uid:
    description:
    - The UID of a top-level shared folder. The lookup starts at this folder.
    - Must be a shared folder UID, not a subfolder UID. For a subfolder, use subfolder_uid.
    - If folder_name and folder_path are not set, the module gets the shared folder itself.
    type: str
    required: no
  subfolder_uid:
    description:
    - The UID of an existing subfolder. The lookup starts at this folder, not at the shared folder.
    - If shared_folder_uid is also set, the subfolder must be inside that shared folder, at any depth.
    - If folder_name and folder_path are not set, the module gets the subfolder itself.
    type: str
    required: no
  folder_name:
    description:
    - The exact name of a folder directly inside the start folder.
    - If there is no start folder, the exact name of a shared folder.
    - Mutually exclusive with folder_path.
    type: str
    required: no
  folder_path:
    description:
    - A path of folder names. The lookup goes down one folder for each name, from the start folder.
      For example, C(Databases/Production).
    - If there is no start folder, the first name is the name of a shared folder. For example,
      C(Infrastructure/Databases/Production).
    - A string is split on C(/). If a folder name contains C(/), give the path as a list of names.
    - An empty name is an error. So a leading, trailing, or double C(/) is an error.
    - Mutually exclusive with folder_name.
    type: raw
    required: no
  include_subfolders:
    description:
    - If true, also get every folder below the found folder, at all depths, in subfolders.
    type: bool
    default: no
    required: no
'''

EXAMPLES = r'''
- name: Get the UID of a subfolder in a shared folder
  keeper_get_folder:
    shared_folder_uid: XXX
    folder_name: Databases
  register: databases_folder

- name: Create a folder in that subfolder
  keeper_create_folder:
    shared_folder_uid: XXX
    subfolder_uid: "{{ databases_folder.folder_uid }}"
    folder_name: Production

- name: Get a nested folder by its path from a shared folder
  keeper_get_folder:
    shared_folder_uid: XXX
    folder_path: Databases/Production
  register: production_folder

- name: Get a nested folder by its path from the top level, with no UID
  keeper_get_folder:
    folder_path: Infrastructure/Databases/Production
  register: production_folder

- name: Use a list of names when a folder name contains "/"
  keeper_get_folder:
    shared_folder_uid: XXX
    folder_path:
      - Databases
      - Prod/EU
  register: prod_eu_folder

- name: Get the shared folder itself, and every folder below it
  keeper_get_folder:
    shared_folder_uid: XXX
    include_subfolders: yes
  register: shared_folder_tree
'''

RETURN = r'''
folder_uid:
  description: The UID of the folder that the lookup found.
  returned: success
  type: str
  sample: XXXX
folder_name:
  description: The name of the folder that the lookup found.
  returned: success
  type: str
  sample: Production
parent_uid:
  description:
  - The UID of the parent folder.
  - An empty string for a shared folder, because a shared folder has no parent.
  returned: success
  type: str
  sample: YYYY
shared_folder_uid:
  description:
  - The UID of the shared folder that contains the folder. For a shared folder, its own UID.
  - Null only if the folder list from the server does not include that shared folder, or if the
    parent folders of the folder form a cycle.
  returned: success
  type: str
  sample: ZZZZ
subfolders:
  description:
  - Every folder below the found folder, at all depths. A parent folder comes before its children.
  - Each item has folder_uid, folder_name, and parent_uid.
  returned: when include_subfolders is true
  type: list
  elements: dict
  sample:
    - folder_uid: AAAA
      folder_name: EU
      parent_uid: XXXX
    - folder_uid: BBBB
      folder_name: Frankfurt
      parent_uid: AAAA
'''
