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

DOCUMENTATION = r'''
---
module: keeper_create_folder

short_description: Create a new Keeper folder

version_added: "1.4.1"

description:
    - Create a new folder in your vault, either directly in a shared folder or nested
      inside an existing subfolder of that shared folder.
    - Idempotent - if a folder with folder_name already exists directly under the target
      parent (shared_folder_uid, or subfolder_uid when given), that folder's UID is
      returned and no new folder is created.
author:
    - RABOUIN Geoffroy
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
value:
  description: The new (or already-existing) folder uid.
  returned: success
  sample: |
    { "folder_uid": "XXXX" }
'''
