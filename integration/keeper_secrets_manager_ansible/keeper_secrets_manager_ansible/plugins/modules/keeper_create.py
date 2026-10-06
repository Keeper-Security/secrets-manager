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
module: keeper_create

short_description: Create a new Keeper record

version_added: "1.1.2"

description:
    - Create a new keeper record in your vault.
author:
    - John Walstra
attributes:
  check_mode:
    support: full
    description: Validates the record and the shared folder key without creating a record. Server
      permissions are checked only in a real run.
notes:
  - Check mode requires an initialized Keeper configuration.
  - The record_uid is null in check mode because no record is created.
  - An empty or null subfolder_uid means no subfolder. In check mode, keeper_create_folder returns a null
    folder_uid for a new folder. A later task that runs for real with that UID creates the record in the
    shared folder.
options:
  shared_folder_uid:
    description:
    - The UID of the top-level shared folder in your Keeper application.
    - To create in a subfolder, also provide C(subfolder_uid).
    type: str
    required: yes
  subfolder_uid:
    description:
    - The UID of an existing subfolder, nested under shared_folder_uid, to create the
      record in.
    - The subfolder must already exist and must be accessible to the KSM application.
    - If omitted, the record is created directly in the shared folder.
    type: str
    required: no
    version_added: "1.5.0"
  record_type:
    description:
    - The type if record to create.
    type: str
    required: yes
  generate_password:
    description:
    - Generate any passwords that has not been set.
    type: bool
    required: no
  password_complexity:
    description:
    - Control the content of the password.
    type: dict
    required: no
    suboptions:
      length:
        description: 
          - Length of the password. Defaults to 64.
          - The length will be distributes to the allow_* params.
          - For example, the length of 64 will generate 21 lowercase, 21 uppercase, 21 digits, and 21 symbols.
        type: int
        required: no
      allow_lowercase:
        description: 
          - Allow lowercase letters. Defaults to True.
        type: bool
        required: no
      allow_uppercase:
        description: 
          - Allow uppercase letters. Defaults to True.
        type: bool
        required: no
      allow_digits:
        description: 
          - Allow digits. Defaults to True.
        type: bool
        required: no
      allow_symbols:
        description: 
          - Allow symbols. Defaults to True.
          - The symbol set is \"!@#$%()+;<>=?[]{}^.,
        type: bool
        required: no
      filter_characters:
        description: 
          - Character not allowed in the password.
          - Application specific password may not allow certain characters.
        type: list
        required: no
  title:
    description:
    - The title of the record.
    type: str
    required: yes
  notes:
    description:
    - Attach a note to the record.
    - C(note) (singular) is accepted as a deprecated alias.
    type: str
    required: no
    aliases: [ note ]
  version:
    description:
    - The record schema version to use.
    - Defaults to v3 (recommended).
    type: str
    required: no
    default: v3
    choices:
      - v2
      - v3
    version_added: '1.1.2'
  fields:
    description:
    - The label, or type, of the standard field in record that contains the value.
    - If the value has a complex value, use notation to get the specific value from the complex value.
    type: dict
    required: no
    suboptions:
      value:
         description: Value
         required: yes 
      type:
        description: Field type
        type: str
        required: yes
        choices:
          - text
          - url
          - pinCode
          - multiline
          - fileRef
          - email
          - phone
          - name
          - address
          - addressRef
          - accountNumber
          - login
          - secret
          - password
          - securityQuestion
          - otp
          - oneTimeCode
          - cardRef
          - paymentCard
          - date
          - birthDate
          - expirationDate
          - bankAccount
          - keyPair
          - host
          - licenseNumber
          - note
  custom_fields:
    description:
    - The label, or type, of the user added customer field in record that contains the value.
    - If the value has a complex value, use notation to get the specific value from the complex value.
    type: str
    required: no
    suboptions:
      value:
        description: Value
        required: yes
      label:
        description: Field label
        type: str
        required: no        
      type:
        description: Field type
        type: str
        required: yes
        choices:
          - text
          - url
          - pinCode
          - multiline
          - fileRef
          - email
          - phone
          - name
          - address
          - addressRef
          - accountNumber
          - login
          - secret
          - password
          - securityQuestion
          - otp
          - oneTimeCode
          - cardRef
          - paymentCard
          - date
          - birthDate
          - expirationDate
          - bankAccount
          - keyPair
          - host
          - licenseNumber
          - note
'''

EXAMPLES = r'''
- name: Create a record in a shared folder
  keeper_create:
    shared_folder_uid: SHARED_FOLDER_UID
    record_type: login
    title: My Title
    notes: This record was created from Ansible
    generate_password: True
    fields:
      - type: login
        value: john.doe@nowhere.com
      - type: url
        value: https://nowhere.com/login
    custom_fields:
      - type: text
        label: Custom Field
        value: This is a value is a custom field.
  register: my_new_record

- name: Create a record in a subfolder
  keeper_create:
    shared_folder_uid: SHARED_FOLDER_UID
    subfolder_uid: SUBFOLDER_UID
    record_type: login
    title: My Subfolder Record
    generate_password: True
    fields:
      - type: login
        value: jane.doe@nowhere.com
  register: my_subfolder_record
'''

RETURN = r'''
changed:
  description: Whether a record was created, or would be created in check mode.
  returned: success
  type: bool
  sample: true
record_uid:
  description: The new record UID. Null in check mode.
  returned: success
  type: str
  sample: XXXX
'''
