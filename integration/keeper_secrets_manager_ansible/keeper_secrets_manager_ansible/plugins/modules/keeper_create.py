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
options:
  shared_folder_uid:
    description:
    - The UID of shared folder in your Keeper application.
    type: str
    required: yes
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
  note:
    description:
    - Attach a note to the record.
    type: str
    required: no
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
- name: Create a new record
  keeper_create:
    share_folder_uid: XXX
    record_type: login
    title: My Title
    note: This record was created from Ansible
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
'''

RETURN = r'''
value:
  description: The new record uid.
  returned: success
  sample: |
    { "record_uid": "XXXX" }
'''