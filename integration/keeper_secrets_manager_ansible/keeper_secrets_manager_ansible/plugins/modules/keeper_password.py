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
module: keeper_password

short_description: Generate a password

version_added: "1.1.2"

description:
    - Generate a password.
    - Set the complexity and characters to exclude from the password.
author:
    - John Walstra
options:
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
'''

EXAMPLES = r'''
- name: Generate a long password
  keeper_password:
    length: 128
  register: long_password
- name: Show long password
  debug:
    msg: "My long password {{ long_password.password }}"
- name: Generate an all number password, without any 4s
  keeper_password:
    allow_lowercase: False
    allow_uppercase: False
    allow_symbols: False
    filter_characters: 
      - 4
  register: no_four_password
- name: Show long password
  debug:
    msg: "No 4s password {{ no_four_password.password }}"
'''

RETURN = r'''
value:
  description: The password
  returned: success
  sample: { "password": "XXXX" }
'''