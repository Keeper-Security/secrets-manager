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


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        keeper = KeeperAnsible(task_vars=task_vars)

        length = self._task.args.get("length", 64)
        allow_lowercase = self._task.args.get("allow_lowercase", True)
        allow_uppercase = self._task.args.get("allow_uppercase", True)
        allow_digits = self._task.args.get("allow_digits", True)
        allow_symbols = self._task.args.get("allow_symbols", True)
        filter_characters = self._task.args.get("filter_characters")

        complexity = keeper.password_complexity_translation(
            length=length,
            allow_lowercase=allow_lowercase,
            allow_uppercase=allow_uppercase,
            allow_digits=allow_digits,
            allow_symbols=allow_symbols,
            filter_characters=filter_characters
        )

        password = keeper.generate_password(**complexity)

        keeper.stash_secret_value(password)

        result = {
            "password": password
        }

        keeper.add_secret_values_to_results(result)

        return result
