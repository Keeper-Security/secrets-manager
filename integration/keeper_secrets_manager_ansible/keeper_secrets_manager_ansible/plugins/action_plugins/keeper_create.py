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
from keeper_secrets_manager_helper.record_type import RecordType
from keeper_secrets_manager_helper.record import Record
from keeper_secrets_manager_helper.field import Field, FieldSectionEnum
from ansible.utils.display import Display
import json

display = Display()

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


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        keeper = KeeperAnsible(task_vars=task_vars)

        shared_folder_uid = self._task.args.get("shared_folder_uid")
        if shared_folder_uid is None:
            raise AnsibleError("The shared_folder_uid is blank. keeper_create requires this value to be set.")
        record_type = self._task.args.get("record_type")
        if record_type is None:
            raise AnsibleError("The record_type is blank. keeper_create requires this value to be set.")
        if record_type not in RecordType.get_record_type_list():
            raise AnsibleError("The record_type {} is not a valid record type.".format(record_type))
        title = self._task.args.get("title")
        if title is None:
            raise AnsibleError("The title is blank. keeper_create requires this value to be set.")
        version = self._task.args.get("version", "v3")

        # If there are custom record type, load them
        keeper_record_types = task_vars.get("keeper_record_types")
        if keeper_record_types is not None:
            if isinstance(keeper_record_types, list) is False:
                raise AnsibleError("The Keeper record types is not a list.")
            for keeper_record_type in keeper_record_types:
                if isinstance(keeper_record_type, str) is True:
                    keeper_record_type = json.loads(keeper_record_type)
                    if isinstance(keeper_record_type, dict) is True:
                        keeper_record_type = [keeper_record_type]
                RecordType.load_commander_record_types(keeper_record_type)

        fields = []

        try:
            for field in self._task.args.get("fields", []):
                fields.append(Field(
                    field_section=FieldSectionEnum.STANDARD,
                    type=field.get("type"),
                    label=field.get("label"),
                    value=field.get("value")
                ))
                keeper.stash_secret_value(str(field.get("value")))

            for field in self._task.args.get("custom_fields", []):
                fields.append(Field(
                    field_section=FieldSectionEnum.CUSTOM,
                    type=field.get("type"),
                    label=field.get("label"),
                    value=field.get("value", "text")
                ))
                keeper.stash_secret_value(str(field.get("value")))

            password_complexity = self._task.args.get("password_complexity")
            if password_complexity is not None:
                password_complexity = keeper.password_complexity_translation(**password_complexity)

            record = Record(version=version).create_from_field_list(
                record_type=record_type,
                title=title,
                notes=self._task.args.get("note"),
                fields=fields,
                password_generate=self._task.args.get("generate_password"),
                password_complexity=password_complexity
            )
            record_create = record[0].get_record_create_obj()
            record_uid = keeper.create_record(record_create, shared_folder_uid=shared_folder_uid)
        except Exception as err:
            raise AnsibleError("Could not create record: {}".format(err))

        result = {
            "record_uid": record_uid
        }

        return result
