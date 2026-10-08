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
from keeper_secrets_manager_ansible import KeeperAnsible

DOCUMENTATION = r'''
---
module: keeper_remove

short_description: Remove a secret from the vault.

version_added: "1.2.1"

description:
    - Remove a secret from the vault.
    - If the record does not exist, or is not shared to this KSM application, the task succeeds without a change.
    - A title that matches more than one record fails the task and lists the matching UIDs. Nothing is deleted.
    - A refused or unconfirmed delete fails the task instead of reporting success.
    - In check mode, a matching record reports a predicted change without sending a delete request.
      Server permissions are checked only during a real delete.
attributes:
  check_mode:
    support: full
    description: Looks up the record without sending a delete request. Server permissions are checked
      only in a real run.
notes:
  - Check mode requires an initialized Keeper configuration.
author:
    - John Walstra
options:
  uid:
    description:
    - The UID of the Keeper Vault record.
    - Set either uid or title, but not both.
    type: str
    required: no
  title:
    description:
    - The Title of the Keeper Vault record.
    - Set either uid or title, but not both. The title must match exactly one record.
    type: str
    required: no
    version_added: '1.2.0'
  cache:
    description:
    - The encrypted cache registered by keeper_cache_records, as a string or byte string.
    - Accepted for compatibility. Removal always reads the current vault, not the registered cache,
      so an outdated or partial cache cannot report a false no-op or hide a duplicate title.
    type: raw
    required: no
    version_added: '1.2.0'
'''

EXAMPLES = r'''
- name: Remove secret using UID.
  keeper_remove:
    uid: XXX
- name: Remove secret using title.
  keeper_remove:
    title: XXXXXXXXX

- name: Preview removal without deleting the record.
  keeper_remove:
    uid: XXX
  check_mode: yes

'''

RETURN = r'''
changed:
  description: Whether a record was deleted, or would be deleted in check mode.
  returned: always
  type: bool
  sample: true
record_uid:
  description: The UID of the deleted record, or the record that would be deleted in check mode.
  returned: success, when a record was found
  type: str
  sample: XXXX
record_title:
  description: The title of the deleted record, or the record that would be deleted in check mode.
  returned: success, when a record was found
  type: str
  sample: Temporary Login
msg:
  description: A message explaining that the record was not found, or why the task failed.
  returned: when the record was not found, or on failure
  type: str
  sample: The record was not found, or it is not shared to this KSM application. Nothing was deleted.
'''


class ActionModule(ActionBase):

    ARGUMENT_SPEC = dict(
        uid=dict(type="str"),
        title=dict(type="str"),
        cache=dict(type="raw"),
    )

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        try:
            args = KeeperAnsible.validate_task_args(
                "keeper_remove", self._task.args, self.ARGUMENT_SPEC,
                mutually_exclusive=[("uid", "title")],
                ignore=KeeperAnsible.group_default_options(self._task, self._templar))
            if args.get("uid") is None and args.get("title") is None:
                raise ValueError("keeper_remove requires either uid or title to be set.")
            for name in ("uid", "title"):
                value = args.get(name)
                if value is not None and not value.strip():
                    raise ValueError("The {} is blank.".format(name))
                if name == "uid" and value is not None and value != value.strip():
                    raise ValueError("The uid {!r} has leading or trailing whitespace.".format(value))
            cache = args.get("cache")
            if cache is not None and not (KeeperAnsible._is_text(cache) or isinstance(cache, (bytes, bytearray))):
                raise ValueError("The cache option must be an encrypted cache string or byte string.")
        except Exception as err:
            return {"failed": True, "changed": False, "msg": str(err)}

        try:
            keeper = KeeperAnsible(task_vars=task_vars, action_module=self)
            return keeper.remove_record(
                uids=args.get("uid"), titles=args.get("title"), cache=args.get("cache"),
                check_mode=bool(self._task.check_mode))
        except Exception as err:
            return {"failed": True, "changed": False, "msg": "Could not remove record: {}".format(err)}
