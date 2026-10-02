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
