import importlib
import os
import sys
from unittest.mock import patch

import pytest
from keeper_secrets_manager_core.exceptions import KeeperError

from ..ansible_test_framework import AnsibleTestFramework
from ..folder_fake_server import FakeKeeperServer

TARGET = os.path.join(os.path.dirname(os.path.realpath(__file__)), "targets", "keeper_remove", "playbook.yml")
SHARED = "SHARED_FOLDER_UID"
DENIED_MESSAGE = "User does not have permission to delete this record"
RECORDS = [
    {"uid": "FIRST_UID", "title": "Record 1", "folder": SHARED},
    {"uid": "SECOND_UID", "title": "Record 2", "folder": SHARED},
    {"uid": "DENIED_UID", "title": "Denied", "folder": SHARED},
    {"uid": "TWIN_1_UID", "title": "Twin", "folder": SHARED},
    {"uid": "TWIN_2_UID", "title": "Twin", "folder": SHARED},
]
VARS = {"first_uid": "FIRST_UID", "first_title": "Record 1", "second_uid": "SECOND_UID", "second_title": "Record 2",
        "denied_uid": "DENIED_UID"}
EXPECTED = {
    "denied": 'Could not remove record: The Keeper server did not delete record "Denied" (UID DENIED_UID). It '
              'returned access_denied: ' + DENIED_MESSAGE + '.',
    "twins": 'Could not remove record: Found multiple records for the title "Twin": TWIN_1_UID, TWIN_2_UID. Use a '
             'single UID to select the record to delete.',
}


class RecordDeleteServer(FakeKeeperServer):
    """The real SDK, with record deletes that the forked task workers of Ansible share through the state file."""

    def handle(self, sm, path, payload):
        if path != "delete_secret":
            return super().handle(sm, path, payload)

        state = self._load()
        state["calls"].append({"path": path, "record_uids": list(payload.recordUids)})
        try:
            if path in state["fail"]:
                raise KeeperError(state["fail"][path])
            statuses = []
            for uid in payload.recordUids:
                if uid in state["delete_status"]:
                    code, message = state["delete_status"][uid]
                else:
                    code, message = "ok", None
                    state["records"] = [r for r in state["records"] if r["uid"] != uid]
                status = {"recordUid": uid, "responseCode": code}
                if message is not None:
                    status["errorMessage"] = message
                statuses.append(status)
            return self._json({"records": statuses})
        finally:
            self._save(state)


def _unload_ansible():
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)


@pytest.fixture(scope="module")
def run():
    _unload_ansible()
    server = RecordDeleteServer(folders=[{"uid": SHARED, "name": "Shared", "parent": None}], records=RECORDS,
                                delete_status={"DENIED_UID": ["access_denied", DENIED_MESSAGE]})
    try:
        errors = importlib.import_module("ansible.errors")
        with server.patch(), patch("keeper_secrets_manager_ansible.AnsibleError", errors.AnsibleError):
            recap, out, err = AnsibleTestFramework(playbook=TARGET, vars=dict(VARS, expected=EXPECTED)).run()
        yield server, recap, out + err
    finally:
        server.cleanup()
        _unload_ansible()


def test_playbook_passes(run):
    _, recap, output = run
    expected = {"ok": 10, "changed": 2, "failed": 0, "unreachable": 0, "skipped": 0, "rescued": 1, "ignored": 1}
    assert {k: recap.get(k) for k in expected} == expected, output


def test_the_server_got_only_the_expected_deletes(run):
    server, _, _ = run
    # Check mode, the no-ops, and the duplicate titles sent no delete. The refused delete was sent three times.
    assert [c["record_uids"] for c in server.calls("delete_secret")] == [
        ["FIRST_UID"], ["SECOND_UID"], ["DENIED_UID"], ["DENIED_UID"]]
    assert sorted(r["uid"] for r in server.records()) == ["DENIED_UID", "TWIN_1_UID", "TWIN_2_UID"]
