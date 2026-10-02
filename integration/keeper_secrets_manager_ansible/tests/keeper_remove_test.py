import importlib
import sys
import unittest
from unittest.mock import patch

from keeper_secrets_manager_core.exceptions import KeeperError

from .ansible_test_framework import AnsibleTestFramework
from .folder_fake_server import FakeKeeperServer


UID = "REMOVE_RECORD_UID"
TITLE = "Record 1"
OTHER_UID = "OTHER_REMOVE_RECORD_UID"
OTHER_TITLE = "Record 2"
KEEP_UID = "KEEP_RECORD_UID"
SHARED_UID = "SHARED_FOLDER_UID"
DENIED_MESSAGE = "User does not have permission to delete this record"

RECORDS = [
    {"uid": UID, "title": TITLE, "folder": SHARED_UID},
    {"uid": OTHER_UID, "title": OTHER_TITLE, "folder": SHARED_UID},
    {"uid": KEEP_UID, "title": "Keep Me", "folder": SHARED_UID},
]


class _RecordDeleteServer(FakeKeeperServer):
    """Use the real SDK and keep record deletions and calls visible across Ansible's forked task workers."""

    def handle(self, sm, path, payload):
        if path != "delete_secret":
            return super().handle(sm, path, payload)

        state = self._load()
        state["calls"].append({"path": path, "record_uids": list(payload.recordUids)})
        try:
            if path in state["fail"]:
                raise KeeperError(state["fail"][path])
            if state["omit_delete_status"]:
                return self._json({"records": []})

            statuses = []
            for uid in payload.recordUids:
                if uid in state["delete_status"]:
                    code, message = state["delete_status"][uid]
                elif any(record["uid"] == uid for record in state["records"]):
                    code, message = "ok", None
                    state["records"] = [record for record in state["records"] if record["uid"] != uid]
                else:
                    code, message = "not_found", "The record does not exist"
                status = {"recordUid": uid, "responseCode": code}
                if message is not None:
                    status["errorMessage"] = message
                statuses.append(status)
            return self._json({"records": statuses})
        finally:
            self._save(state)


class KeeperRemoveTest(unittest.TestCase):

    def setUp(self):
        for name in list(sys.modules):
            if name.startswith("ansible"):
                sys.modules.pop(name, None)
        self.server = _RecordDeleteServer(
            folders=[{"uid": SHARED_UID, "name": "Shared", "parent": None}], records=RECORDS,
        )
        self.addCleanup(self.server.cleanup)

    def _run(self, playbook, **variables):
        extra_vars = {
            "uid": UID, "title": OTHER_TITLE, "record_title": TITLE, "other_uid": OTHER_UID,
        }
        extra_vars.update(variables)
        # The harness unloads Ansible after every playbook. Bind the error class of this run, as a real
        # ansible-playbook process does, rather than keeping a class from an earlier import.
        errors = importlib.import_module("ansible.errors")
        with self.server.patch(), patch("keeper_secrets_manager_ansible.AnsibleError", errors.AnsibleError):
            return AnsibleTestFramework(playbook=playbook, vars=extra_vars).run()

    def assertRecap(self, recap, out, err, **expected):
        actual = {key: recap.get(key) for key in expected}
        markers = ("TASK [", "fatal:", "[ERROR]", '"msg"', "localhost  ", "Traceback", "Error:")
        summary = "\n".join(line for line in (out + err).splitlines() if any(mark in line for mark in markers))
        self.assertEqual(actual, expected, "Unexpected recap {}:\n{}".format(recap, summary))

    def assertRecords(self, *uids):
        self.assertEqual(sorted(record["uid"] for record in self.server.records()), sorted(uids))

    def assertDeletes(self, *uids):
        self.assertEqual(
            [call["record_uids"] for call in self.server.calls("delete_secret")], [[uid] for uid in uids],
        )

    def test_keeper_remove(self):
        recap, out, err = self._run("keeper_remove.yml")
        self.assertRecap(recap, out, err, ok=2, changed=2, failed=0)
        self.assertDeletes(UID, OTHER_UID)
        self.assertRecords(KEEP_UID)

    def test_keeper_remove_cache(self):
        recap, out, err = self._run("keeper_remove_cache.yml")
        self.assertRecap(recap, out, err, ok=5, changed=2, failed=0)
        self.assertDeletes(UID, OTHER_UID)
        self.assertRecords(KEEP_UID)

    def test_missing_and_repeated_deletes_are_no_ops(self):
        recap, out, err = self._run("keeper_remove_idempotent.yml")
        self.assertRecap(recap, out, err, ok=8, changed=2, failed=0, ignored=0)
        self.assertDeletes(UID, OTHER_UID)
        self.assertRecords(KEEP_UID)

    def test_repeated_deletes_with_a_stale_or_partial_cache_are_no_ops(self):
        recap, out, err = self._run(
            "keeper_remove_cache_idempotent.yml", keeper_record_cache_secret="record-removal-test-only",
        )
        self.assertRecap(recap, out, err, ok=6, changed=2, failed=0)
        self.assertDeletes(UID, OTHER_UID)
        self.assertRecords(KEEP_UID)

    def test_duplicate_title_fails_without_deleting_in_normal_or_check_mode(self):
        state = self.server._load()
        state["records"][1]["title"] = TITLE
        self.server._save(state)
        for preview in (False, True):
            with self.subTest(check_mode=preview):
                recap, out, err = self._run("keeper_remove_duplicate_title.yml", preview=preview)
                self.assertRecap(recap, out, err, ok=2, changed=0, failed=0, ignored=1)
                self.assertDeletes()
                self.assertRecords(UID, OTHER_UID, KEEP_UID)

    def test_refused_delete_reports_the_server_code_and_message(self):
        state = self.server._load()
        state["delete_status"][UID] = ["access_denied", DENIED_MESSAGE]
        self.server._save(state)
        recap, out, err = self._run(
            "keeper_remove_refused.yml", expected_code="access_denied", expected_message=DENIED_MESSAGE,
        )
        self.assertRecap(recap, out, err, ok=2, changed=0, failed=0, ignored=1)
        self.assertDeletes(UID)
        self.assertRecords(UID, OTHER_UID, KEEP_UID)

    def test_unconfirmed_delete_is_not_reported_as_a_success(self):
        state = self.server._load()
        state["omit_delete_status"] = True
        self.server._save(state)
        recap, out, err = self._run(
            "keeper_remove_refused.yml", expected_code="did not confirm", expected_message=UID,
        )
        self.assertRecap(recap, out, err, ok=2, changed=0, failed=0, ignored=1)
        self.assertDeletes(UID)
        self.assertRecords(UID, OTHER_UID, KEEP_UID)

    def test_failed_when_ignore_errors_and_rescue_handle_a_refusal(self):
        state = self.server._load()
        state["delete_status"][UID] = ["access_denied", DENIED_MESSAGE]
        self.server._save(state)
        recap, out, err = self._run("keeper_remove_rescue.yml")
        self.assertRecap(recap, out, err, ok=7, changed=0, failed=0, ignored=1, rescued=1)
        self.assertDeletes(UID, UID, UID, UID)
        self.assertRecords(UID, OTHER_UID, KEEP_UID)

    def test_network_errors_are_task_failures_not_no_ops(self):
        for path in ("get_secret", "delete_secret"):
            with self.subTest(path=path):
                state = self.server._load()
                state["fail"] = {path: "Cannot reach Keeper"}
                state["calls"] = []
                self.server._save(state)
                recap, out, err = self._run(
                    "keeper_remove_refused.yml", expected_code="Could not remove record",
                    expected_message="Cannot reach Keeper",
                )
                self.assertRecap(recap, out, err, ok=2, changed=0, failed=0, ignored=1)
                self.assertDeletes(*([UID] if path == "delete_secret" else []))
                self.assertRecords(UID, OTHER_UID, KEEP_UID)

    def test_check_mode_predicts_changes_and_never_deletes(self):
        recap, out, err = self._run("keeper_remove_check_mode.yml")
        self.assertRecap(recap, out, err, ok=5, changed=2, failed=0)
        self.assertDeletes()
        self.assertRecords(UID, OTHER_UID, KEEP_UID)
