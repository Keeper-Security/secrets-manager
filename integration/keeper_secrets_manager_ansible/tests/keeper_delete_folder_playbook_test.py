import contextlib
import importlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import keeper_secrets_manager_ansible.plugins
from .ansible_test_framework import AnsibleTestFramework
from .folder_fake_server import FakeKeeperServer, NOT_EMPTY_CODE


# The vault that every playbook test starts with.
#
#   Infrastructure (SHARED_FOLDER_UID)          shared folder, one record at its top level
#     Staging (EMPTY_FOLDER_UID)                empty
#     Web (RECORD_FOLDER_UID)                   one record
#     Databases (TREE_FOLDER_UID)               one record and one subfolder
#       Production (TREE_CHILD_UID)             one record
#     Apps (PARENT_FOLDER_UID)                  only a subfolder
#       Archive (PARENT_CHILD_UID)              empty
#     Temporary (TEMP_FOLDER_UID)               empty
#   Operations (OPS_SHARED_UID)                 shared folder, one record at its top level
#   Sandbox (SANDBOX_SHARED_UID)                empty shared folder
SHARED_FOLDER_UID = "SHARED_FOLDER_UID"
EMPTY_FOLDER_UID = "EMPTY_FOLDER_UID"
RECORD_FOLDER_UID = "RECORD_FOLDER_UID"
TREE_FOLDER_UID = "TREE_FOLDER_UID"
TREE_CHILD_UID = "TREE_CHILD_UID"
PARENT_FOLDER_UID = "PARENT_FOLDER_UID"
PARENT_CHILD_UID = "PARENT_CHILD_UID"
TEMP_FOLDER_UID = "TEMP_FOLDER_UID"
OPS_SHARED_UID = "OPS_SHARED_UID"
SANDBOX_SHARED_UID = "SANDBOX_SHARED_UID"

FOLDERS = [
    {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
    {"uid": OPS_SHARED_UID, "name": "Operations", "parent": None},
    {"uid": SANDBOX_SHARED_UID, "name": "Sandbox", "parent": None},
    {"uid": EMPTY_FOLDER_UID, "name": "Staging", "parent": SHARED_FOLDER_UID},
    {"uid": RECORD_FOLDER_UID, "name": "Web", "parent": SHARED_FOLDER_UID},
    {"uid": TREE_FOLDER_UID, "name": "Databases", "parent": SHARED_FOLDER_UID},
    {"uid": TREE_CHILD_UID, "name": "Production", "parent": TREE_FOLDER_UID},
    {"uid": PARENT_FOLDER_UID, "name": "Apps", "parent": SHARED_FOLDER_UID},
    {"uid": PARENT_CHILD_UID, "name": "Archive", "parent": PARENT_FOLDER_UID},
    {"uid": TEMP_FOLDER_UID, "name": "Temporary", "parent": SHARED_FOLDER_UID},
]

RECORDS = [
    {"uid": "RECORD_AT_TOP", "title": "Top Login", "folder": SHARED_FOLDER_UID, "inner": None},
    {"uid": "RECORD_IN_WEB", "title": "Web Login", "folder": SHARED_FOLDER_UID, "inner": RECORD_FOLDER_UID},
    {"uid": "RECORD_IN_DATABASES", "title": "Database Login", "folder": SHARED_FOLDER_UID, "inner": TREE_FOLDER_UID},
    {"uid": "RECORD_IN_PRODUCTION", "title": "Production Login", "folder": SHARED_FOLDER_UID,
     "inner": TREE_CHILD_UID},
    {"uid": "RECORD_IN_OPERATIONS", "title": "Operations Login", "folder": OPS_SHARED_UID, "inner": None},
]

ALL_FOLDER_UIDS = sorted(f["uid"] for f in FOLDERS)
ALL_RECORD_UIDS = sorted(r["uid"] for r in RECORDS)

PLAYBOOK_VARS = {
    "shared_folder_uid": SHARED_FOLDER_UID,
    "empty_folder_uid": EMPTY_FOLDER_UID,
    "record_folder_uid": RECORD_FOLDER_UID,
    "tree_folder_uid": TREE_FOLDER_UID,
    "parent_folder_uid": PARENT_FOLDER_UID,
    "parent_child_uid": PARENT_CHILD_UID,
    "temp_folder_uid": TEMP_FOLDER_UID,
    "ops_shared_uid": OPS_SHARED_UID,
    "sandbox_shared_uid": SANDBOX_SHARED_UID,
}

# The exact messages. The playbooks compare the registered msg with them: on ansible-core 2.19+ the display adds
# "Task failed: Action failed: ", but the registered msg must not have it.
NULL_MESSAGE = "The {} option is null. Give it a value, or leave the option out of the task."
NOT_A_STRING_MESSAGE = ("The folder_uid option must be a string, but it is {}. Put quotes around the value, or "
                        "use the string filter.")
SUPPORTED_MARKER = "Supported parameters include: "


def _label(path, folder_uid):
    # The folder label in messages, for a path with no character that JSON escapes.
    return '"{}" (UID {})'.format(path, folder_uid)


def _not_found_msg(folder_uid):
    return ("The folder {} was not found, or it is not shared to this KSM application. Nothing was "
            "deleted.".format(folder_uid))


def _not_empty_msg(label, records, subfolders):
    return ("Could not delete folder: The folder {} is not empty. It contains {} record(s) and {} subfolder(s). "
            "Set force_deletion to true to delete the folder and everything in it.".format(label, records,
                                                                                          subfolders))


def _unsupported_before(option):
    # The text before the list of supported names. That list is in set order on ansible-core 2.12.
    return "Unsupported parameters for (keeper_delete_folder) module: {}. ".format(option)


def _lookup_not_found_msg(name):
    return ('Could not look up folder: No folder named "{}" was found in the folder "Infrastructure" '
            '(UID SHARED_FOLDER_UID).'.format(name))


WEB_NOT_EMPTY = _not_empty_msg(_label("Infrastructure/Web", RECORD_FOLDER_UID), 1, 0)
TREE_NOT_EMPTY = _not_empty_msg(_label("Infrastructure/Databases", TREE_FOLDER_UID), 1, 1)
APPS_NOT_EMPTY = _not_empty_msg(_label("Infrastructure/Apps", PARENT_FOLDER_UID), 0, 1)
ACCESS_DENIED = ["access_denied", "User does not have permission to delete this folder"]


class _ChosenDeleteBodyServer(FakeKeeperServer):
    """
    FakeKeeperServer with a delete_folder response body that the test chooses. With really_delete, the server
    deletes the folder as usual and then sends that body, so it can delete a folder and send no status for it.
    FakeKeeperServer cannot do that: omit_delete_status leaves the folder in place. With
    fail_folder_read_after_delete, every get_folders request after the delete fails, as after a network error.
    """

    def __init__(self, folders, records=None, delete_body=None, really_delete=True,
                 fail_folder_read_after_delete=None):
        FakeKeeperServer.__init__(self, folders, records=records, omit_delete_status=not really_delete)
        self.delete_body = delete_body
        self.fail_folder_read_after_delete = fail_folder_read_after_delete

    def handle(self, sm, path, payload):
        response = FakeKeeperServer.handle(self, sm, path, payload)
        if path == "delete_folder":
            if self.fail_folder_read_after_delete is not None:
                state = self._load()
                state["fail"]["get_folders"] = self.fail_folder_read_after_delete
                self._save(state)
            return json.dumps(self.delete_body).encode()
        return response


def _run(server, playbook, **extra_vars):
    variables = dict(PLAYBOOK_VARS)
    variables.update(extra_vars)
    # AnsibleTestFramework unloads every ansible module after a run, but keeper_secrets_manager_ansible keeps
    # the AnsibleError class of the first import. In a later run, an AnsibleError of that old class (KeeperAnsible
    # raises one for a config error) recurses without end in __str__ on ansible-core 2.19+, and the task executor
    # crashes instead of failing the task. A real ansible-playbook imports ansible only once, so bind the class of
    # the ansible that this run uses, as in production.
    ansible_errors = importlib.import_module("ansible.errors")
    with server.patch(), patch("keeper_secrets_manager_ansible.AnsibleError", ansible_errors.AnsibleError):
        return AnsibleTestFramework(playbook=playbook, vars=variables).run()


def _summary(out, err):
    """The lines of the playbook output that explain a failure, not the whole verbose log."""
    keep = ("TASK [", "fatal:", "[ERROR]", '"msg"', "localhost  ", "Traceback", "Error:")
    return "\n".join(line for line in (out + err).splitlines() if any(k in line for k in keep))


class _PlaybookTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # The first playbook run in a process must import the ansible modules itself, after AnsibleTestFramework
        # sets the plugin paths. A test module that imports a plugin class at the top has already loaded ansible's
        # plugin loader with the default paths, and then the run fails with "couldn't resolve module/action".
        # Unload the ansible modules first, as AnsibleTestFramework does after each run, so that these tests pass in
        # any order and in any subset.
        for module in list(sys.modules):
            if module.startswith("ansible"):
                sys.modules.pop(module, None)

    def assertRecap(self, recap, out, err, **expected):
        actual = {key: recap.get(key) for key in expected}
        self.assertEqual(actual, expected, "unexpected PLAY RECAP {}:\n{}".format(recap, _summary(out, err)))

    def assertFolders(self, server, expected_uids):
        self.assertEqual(sorted(f["uid"] for f in server.folders()), sorted(expected_uids))

    def assertRecords(self, server, expected_uids):
        self.assertEqual(sorted(r["uid"] for r in server.records()), sorted(expected_uids))

    def assertDeleteRequests(self, server, expected):
        """expected: a list of (folder_uids, force), in the order that the server received them."""
        requests = [(c["folder_uids"], c["force"]) for c in server.calls("delete_folder")]
        self.assertEqual(requests, expected)
        for (_, force), (_, expected_force) in zip(requests, expected):
            self.assertIs(force, expected_force, "force must be a real bool in the request")

    def assertNothingSent(self, server):
        """No request of any kind reached the server, and the vault is as it was."""
        self.assertEqual(server.calls(), [])
        self.assertFolders(server, ALL_FOLDER_UIDS)
        self.assertRecords(server, ALL_RECORD_UIDS)


class KeeperDeleteFolderPlaybookTest(_PlaybookTestCase):
    """
    The acceptance scenarios and the QA test steps, through real playbooks. Only the network is fake: the real
    SDK builds each request and parses each response, and each task sees what the tasks before it changed.
    """

    MAIN_EXPECTED = {
        "not_found_empty": _not_found_msg(EMPTY_FOLDER_UID),
        "not_found_never": _not_found_msg("NO_SUCH_FOLDER_UID"),
        "lookup_after_delete": _lookup_not_found_msg("Staging"),
    }

    NOT_EMPTY_EXPECTED = {
        "has_record": WEB_NOT_EMPTY,
        "has_subfolder": APPS_NOT_EMPTY,
        "force_no": TREE_NOT_EMPTY,
        "shared_has_record": _not_empty_msg(_label("Operations", OPS_SHARED_UID), 1, 0),
    }

    FORCE_EXPECTED = {
        "not_found_tree": _not_found_msg(TREE_FOLDER_UID),
        "lookup_child": _lookup_not_found_msg("Databases"),
    }

    def test_empty_folder_is_deleted_and_a_second_delete_is_a_no_op(self):
        """
        QA steps 1 to 3 and the first and third scenarios: an empty folder in a shared folder is deleted by UID
        (changed), it is gone, and a second delete of it, or of a folder that never existed, is ok and not
        changed, says that nothing was deleted, and sends no second delete request. An empty shared folder is
        deleted the same way.
        """
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder.yml", expected=self.MAIN_EXPECTED)

            self.assertRecap(recap, out, err, ok=6, changed=2, failed=0, ignored=1, skipped=0)
            self.assertDeleteRequests(server, [([EMPTY_FOLDER_UID], False), ([SANDBOX_SHARED_UID], False)])
            self.assertIsNone(server.folder(EMPTY_FOLDER_UID), "the empty folder must be gone")
            self.assertIsNone(server.folder(SANDBOX_SHARED_UID), "the empty shared folder must be gone")
            self.assertFolders(server, [uid for uid in ALL_FOLDER_UIDS
                                        if uid not in (EMPTY_FOLDER_UID, SANDBOX_SHARED_UID)])
            self.assertRecords(server, ALL_RECORD_UIDS)
            self.assertEqual(len(server.calls("get_secret")), 2,
                             "only the two real deletes read the records; a folder that is not found needs no check")
        finally:
            server.cleanup()

    def test_folder_that_is_not_empty_fails_without_force(self):
        """
        QA step 4 and the second scenario: a folder with a record, a folder with only a subfolder, and a
        shared folder with a top-level record all fail without force_deletion (also with force_deletion: no and
        force_deletion: "false"), with the exact message, and the server receives no delete request.
        """
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_not_empty.yml", expected=self.NOT_EMPTY_EXPECTED)

            self.assertRecap(recap, out, err, ok=6, changed=0, failed=0, ignored=5)
            self.assertDeleteRequests(server, [])
            self.assertFolders(server, ALL_FOLDER_UIDS)
            self.assertRecords(server, ALL_RECORD_UIDS)
        finally:
            server.cleanup()

    def test_force_deletes_the_folder_with_its_subtree_and_records(self):
        """
        force_deletion: yes and force_deletion: "true" delete the folder, its subfolders, and their records, and
        nothing else.
        """
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_force.yml", expected=self.FORCE_EXPECTED)

            self.assertRecap(recap, out, err, ok=5, changed=2, failed=0, ignored=1)
            self.assertDeleteRequests(server, [([TREE_FOLDER_UID], True), ([RECORD_FOLDER_UID], True)])
            self.assertEqual(server.calls("get_secret"), [], "a forced delete must not read the records")
            self.assertFolders(server, [uid for uid in ALL_FOLDER_UIDS
                                        if uid not in (TREE_FOLDER_UID, TREE_CHILD_UID, RECORD_FOLDER_UID)])
            self.assertRecords(server, ["RECORD_AT_TOP", "RECORD_IN_OPERATIONS"])
        finally:
            server.cleanup()

    def test_same_folder_fails_without_force_then_force_deletes_it(self):
        """
        The folder with a record and a subfolder is still there, with its records, after the delete without
        force. Then force deletes the same folder with everything in it.
        """
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_not_empty.yml", expected=self.NOT_EMPTY_EXPECTED)
            self.assertRecap(recap, out, err, failed=0, ignored=5)
            self.assertDeleteRequests(server, [])
            self.assertEqual(server.folder(TREE_FOLDER_UID)["name"], "Databases")
            self.assertEqual(server.folder(TREE_CHILD_UID)["parent"], TREE_FOLDER_UID)
            self.assertRecords(server, ALL_RECORD_UIDS)

            recap, out, err = _run(server, "keeper_delete_folder_force.yml", expected=self.FORCE_EXPECTED)
            self.assertRecap(recap, out, err, failed=0, changed=2)
            self.assertDeleteRequests(server, [([TREE_FOLDER_UID], True), ([RECORD_FOLDER_UID], True)])
            self.assertIsNone(server.folder(TREE_FOLDER_UID))
            self.assertIsNone(server.folder(TREE_CHILD_UID))
            self.assertNotIn("RECORD_IN_DATABASES", [r["uid"] for r in server.records()])
            self.assertNotIn("RECORD_IN_PRODUCTION", [r["uid"] for r in server.records()])
        finally:
            server.cleanup()


class KeeperDeleteFolderServerStatusPlaybookTest(_PlaybookTestCase):
    """
    The server does not raise an error when it does not delete a folder. The task must fail with the exact
    message, and it must never report a delete that did not happen.
    """

    def _refused(self, server, folder_uid, msg, force=False):
        return _run(server, "keeper_delete_folder_refused.yml", target_folder_uid=folder_uid, target_force=force,
                    expected={"msg": msg})

    def test_access_denied_fails_and_the_folder_still_exists(self):
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS, delete_status={EMPTY_FOLDER_UID: ACCESS_DENIED})
        try:
            recap, out, err = self._refused(
                server, EMPTY_FOLDER_UID,
                'Could not delete folder: The Keeper server did not delete the folder "Infrastructure/Staging" '
                '(UID EMPTY_FOLDER_UID). It returned access_denied: User does not have permission to delete this '
                'folder.')

            self.assertRecap(recap, out, err, ok=2, changed=0, failed=0, ignored=1)
            self.assertDeleteRequests(server, [([EMPTY_FOLDER_UID], False)])
            self.assertEqual(server.folder(EMPTY_FOLDER_UID)["name"], "Staging")
            self.assertFolders(server, ALL_FOLDER_UIDS)
            self.assertEqual(len(server.calls("get_folders")), 1, "a refusal status needs no second get_folders")
        finally:
            server.cleanup()

    def test_access_denied_on_a_forced_delete_keeps_the_whole_subtree(self):
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS, delete_status={TREE_FOLDER_UID: ACCESS_DENIED})
        try:
            recap, out, err = self._refused(
                server, TREE_FOLDER_UID,
                'Could not delete folder: The Keeper server did not delete the folder "Infrastructure/Databases" '
                '(UID TREE_FOLDER_UID). It returned access_denied: User does not have permission to delete this '
                'folder.', force=True)

            self.assertRecap(recap, out, err, failed=0, ignored=1)
            self.assertDeleteRequests(server, [([TREE_FOLDER_UID], True)])
            self.assertFolders(server, ALL_FOLDER_UIDS)
            self.assertRecords(server, ALL_RECORD_UIDS)
        finally:
            server.cleanup()

    def test_missing_status_fails_because_the_folder_still_exists(self):
        """The server sends no status and deletes nothing: the second get_folders still finds the folder."""
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS, omit_delete_status=True)
        try:
            recap, out, err = self._refused(
                server, EMPTY_FOLDER_UID,
                'Could not delete folder: The Keeper server did not confirm the delete of the folder '
                '"Infrastructure/Staging" (UID EMPTY_FOLDER_UID), and the folder still exists.')

            self.assertRecap(recap, out, err, ok=2, changed=0, failed=0, ignored=1)
            self.assertDeleteRequests(server, [([EMPTY_FOLDER_UID], False)])
            self.assertEqual(server.folder(EMPTY_FOLDER_UID)["name"], "Staging")
            self.assertEqual(len(server.calls("get_folders")), 2, "the module must read the folders again")
        finally:
            server.cleanup()

    def test_server_refuses_a_folder_with_a_record_that_the_application_cannot_see(self):
        """
        The records check sees only the records that get_secrets returns. A record that it does not return
        (here, in a shared folder that is not shared to the application) must still be protected, because the
        module sends force false and reads the refusal of the server.
        """
        records = RECORDS + [{"uid": "HIDDEN_RECORD", "title": "Hidden", "folder": "NOT_SHARED_TO_APP",
                              "inner": EMPTY_FOLDER_UID}]
        server = FakeKeeperServer(folders=FOLDERS, records=records)
        try:
            recap, out, err = self._refused(
                server, EMPTY_FOLDER_UID,
                'Could not delete folder: The Keeper server did not delete the folder "Infrastructure/Staging" '
                '(UID EMPTY_FOLDER_UID). It returned {}: The folder is not empty.'.format(NOT_EMPTY_CODE))

            self.assertRecap(recap, out, err, failed=0, ignored=1)
            self.assertDeleteRequests(server, [([EMPTY_FOLDER_UID], False)])
            self.assertIsNotNone(server.folder(EMPTY_FOLDER_UID))
            self.assertIn("HIDDEN_RECORD", [r["uid"] for r in server.records()])
        finally:
            server.cleanup()

    def test_status_only_for_another_folder_fails_because_the_folder_still_exists(self):
        """An ok for some other folder UID is not an ok for this folder."""
        server = _ChosenDeleteBodyServer(
            folders=FOLDERS, records=RECORDS, really_delete=False,
            delete_body={"folders": [{"folderUid": SANDBOX_SHARED_UID, "responseCode": "ok"}]})
        try:
            recap, out, err = self._refused(
                server, EMPTY_FOLDER_UID,
                'Could not delete folder: The Keeper server did not confirm the delete of the folder '
                '"Infrastructure/Staging" (UID EMPTY_FOLDER_UID), and the folder still exists.')

            self.assertRecap(recap, out, err, failed=0, ignored=1)
            self.assertFolders(server, ALL_FOLDER_UIDS)
        finally:
            server.cleanup()

    def test_folder_deleted_without_a_status_reports_changed(self):
        """
        The server deletes the folder but sends no status for it: no "folders" key (SDK 17.3.0 returns {}), or
        "folders": null (the SDK returns None). The second get_folders does not find the folder, so the delete
        happened, and the task reports changed.
        """
        for body in [{}, {"folders": None}, {"folders": []}]:
            with self.subTest(delete_body=body):
                server = _ChosenDeleteBodyServer(folders=FOLDERS, records=RECORDS, delete_body=body)
                try:
                    recap, out, err = _run(server, "keeper_delete_folder.yml",
                                           expected=KeeperDeleteFolderPlaybookTest.MAIN_EXPECTED)

                    self.assertRecap(recap, out, err, ok=6, changed=2, failed=0, ignored=1)
                    self.assertDeleteRequests(server, [([EMPTY_FOLDER_UID], False), ([SANDBOX_SHARED_UID], False)])
                    self.assertIsNone(server.folder(EMPTY_FOLDER_UID))
                    self.assertIsNone(server.folder(SANDBOX_SHARED_UID))
                    # 1 for each of the 4 deletes, 1 for the lookup, and 1 more for each of the 2 missing statuses.
                    self.assertEqual(len(server.calls("get_folders")), 7)
                finally:
                    server.cleanup()

    def test_failed_folder_check_after_a_delete_without_a_status(self):
        """
        No status for the folder, and the folder list cannot be read after the delete. The module cannot know
        if the folder is gone, so the task fails and says that the folder can still exist. That is true in both
        cases: the server deleted the folder, or it did not.
        """
        msg = ('Could not delete folder: The Keeper server sent no result for the delete of the folder '
               '"Infrastructure/Staging" (UID EMPTY_FOLDER_UID), and the check of the folder list after it failed, '
               'so the folder can still exist. Cannot get folders: Throttled')
        for really_delete in [False, True]:
            with self.subTest(really_delete=really_delete):
                server = _ChosenDeleteBodyServer(folders=FOLDERS, records=RECORDS, delete_body={},
                                                 really_delete=really_delete, fail_folder_read_after_delete="Throttled")
                try:
                    recap, out, err = self._refused(server, EMPTY_FOLDER_UID, msg)

                    self.assertRecap(recap, out, err, ok=2, changed=0, failed=0, ignored=1)
                    self.assertDeleteRequests(server, [([EMPTY_FOLDER_UID], False)])
                    self.assertEqual(len(server.calls("get_folders")), 2)
                    self.assertEqual(server.folder(EMPTY_FOLDER_UID) is None, really_delete)
                finally:
                    server.cleanup()

    def test_sdk_errors_fail_the_task_and_delete_nothing(self):
        """
        An error from the SDK (here a KeeperError from the fake server) must fail the task with the step that
        failed. A get_folders error must not look like "not found", which would silently report changed false.
        """
        cases = [
            ("get_folders", "Could not delete folder: Cannot get folders: Throttled", []),
            ("get_secret", 'Could not delete folder: Cannot get records to check if the folder '
                           '"Infrastructure/Staging" (UID EMPTY_FOLDER_UID) is empty: Throttled', []),
            ("delete_folder", 'Could not delete folder: Cannot delete the folder "Infrastructure/Staging" '
                              '(UID EMPTY_FOLDER_UID): Throttled', [([EMPTY_FOLDER_UID], False)]),
        ]
        for path, msg, delete_requests in cases:
            with self.subTest(failing_path=path):
                server = FakeKeeperServer(folders=FOLDERS, records=RECORDS, fail={path: "Throttled"})
                try:
                    recap, out, err = self._refused(server, EMPTY_FOLDER_UID, msg)

                    self.assertRecap(recap, out, err, ok=2, changed=0, failed=0, ignored=1)
                    self.assertDeleteRequests(server, delete_requests)
                    self.assertFolders(server, ALL_FOLDER_UIDS)
                    self.assertRecords(server, ALL_RECORD_UIDS)
                finally:
                    server.cleanup()

    def test_folder_names_with_a_quote_or_a_newline_are_escaped_in_messages(self):
        """
        Folder names are shown in JSON quotes. The real SDK decrypts the names here, so the double quote and
        the newline come from the vault data, as they would from a real vault.
        """
        folders = FOLDERS + [{"uid": "QUOTE_FOLDER_UID", "name": 'Web "Prod"', "parent": SHARED_FOLDER_UID},
                             {"uid": "NEWLINE_FOLDER_UID", "name": "Staging\n", "parent": SHARED_FOLDER_UID}]
        records = RECORDS + [{"uid": "RECORD_IN_QUOTE", "title": "Quote", "folder": SHARED_FOLDER_UID,
                              "inner": "QUOTE_FOLDER_UID"}]
        cases = [
            ("QUOTE_FOLDER_UID",
             r'Could not delete folder: The folder "Infrastructure/Web \"Prod\"" (UID QUOTE_FOLDER_UID) is not '
             r'empty. It contains 1 record(s) and 0 subfolder(s). Set force_deletion to true to delete the folder '
             r'and everything in it.', []),
            ("NEWLINE_FOLDER_UID",
             r'Could not delete folder: The Keeper server did not delete the folder "Infrastructure/Staging\n" '
             r'(UID NEWLINE_FOLDER_UID). It returned access_denied: User does not have permission to delete this '
             r'folder.', [(["NEWLINE_FOLDER_UID"], False)]),
        ]
        for folder_uid, msg, delete_requests in cases:
            with self.subTest(folder_uid=folder_uid):
                server = FakeKeeperServer(folders=folders, records=records,
                                          delete_status={"NEWLINE_FOLDER_UID": ACCESS_DENIED})
                try:
                    recap, out, err = self._refused(server, folder_uid, msg)

                    self.assertRecap(recap, out, err, ok=2, changed=0, failed=0, ignored=1)
                    self.assertDeleteRequests(server, delete_requests)
                    self.assertFolders(server, [f["uid"] for f in folders])
                finally:
                    server.cleanup()


class KeeperDeleteFolderCheckModePlaybookTest(_PlaybookTestCase):

    def test_check_mode_reports_changed_but_sends_no_delete(self):
        """
        check_mode: yes reports changed for a deletable folder, still fails for a folder that is not empty or a
        padded UID, still reports not changed for a missing folder, and sends no delete request at all.
        """
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_check_mode.yml", expected={
                "check_not_empty": WEB_NOT_EMPTY,
                "check_missing": _not_found_msg("NO_SUCH_FOLDER_UID"),
                "check_padded": "Could not delete folder: The folder_uid 'EMPTY_FOLDER_UID ' has leading or trailing "
                                "whitespace.",
            })

            self.assertRecap(recap, out, err, ok=7, changed=2, failed=0, ignored=2)
            self.assertEqual(server.calls("delete_folder"), [])
            self.assertFolders(server, ALL_FOLDER_UIDS)
            self.assertRecords(server, ALL_RECORD_UIDS)
            self.assertEqual(len(server.calls("get_secret")), 2,
                             "the records check must run in check mode, but not for force or a missing folder")
        finally:
            server.cleanup()


class KeeperDeleteFolderBadInputPlaybookTest(_PlaybookTestCase):
    """Wrong options and option values fail the task with the exact message, and nothing is deleted."""

    def test_wrong_options_fail_before_any_request(self):
        """
        The old option name force (also on a folder that is not empty), a misspelled or unknown option, a missing
        folder_uid, or a bad force_deletion fails before the first request, and nothing is deleted.
        """
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_bad_options.yml", expected={
                "supported_marker": SUPPORTED_MARKER,
                "unsupported_before": [_unsupported_before("force"), _unsupported_before("force"),
                                       _unsupported_before("force_delete"), _unsupported_before("forse"),
                                       _unsupported_before("folder_name")],
                "no_uid": "missing required arguments: folder_uid",
                "bad_force_start": "argument 'force_deletion' is of type ",
                "bad_force_middle": " and we were unable to convert to bool: ",
                "bad_force_detail": "The value 'maybe' is not a valid boolean.",
            })

            self.assertRecap(recap, out, err, ok=9, changed=0, failed=0, ignored=7)
            self.assertNothingSent(server)
        finally:
            server.cleanup()

    def test_bad_folder_uid_fails_and_deletes_nothing(self):
        """A padded, empty, blank, or null folder_uid fails, also with force, and no delete request is sent."""
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_bad_uid.yml", expected={"msgs": [
                "Could not delete folder: The folder_uid 'EMPTY_FOLDER_UID ' has leading or trailing whitespace.",
                "Could not delete folder: The folder_uid ' EMPTY_FOLDER_UID' has leading or trailing whitespace.",
                "Could not delete folder: The folder_uid 'TREE_FOLDER_UID\\n' has leading or trailing whitespace.",
                "Could not delete folder: The folder_uid 'NO_SUCH_FOLDER_UID ' has leading or trailing whitespace.",
                "Could not delete folder: The folder_uid is blank.",
                "Could not delete folder: The folder_uid is blank.",
                NULL_MESSAGE.format("folder_uid"),
            ]})

            self.assertRecap(recap, out, err, ok=8, changed=0, failed=0, ignored=7)
            self.assertEqual(server.calls("delete_folder"), [])
            self.assertEqual(server.calls("get_secret"), [])
            self.assertFolders(server, ALL_FOLDER_UIDS)
            self.assertRecords(server, ALL_RECORD_UIDS)
        finally:
            server.cleanup()

    def test_list_as_folder_uid_fails_and_deletes_nothing(self):
        """
        A list of real folder UIDs, with force_deletion, is not a folder UID. Before the option check, Ansible turned it
        into the string "['A', 'B']", and the task silently reported "not found". Now the task fails on the
        option check, before any request, and nothing is deleted.
        """
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_list_uid.yml",
                                   expected={"msg": NOT_A_STRING_MESSAGE.format("a list")})

            self.assertRecap(recap, out, err, ok=2, changed=0, failed=0, ignored=1)
            self.assertNothingSent(server)
        finally:
            server.cleanup()

    def test_null_options_fail_before_any_request(self):
        """
        Every option set to null, as a YAML null, a tilde, or a variable with no value, fails before any request.
        A null force_deletion must never mean "not forced" or "forced": the delete of a folder that is not empty
        with a null force_deletion fails on the option, and nothing is deleted. A null option is reported before
        the old option name force.
        """
        null_uid, null_force = NULL_MESSAGE.format("folder_uid"), NULL_MESSAGE.format("force_deletion")
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_null_options.yml", expected={"msgs": [
                null_uid, null_force, null_force, null_uid + " " + null_force, null_uid, null_force, null_uid]})

            self.assertRecap(recap, out, err, ok=8, changed=0, failed=0, ignored=7)
            self.assertNothingSent(server)
        finally:
            server.cleanup()

    def test_folder_uid_of_another_type_fails_but_a_quoted_number_works(self):
        """
        A YAML list, dictionary, boolean, number, or date fails on the option check, before any request. The
        unquoted 0012 shows why a number is refused: YAML reads it as 10, a different UID. The same digits in
        quotes are a string, and the folder with that UID is deleted.
        """
        folders = FOLDERS + [{"uid": "12345", "name": "Numbered", "parent": SHARED_FOLDER_UID}]
        server = FakeKeeperServer(folders=folders, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_uid_types.yml", expected={"msgs": [
                NOT_A_STRING_MESSAGE.format("a list"), NOT_A_STRING_MESSAGE.format("a dictionary"),
                NOT_A_STRING_MESSAGE.format("a boolean (True)"), NOT_A_STRING_MESSAGE.format("a boolean (False)"),
                NOT_A_STRING_MESSAGE.format("a number (1.1)"), NOT_A_STRING_MESSAGE.format("a number (12345)"),
                NOT_A_STRING_MESSAGE.format("a number (10)"), NOT_A_STRING_MESSAGE.format("a date (2026-09-29)")]})

            self.assertRecap(recap, out, err, ok=11, changed=1, failed=0, ignored=8)
            self.assertDeleteRequests(server, [(["12345"], False)])
            self.assertEqual([c["path"] for c in server.calls()], ["get_folders", "get_secret", "delete_folder"],
                             "only the quoted UID may reach the server")
            self.assertFolders(server, ALL_FOLDER_UIDS)
            self.assertRecords(server, ALL_RECORD_UIDS)
        finally:
            server.cleanup()


class KeeperDeleteFolderFailureHandlingPlaybookTest(_PlaybookTestCase):
    """
    The plugin returns a failure instead of raising it. So rescue, failed_when, and ignore_errors work on a failed
    delete, and each one sees the exact message.
    """

    def test_rescue_and_failed_when_work_on_a_failed_delete(self):
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_rescue.yml", expected={
                "record_not_empty": WEB_NOT_EMPTY,
                "tree_not_empty": TREE_NOT_EMPTY,
                "parent_not_empty": APPS_NOT_EMPTY,
                "forse_before": _unsupported_before("forse") + SUPPORTED_MARKER,
            })

            self.assertRecap(recap, out, err, ok=6, changed=0, failed=0, rescued=1, ignored=1, skipped=0)
            self.assertEqual(server.calls("delete_folder"), [])
            self.assertEqual(len(server.calls("get_folders")), 3, "the typo task must not reach the server")
            self.assertFolders(server, ALL_FOLDER_UIDS)
            self.assertRecords(server, ALL_RECORD_UIDS)
        finally:
            server.cleanup()


class KeeperDeleteFolderStopsThePlayTest(_PlaybookTestCase):
    """
    A task that fails without ignore_errors makes ansible-playbook exit non-zero, and AnsibleTestFramework then
    returns {} instead of the PLAY RECAP counts. The error message is still in stdout and stderr.
    """

    def test_failure_without_ignore_errors_stops_the_play(self):
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_stop.yml")

            self.assertEqual(recap, {}, "the failed delete must stop the play")
            self.assertIn("Could not delete folder: The folder ", out + err)
            self.assertIn("(UID RECORD_FOLDER_UID) is not empty. It contains 1 record(s) and 0 subfolder(s). "
                          "Set force_deletion to true to delete the folder and everything in it.", out + err)
            self.assertEqual(server.calls("delete_folder"), [], "the second task must not run")
            self.assertIsNotNone(server.folder(EMPTY_FOLDER_UID))
            self.assertFolders(server, ALL_FOLDER_UIDS)
            self.assertRecords(server, ALL_RECORD_UIDS)
        finally:
            server.cleanup()


class KeeperDeleteFolderExamplesPlaybookTest(_PlaybookTestCase):
    """The patterns that the module EXAMPLES show to playbook authors must work as documented."""

    def test_idempotent_pattern_runs_twice_in_one_play(self):
        """The first run deletes the folder. The second run skips the delete cleanly: no failure, not changed."""
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_idempotent.yml",
                                   expected={"second_lookup": _lookup_not_found_msg("Temporary")})

            self.assertRecap(recap, out, err, ok=4, changed=1, failed=0, skipped=1, ignored=0)
            self.assertDeleteRequests(server, [([TEMP_FOLDER_UID], False)])
            self.assertIsNone(server.folder(TEMP_FOLDER_UID))
            self.assertFolders(server, [uid for uid in ALL_FOLDER_UIDS if uid != TEMP_FOLDER_UID])
        finally:
            server.cleanup()

    def test_idempotent_pattern_does_not_hide_other_lookup_failures(self):
        """
        The failed_when of the documented pattern ignores only the "No folder named" failure. Two folders with the
        same name, or a network error, must still fail the lookup, so that the play does not report success while it
        deletes nothing.
        """
        duplicate = {"uid": "TEMP_FOLDER_2_UID", "name": "Temporary", "parent": SHARED_FOLDER_UID}
        cases = [
            ("two folders with the same name", dict(folders=FOLDERS + [duplicate], records=RECORDS),
             'Found 2 folders named "Temporary"'),
            ("a network error", dict(folders=FOLDERS, records=RECORDS, fail={"get_folders": "Connection aborted"}),
             "Cannot get folders: Connection aborted"),
        ]
        for name, server_args, expected_text in cases:
            with self.subTest(case=name):
                server = FakeKeeperServer(**server_args)
                try:
                    recap, out, err = _run(server, "keeper_delete_folder_idempotent_errors.yml",
                                           expected_text=expected_text)
                    # The ignored lookup and the assert are ok. The delete is skipped.
                    self.assertRecap(recap, out, err, ok=2, changed=0, failed=0, skipped=1, ignored=1)
                    self.assertDeleteRequests(server, [])
                    self.assertIsNotNone(server.folder(TEMP_FOLDER_UID))
                finally:
                    server.cleanup()

    def test_loop_deletes_each_folder_once(self):
        """
        Each loop item sees the folders as the item before it left them, so a parent whose only subfolder was
        just deleted is empty. The second loop sends no delete request, and each item says that nothing was
        deleted.
        """
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            recap, out, err = _run(server, "keeper_delete_folder_loop.yml", expected={"second_loop_msgs": [
                _not_found_msg(EMPTY_FOLDER_UID), _not_found_msg(PARENT_CHILD_UID), _not_found_msg(PARENT_FOLDER_UID)]})

            self.assertRecap(recap, out, err, ok=3, changed=1, failed=0)
            self.assertDeleteRequests(server, [([EMPTY_FOLDER_UID], False), ([PARENT_CHILD_UID], False),
                                               ([PARENT_FOLDER_UID], False)])
            self.assertFolders(server, [uid for uid in ALL_FOLDER_UIDS
                                        if uid not in (EMPTY_FOLDER_UID, PARENT_CHILD_UID, PARENT_FOLDER_UID)])
            self.assertRecords(server, ALL_RECORD_UIDS)
        finally:
            server.cleanup()


VAULT_PASSWORD = "keeper-delete-folder-test-only"
COMPONENT_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
RUNTIME_YML = os.path.join(COMPONENT_DIR, "ansible_galaxy", "keepersecurity", "keeper_secrets_manager", "meta",
                           "runtime.yml")
PLUGINS_DIR = os.path.dirname(os.path.realpath(keeper_secrets_manager_ansible.plugins.__file__))
COLLECTION = ("keepersecurity", "keeper_secrets_manager")


@contextlib.contextmanager
def _environment(name, value):
    # AnsibleTestFramework imports ansible again for each run, so an ansible setting in the environment takes
    # effect for the run.
    saved = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = saved


@contextlib.contextmanager
def _collection_path():
    """
    A collections path with the collection keepersecurity.keeper_secrets_manager: the real meta/runtime.yml, which
    defines the action group, and the plugins of the package as symlinks. So Ansible runs the modules by their full
    collection names and gives them the group module_defaults, as it does for the installed collection.
    """
    root = tempfile.mkdtemp(prefix="ksm_delete_folder_collections_")
    collection = os.path.join(root, "ansible_collections", *COLLECTION)
    plugins = os.path.join(collection, "plugins")
    try:
        os.makedirs(os.path.join(collection, "meta"))
        os.makedirs(plugins)
        shutil.copyfile(RUNTIME_YML, os.path.join(collection, "meta", "runtime.yml"))
        for name in ("action", "modules"):
            os.symlink(os.path.join(PLUGINS_DIR, name), os.path.join(plugins, name))
        with _environment("ANSIBLE_COLLECTIONS_PATH", root):
            yield
    finally:
        # Remove the symlinks first, so that nothing can ever delete the real plugin files of the package.
        for name in ("action", "modules"):
            link = os.path.join(plugins, name)
            if os.path.islink(link):
                os.unlink(link)
        shutil.rmtree(root)


class KeeperDeleteFolderVaultPlaybookTest(_PlaybookTestCase):

    def test_vault_encrypted_folder_uid_is_accepted(self):
        """
        A folder_uid that Ansible Vault encrypts, written in the task, is a string value. The option check must
        accept it, and the module must use the decrypted UID: the empty folder is deleted, and the not-empty check
        runs on the other folder.
        """
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        fd, password_file = tempfile.mkstemp(prefix="ksm_delete_folder_vault_", suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write(VAULT_PASSWORD + "\n")
        try:
            with _environment("ANSIBLE_VAULT_PASSWORD_FILE", password_file):
                recap, out, err = _run(server, "keeper_delete_folder_vault_uid.yml",
                                       expected={"tree_not_empty": TREE_NOT_EMPTY})

            self.assertRecap(recap, out, err, ok=3, changed=1, failed=0, ignored=1)
            self.assertDeleteRequests(server, [([EMPTY_FOLDER_UID], False)])
            self.assertIsNone(server.folder(EMPTY_FOLDER_UID))
            self.assertFolders(server, [uid for uid in ALL_FOLDER_UIDS if uid != EMPTY_FOLDER_UID])
            self.assertRecords(server, ALL_RECORD_UIDS)
        finally:
            os.remove(password_file)
            server.cleanup()


class KeeperDeleteFolderGroupDefaultsPlaybookTest(_PlaybookTestCase):
    """
    module_defaults for the action group of this collection, end to end, with the modules run by their full
    collection names. The two tests are about the option that deletes the contents of a folder.
    """

    def test_group_default_force_does_not_force_a_delete(self):
        """
        keeper_copy has an option named force, and a group default for it reaches every module of the group. It
        must never delete the contents of a folder: the folder that is not empty is still there with its records,
        also for a task that writes force itself, and the empty folder is deleted with force_deletion False.
        """
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            with _collection_path():
                recap, out, err = _run(server, "keeper_delete_folder_group_force.yml",
                                       expected={"tree_not_empty": TREE_NOT_EMPTY})

            self.assertRecap(recap, out, err, ok=4, changed=1, failed=0, ignored=2)
            self.assertDeleteRequests(server, [([EMPTY_FOLDER_UID], False)])
            self.assertFolders(server, [uid for uid in ALL_FOLDER_UIDS if uid != EMPTY_FOLDER_UID])
            self.assertRecords(server, ALL_RECORD_UIDS)
        finally:
            server.cleanup()
        self.assertTrue(os.path.isdir(os.path.join(PLUGINS_DIR, "action")), "the real plugin dir must be untouched")

    def test_group_default_force_deletion_applies(self):
        """
        The module has force_deletion, so a group default for it applies to each keeper_delete_folder task, as
        module_defaults does for any option of any module. This test documents that: the folder that is not empty
        is deleted with everything in it, and a task that sets force_deletion: no is not forced.
        """
        server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
        try:
            with _collection_path():
                recap, out, err = _run(server, "keeper_delete_folder_group_force_deletion.yml",
                                       expected={"web_not_empty": WEB_NOT_EMPTY})

            self.assertRecap(recap, out, err, ok=3, changed=1, failed=0, ignored=1)
            self.assertDeleteRequests(server, [([TREE_FOLDER_UID], True)])
            self.assertFolders(server, [uid for uid in ALL_FOLDER_UIDS if uid not in (TREE_FOLDER_UID, TREE_CHILD_UID)])
            self.assertRecords(server, [uid for uid in ALL_RECORD_UIDS
                                        if uid not in ("RECORD_IN_DATABASES", "RECORD_IN_PRODUCTION")])
        finally:
            server.cleanup()
        self.assertTrue(os.path.isdir(os.path.join(PLUGINS_DIR, "action")), "the real plugin dir must be untouched")


if __name__ == "__main__":
    unittest.main()
