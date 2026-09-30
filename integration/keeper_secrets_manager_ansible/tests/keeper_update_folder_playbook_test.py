import contextlib
import importlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import keeper_secrets_manager_ansible
from .ansible_test_framework import AnsibleTestFramework
from .folder_fake_server import FakeKeeperServer


SHARED_FOLDER_UID = "SHARED_FOLDER_UID"
FOLDER_UID = "FOLDER_UID"
SIBLING_UID = "SIBLING_UID"
MISSING_FOLDER_UID = "MISSING_FOLDER_UID"
NOT_SHARED_FOLDER_UID = "NOT_SHARED_FOLDER_UID"

UNICODE_NAME = "Frankfurt am Main \u00e4\u00f6\u00fc\u00df \u6570\u636e \U0001F512"


def _folders():
    """
    A shared folder with two subfolders: Infrastructure/Staging (the folder to rename) and Infrastructure/Databases.
    """
    return [
        {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
        {"uid": FOLDER_UID, "name": "Staging", "parent": SHARED_FOLDER_UID},
        {"uid": SIBLING_UID, "name": "Databases", "parent": SHARED_FOLDER_UID},
    ]


def _normalized(text):
    """The output with each run of whitespace made one space, so a message that Ansible wraps still matches."""
    return " ".join(text.split())


class _RecordingDisplay:
    """
    Stands in for the package's Display object. Every call goes to the real Display, and each warning is also written
    to a file, one JSON string per line. A forked worker process can write to that file, so the test can read the
    warnings after the run, on every ansible-core version.
    """

    def __init__(self, display, path):
        self._display = display
        self._path = path

    def warning(self, msg, *args, **kwargs):
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(msg) + "\n")
        return self._display.warning(msg, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._display, name)


@contextlib.contextmanager
def _current_ansible_objects(warnings_path):
    """
    For the length of one playbook run, give keeper_secrets_manager_ansible the AnsibleError class and the Display
    object of the ansible modules that the run uses.

    AnsibleTestFramework unloads every ansible module after a run, but not keeper_secrets_manager_ansible, so the
    names that the package imported from ansible stay bound to the modules of an earlier run. In a later run:
    - A warning sent through the old display is written straight to the worker's stderr, and a warning text that an
      earlier run already showed is dropped as a duplicate.
    - An AnsibleError that the package raises (the KeeperAnsible constructor raises one for a config error) is an
      instance of the old class. The new run's error handling recurses in str() on it, and the worker dies ("A
      worker was found in a dead state") instead of failing the task with the message.
    A real ansible-playbook run loads the ansible modules once, so neither problem happens there. The display is
    also wrapped, so that the test can read the warnings of the package (see _RecordingDisplay).
    """
    errors = importlib.import_module("ansible.errors")
    display_module = importlib.import_module("ansible.utils.display")
    display = _RecordingDisplay(display_module.Display(), warnings_path)
    with patch.object(keeper_secrets_manager_ansible, "AnsibleError", errors.AnsibleError), \
            patch.object(keeper_secrets_manager_ansible, "display", display):
        yield


def _worker_display_reaches_the_output():
    """
    ansible-core 2.13 and later send the display of a worker process to the main process, which prints it. ansible-core
    2.12 writes it straight to the worker's own stdout and stderr. In a terminal it is shown the same way, but the test
    framework captures only the main process, so there a warning of an action plugin is not in the captured output.
    """
    return hasattr(importlib.import_module("ansible.utils.display").Display, "set_queue")


class _PlaybookTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # The first playbook run in a process must import the ansible modules itself, after AnsibleTestFramework sets
        # the plugin paths. A test module that imports a plugin class at the top (keeper_redact_test.py, and
        # keeper_update_folder_test.py) already loaded ansible's plugin loader with the default paths, and then the
        # run fails with "couldn't resolve module/action". The full suite hides this only because
        # keeper_ansible_test.py runs first and unloads the ansible modules in its tearDownClass. Do the same here, so
        # these tests pass in any order and in any subset.
        for module in list(sys.modules):
            if module.startswith("ansible"):
                sys.modules.pop(module, None)

    def run_playbook(self, server, playbook, variables):
        """Run the playbook against the server. The warnings of the package are in self.warnings after the run."""
        framework = AnsibleTestFramework(playbook=playbook, vars=variables)
        fd, warnings_path = tempfile.mkstemp(prefix="ksm_update_folder_warnings_", suffix=".jsonl")
        os.close(fd)
        try:
            with server.patch(), _current_ansible_objects(warnings_path):
                result = framework.run()
            with open(warnings_path, encoding="utf-8") as fh:
                self.warnings = [json.loads(line) for line in fh if line.strip()]
        finally:
            os.remove(warnings_path)
        return result

    def assert_recap(self, result, out, err, ok, changed=0, ignored=0):
        failures = [line for line in (out + err).splitlines()
                    if "FAILED!" in line or "fatal:" in line or "[ERROR]" in line or "ERROR!" in line]
        detail = "\n" + "\n".join(failures[-20:])
        self.assertEqual(result.get("failed"), 0, "a task failed, or an assert in the playbook failed:" + detail)
        self.assertEqual(result.get("ok"), ok, "not every task ran:" + detail)
        self.assertEqual(result.get("changed"), changed, "wrong number of changed tasks:" + detail)
        self.assertEqual(result.get("ignored"), ignored, "wrong number of ignored failures:" + detail)
        self.assertEqual(result.get("skipped"), 0, detail)
        self.assertEqual(result.get("unreachable"), 0, detail)

    @staticmethod
    def paths(server):
        return [c["path"] for c in server.calls()]


class KeeperUpdateFolderPlaybookTest(_PlaybookTestCase):
    """
    keeper_update_folder in real playbooks, against FakeKeeperServer. Only the network is fake: the real SDK decrypts
    the folder keys and names, and encrypts the new name, and the server decrypts it again. Each task runs in its own
    worker process and sees what the tasks before it changed.
    """

    def test_rename_then_same_rename_again(self):
        """
        The QA steps: a folder inside a shared folder is renamed with its UID and a new name (changed), then the same
        task runs again (not changed). Exactly one update reaches the server, with the new name, and a lookup by the
        new name in the next task finds the folder.
        """
        server = FakeKeeperServer(folders=_folders())
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder.yml", {
                "shared_folder_uid": SHARED_FOLDER_UID,
                "folder_uid": FOLDER_UID,
            })

            # 2 renames, 2 lookups, and the assert. The lookup by the old name fails on purpose.
            self.assert_recap(result, out, err, ok=5, changed=1, ignored=1)
            self.assertEqual(self.warnings, [], "a rename into a free name must not warn")
            self.assertEqual(server.calls("update_folder"),
                             [{"path": "update_folder", "folder_uid": FOLDER_UID, "folder_name": "Production"}],
                             "exactly one update, the first rename, may reach the server")
            self.assertEqual(server.folder(FOLDER_UID),
                             {"uid": FOLDER_UID, "name": "Production", "parent": SHARED_FOLDER_UID},
                             "the folder must have the new name, and the same parent")
            self.assertEqual(server.folder(SIBLING_UID)["name"], "Databases", "only the named folder may change")
            self.assertEqual(server.folder(SHARED_FOLDER_UID)["name"], "Infrastructure")

            paths = self.paths(server)
            # The first rename reads the folders once and sends the update with that list: no second get_folders.
            # The second rename starts with a get_folders and sends nothing more.
            self.assertEqual(paths[:3], ["get_folders", "update_folder", "get_folders"], paths)
            self.assertEqual(paths.count("update_folder"), 1, paths)
            self.assertEqual(sorted(set(paths)), ["get_folders", "update_folder"],
                             "a rename must not read records, or create or delete folders")
        finally:
            server.cleanup()

    def test_check_mode_reports_the_rename_but_sends_nothing(self):
        """
        With check_mode on the task, and on the play, the task reports what a real run would do, and runs the same
        checks (a missing folder still fails), but no update reaches the server and the name does not change.
        """
        server = FakeKeeperServer(folders=_folders())
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_check_mode.yml", {
                "shared_folder_uid": SHARED_FOLDER_UID,
                "folder_uid": FOLDER_UID,
                "missing_folder_uid": MISSING_FOLDER_UID,
            })

            # Play 1: 3 renames in check mode (the missing folder fails on purpose), a lookup, and the assert.
            # Play 2: a rename with check mode set on the play, and the assert.
            self.assert_recap(result, out, err, ok=7, changed=2, ignored=1)
            self.assertEqual(server.calls("update_folder"), [], "check mode must not send an update")
            self.assertEqual(server.folders(), _folders(), "check mode must not change any folder")
        finally:
            server.cleanup()

    def test_missing_folder_fails_with_clear_error(self):
        """
        A folder UID that does not exist, and one that is not shared to the KSM application (the server does not
        return it to the application), both fail with a message that names the UID. Nothing is changed.
        """
        server = FakeKeeperServer(folders=_folders())
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_not_found.yml", {
                "missing_folder_uid": MISSING_FOLDER_UID,
                "not_shared_folder_uid": NOT_SHARED_FOLDER_UID,
            })

            self.assert_recap(result, out, err, ok=3, changed=0, ignored=2)
            self.assertEqual(self.paths(server), ["get_folders", "get_folders"],
                             "each task may read the folders once, and send nothing else")
            self.assertEqual(server.folders(), _folders())
        finally:
            server.cleanup()

    def test_missing_folder_without_ignore_errors_stops_the_play(self):
        """
        With no ignore_errors, the failure stops the playbook: ansible-playbook exits non-zero, so the framework
        returns no recap ({}), and the message is in the output. The next task, a rename, never runs.
        """
        server = FakeKeeperServer(folders=_folders())
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_not_found_fails.yml", {
                "missing_folder_uid": MISSING_FOLDER_UID,
                "folder_uid": FOLDER_UID,
            })

            self.assertEqual(result, {}, "expected the task to fail, not a normal PLAY RECAP")
            self.assertIn("Could not update folder: The folder MISSING_FOLDER_UID was not found, or it is not shared "
                          "to this KSM application.", _normalized(out + err))
            self.assertEqual(self.paths(server), ["get_folders"], "the task after the failure must not run")
            self.assertEqual(server.folder(FOLDER_UID)["name"], "Staging")
        finally:
            server.cleanup()

    def test_wrong_options_fail_before_any_request(self):
        """
        A misspelled option, an option of another module, or a missing option fails the task before KeeperAnsible
        connects. The server receives no request at all, not even get_folders.
        """
        server = FakeKeeperServer(folders=_folders())
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_bad_options.yml", {
                "folder_uid": FOLDER_UID,
            })

            self.assert_recap(result, out, err, ok=5, changed=0, ignored=4)
            self.assertEqual(server.calls(), [], "a task with wrong options must not reach the server")
            self.assertEqual(server.folders(), _folders())
        finally:
            server.cleanup()

    def test_blank_or_padded_values_fail_before_any_request(self):
        """
        A blank or empty new name, an empty UID, and a UID with a leading space or a trailing newline all fail with
        their own message. The padded UID of an existing folder is not stripped and used, and is not reported as "not
        found". None of these tasks sends a request.
        """
        server = FakeKeeperServer(folders=_folders())
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_bad_values.yml", {
                "folder_uid": FOLDER_UID,
            })

            self.assert_recap(result, out, err, ok=6, changed=0, ignored=5)
            self.assertEqual(server.calls(), [], "a blank or padded value must fail before any request")
            self.assertEqual(server.folders(), _folders())
        finally:
            server.cleanup()

    def test_server_rejects_the_update(self):
        """The server refuses the update: the task fails with the folder path, UID, and the server's error."""
        server = FakeKeeperServer(folders=_folders(), fail={"update_folder": "access denied"})
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_server_error.yml", {
                "folder_uid": FOLDER_UID,
                "expected": {"msg": 'Could not update folder: Cannot rename the folder "Infrastructure/Staging" '
                                    '(UID FOLDER_UID): access denied'},
            })

            self.assert_recap(result, out, err, ok=2, changed=0, ignored=1)
            self.assertEqual(self.paths(server), ["get_folders", "update_folder"],
                             "the update must reach the server once, and must not be retried")
            self.assertEqual(server.calls("update_folder"), [{"path": "update_folder", "folder_uid": FOLDER_UID}],
                             "the refused request must be for the named folder")
            self.assertEqual(server.folder(FOLDER_UID)["name"], "Staging")
        finally:
            server.cleanup()

    def test_server_fails_to_list_folders(self):
        """The folder list cannot be read: the task fails with "Cannot get folders", and no update is sent."""
        server = FakeKeeperServer(folders=_folders(), fail={"get_folders": "throttled"})
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_server_error.yml", {
                "folder_uid": FOLDER_UID,
                "expected": {"msg": "Could not update folder: Cannot get folders: throttled"},
            })

            self.assert_recap(result, out, err, ok=2, changed=0, ignored=1)
            self.assertEqual(self.paths(server), ["get_folders"])
            self.assertEqual(server.folder(FOLDER_UID)["name"], "Staging")
        finally:
            server.cleanup()

    def test_names_reach_the_server_exactly(self):
        """
        Through YAML, Jinja, the SDK's encryption, and the server's decryption, the new name arrives exactly as the
        playbook wrote it: a case-only change, a Unicode name on a deep subfolder, a name with "/", a clean name for a
        folder whose current name ends with a space, a name with a newline and a tab inside, a quoted number (the
        string "2026"), and a shared folder. The same Unicode name again sends nothing. A lookup by the new path
        finds the folder.
        """
        server = FakeKeeperServer(folders=[
            {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
            {"uid": FOLDER_UID, "name": "Staging", "parent": SHARED_FOLDER_UID},
            {"uid": "MIDDLE_UID", "name": "EU", "parent": FOLDER_UID},
            {"uid": "DEEP_UID", "name": "Frankfurt", "parent": "MIDDLE_UID"},
            {"uid": "REPORTS_UID", "name": "Reports ", "parent": SHARED_FOLDER_UID},
            {"uid": "NOTES_UID", "name": "Notes", "parent": SHARED_FOLDER_UID},
            {"uid": "YEAR_UID", "name": "2025", "parent": SHARED_FOLDER_UID},
        ])
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_names.yml", {
                "shared_folder_uid": SHARED_FOLDER_UID,
                "folder_uid": FOLDER_UID,
                "middle_folder_uid": "MIDDLE_UID",
                "deep_folder_uid": "DEEP_UID",
                "reports_folder_uid": "REPORTS_UID",
                "notes_folder_uid": "NOTES_UID",
                "year_folder_uid": "YEAR_UID",
            })

            self.assert_recap(result, out, err, ok=10, changed=7)
            self.assertEqual(
                [(c["folder_uid"], c["folder_name"]) for c in server.calls("update_folder")],
                [
                    (FOLDER_UID, "staging"),
                    ("DEEP_UID", UNICODE_NAME),
                    ("MIDDLE_UID", "EU/West"),
                    ("REPORTS_UID", "Reports"),
                    ("NOTES_UID", "Line 1\nLine 2\tEnd"),
                    ("YEAR_UID", "2026"),
                    (SHARED_FOLDER_UID, "Infrastructure 2026"),
                ])
            self.assertIsInstance(server.calls("update_folder")[5]["folder_name"], str,
                                  "a quoted number must reach the server as a string name, not a JSON number")
            self.assertEqual({f["uid"]: f["name"] for f in server.folders()}, {
                SHARED_FOLDER_UID: "Infrastructure 2026",
                FOLDER_UID: "staging",
                "MIDDLE_UID": "EU/West",
                "DEEP_UID": UNICODE_NAME,
                "REPORTS_UID": "Reports",
                "NOTES_UID": "Line 1\nLine 2\tEnd",
                "YEAR_UID": "2026",
            })
        finally:
            server.cleanup()

    def test_rename_to_the_name_of_a_sibling_warns_and_renames(self):
        """
        The parent already has a folder with the new name. The rename still happens, and the playbook output has a
        warning that names the folder and the sibling. The next lookup of that name fails, as the warning says. In the
        warning, a double quote or a newline inside the name is shown as a JSON escape.
        """
        server = FakeKeeperServer(folders=[
            {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
            {"uid": FOLDER_UID, "name": "Staging", "parent": SHARED_FOLDER_UID},
            {"uid": "PRODUCTION_SIBLING_UID", "name": "Production", "parent": SHARED_FOLDER_UID},
            {"uid": "QUOTE_FOLDER_UID", "name": "Old", "parent": SHARED_FOLDER_UID},
            {"uid": "QUOTE_SIBLING_UID", "name": 'Prod "EU"', "parent": SHARED_FOLDER_UID},
            {"uid": "NEWLINE_FOLDER_UID", "name": "Older", "parent": SHARED_FOLDER_UID},
            {"uid": "NEWLINE_SIBLING_UID", "name": "Prod\nEU", "parent": SHARED_FOLDER_UID},
        ])
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_same_name.yml", {
                "shared_folder_uid": SHARED_FOLDER_UID,
                "folder_uid": FOLDER_UID,
                "quote_folder_uid": "QUOTE_FOLDER_UID",
                "newline_folder_uid": "NEWLINE_FOLDER_UID",
            })

            self.assert_recap(result, out, err, ok=5, changed=3, ignored=1)
            self.assertEqual([(c["folder_uid"], c["folder_name"]) for c in server.calls("update_folder")], [
                (FOLDER_UID, "Production"),
                ("QUOTE_FOLDER_UID", 'Prod "EU"'),
                ("NEWLINE_FOLDER_UID", "Prod\nEU"),
            ])
            after = " After the rename, a lookup of this name fails because the name is not unique."
            expected = [
                'The parent of the folder "Infrastructure/Staging" (UID FOLDER_UID) already has a folder named '
                '"Production" (PRODUCTION_SIBLING_UID).' + after,
                'The parent of the folder "Infrastructure/Old" (UID QUOTE_FOLDER_UID) already has a folder named '
                '"Prod \\"EU\\"" (QUOTE_SIBLING_UID).' + after,
                'The parent of the folder "Infrastructure/Older" (UID NEWLINE_FOLDER_UID) already has a folder named '
                '"Prod\\nEU" (NEWLINE_SIBLING_UID).' + after,
            ]
            self.assertEqual(self.warnings, expected, "each rename must show exactly its own warning")
            if _worker_display_reaches_the_output():
                output = _normalized(out + err)
                for warning in expected:
                    self.assertIn("[WARNING]: " + warning, output)
        finally:
            server.cleanup()

    def test_padded_new_names_fail_before_any_request_and_inside_whitespace_works(self):
        """
        A new name with whitespace at the start or the end fails before any request: a YAML block scalar (|) or
        folded scalar (>), which keep the newline at the end, a space, a tab, a carriage return, a Windows line end,
        and a variable whose value ends with a newline. The message shows the name with repr(). A block scalar with
        strip chomping (|-), a newline or a tab inside the name, and a clean name for a folder whose current name ends
        with a space are renamed exactly.
        """
        server = FakeKeeperServer(folders=_folders() + [
            {"uid": "REPORTS_UID", "name": "Reports", "parent": SHARED_FOLDER_UID},
            {"uid": "ARCHIVE_UID", "name": "Archive ", "parent": SHARED_FOLDER_UID},
        ])
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_padded_names.yml", {
                "folder_uid": FOLDER_UID,
                "sibling_uid": SIBLING_UID,
                "reports_uid": "REPORTS_UID",
                "archive_uid": "ARCHIVE_UID",
            })

            # 8 failures on purpose, 4 renames, and the assert.
            self.assert_recap(result, out, err, ok=13, changed=4, ignored=8)
            self.assertEqual(self.paths(server), ["get_folders", "update_folder"] * 4,
                             "a padded name must fail before any request; only the 4 renames may send requests")
            self.assertEqual([(c["folder_uid"], c["folder_name"]) for c in server.calls("update_folder")], [
                (FOLDER_UID, "Production"),
                (SIBLING_UID, "Prod\nEU"),
                ("REPORTS_UID", "Prod\tEU"),
                ("ARCHIVE_UID", "Archive"),
            ])
        finally:
            server.cleanup()

    def test_null_options_fail_before_any_request(self):
        """
        An option set to null, directly or from a variable with no value, fails the task at the option check, with a
        message that says to give it a value or leave it out. With default(omit) for an undefined variable, or
        default(omit, true) for a variable defined as null, a required option is reported as missing. No task sends
        a request.
        """
        server = FakeKeeperServer(folders=_folders())
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_null_options.yml", {
                "folder_uid": FOLDER_UID,
            })

            self.assert_recap(result, out, err, ok=9, changed=0, ignored=8)
            self.assertEqual(server.calls(), [], "a null option must fail before any request")
            self.assertEqual(server.folders(), _folders())
        finally:
            server.cleanup()

    def test_values_that_are_not_strings_fail_and_quoted_values_work(self):
        """
        A list (from a variable or in YAML), a dictionary, a YAML boolean, float, integer, date, or date and time as the
        name, and a list, boolean, float, or integer as the UID fail before any request, instead of renaming the
        folder to "['Prod', 'EU']", "True", "1.1", or a changed number: YAML makes 007 into 7, 010 into 8, 0x1F into
        31, and 1_000 into 1000. The message shows the value that YAML made. A quoted number, as the name or as the
        UID, and a number variable with the string filter are accepted as written.
        """
        folders = _folders() + [{"uid": "12345", "name": "Old Number", "parent": SHARED_FOLDER_UID}]
        server = FakeKeeperServer(folders=folders)
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_wrong_types.yml", {
                "folder_uid": FOLDER_UID,
                "sibling_uid": SIBLING_UID,
            })

            # 16 failures on purpose, 3 renames, and the assert.
            self.assert_recap(result, out, err, ok=20, changed=3, ignored=16)
            self.assertEqual(self.paths(server), ["get_folders", "update_folder"] * 3,
                             "only the 3 accepted renames may send requests")
            self.assertEqual([(c["folder_uid"], c["folder_name"]) for c in server.calls("update_folder")],
                             [(FOLDER_UID, "2024"), ("12345", "007"), (SIBLING_UID, "2025")])
        finally:
            server.cleanup()

    def test_failed_when_and_rescue_handle_a_failed_rename(self):
        """
        The plugin returns its failures instead of raising them, so the playbook can handle them: failed_when: false
        and a failed_when that reads the message keep the task ok, and a rescue gets the message in
        ansible_failed_result. This works for a failure of the rename and for a failure of the option check.
        """
        server = FakeKeeperServer(folders=_folders())
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_failure_handling.yml", {
                "folder_uid": FOLDER_UID,
                "missing_folder_uid": MISSING_FOLDER_UID,
            })

            detail = "\n".join(line for line in (out + err).splitlines() if "FAILED!" in line or "fatal:" in line)
            self.assertEqual(result.get("rescued"), 2, "both blocks must go to their rescue:\n" + detail)
            self.assertEqual(result.get("failed"), 0, detail)
            self.assertEqual(result.get("ignored"), 0, detail)
            # 3 tasks with failed_when, 2 rescue tasks, and the assert.
            self.assertEqual(result.get("ok"), 6, detail)
            self.assertEqual(result.get("changed"), 0, detail)
            self.assertEqual(self.paths(server), ["get_folders", "get_folders", "get_folders"],
                             "the 3 renames of the missing folder read the folders, and the option failures send "
                             "nothing")
            self.assertEqual(server.folders(), _folders())
        finally:
            server.cleanup()


class KeeperUpdateFolderPlaybookFilesTest(unittest.TestCase):
    """
    A static check of the playbooks of these tests. If YAML reads an assert condition as a mapping (for example an
    unquoted line that has ": " in it), ansible-core 2.19 and later fail the task, but earlier versions treat the
    mapping as true, and the assert passes without checking anything.
    """

    def test_every_condition_is_a_string(self):
        import glob
        import yaml

        directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), "ansible_example", "playbooks")
        playbooks = sorted(glob.glob(os.path.join(directory, "keeper_update_folder*.yml")) +
                           glob.glob(os.path.join(directory, "keeper_folder_vault.yml")))
        self.assertGreater(len(playbooks), 0)

        def conditions(tasks):
            for task in tasks or []:
                for key in ("block", "rescue", "always"):
                    for found in conditions(task.get(key)):
                        yield found
                if "assert" in task:
                    for condition in task["assert"]["that"]:
                        yield task.get("name"), condition
                if "failed_when" in task:
                    yield task.get("name"), task["failed_when"]

        class _Loader(yaml.SafeLoader):
            """A safe loader that reads an inline !vault value as its ciphertext text."""

        _Loader.add_constructor("!vault", lambda loader, node: loader.construct_scalar(node))

        for playbook in playbooks:
            with open(playbook, encoding="utf-8") as fh:
                plays = yaml.load(fh, Loader=_Loader)
            for play in plays:
                for name, condition in conditions(play.get("tasks")):
                    with self.subTest(playbook=os.path.basename(playbook), task=name):
                        self.assertIsInstance(condition, (str, bool), condition)


if __name__ == "__main__":
    unittest.main()
