"""
Playbook tests for keeper_get_folder, against FakeKeeperServer.

Only the network is fake. The real SDK decrypts every folder key and folder name, and ansible-playbook runs the
real action plugin, so these tests also cover the task argument handling, the result that a playbook registers,
and the failure that it sees.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

import keeper_secrets_manager_ansible.plugins

from .ansible_test_framework import AnsibleTestFramework
from .folder_fake_server import FakeKeeperServer


def setUpModule():
    # A test module that imports a plugin when it loads (keeper_redact_test.py, for example) starts ansible's plugin
    # loader with the default paths, before AnsibleTestFramework sets the plugin paths. Unload the ansible modules, so
    # the first playbook run here loads them again with the right paths, in any test order.
    for module in list(sys.modules):
        if module.startswith("ansible"):
            sys.modules.pop(module, None)


SHARED_FOLDER_UID = "SHARED_FOLDER_UID"
OTHER_SHARED_FOLDER_UID = "OTHER_SHARED_FOLDER_UID"
DATABASES_UID = "DATABASES_UID"
PRODUCTION_UID = "PRODUCTION_UID"
EU_UID = "EU_UID"
STAGING_UID = "STAGING_UID"
SLASH_UID = "SLASH_UID"
YEAR_UID = "YEAR_UID"
UNICODE_UID = "UNICODE_UID"
DUP_1_UID = "DUP_1_UID"
DUP_2_UID = "DUP_2_UID"
LEAF_UID = "LEAF_UID"

# Shared folders come before their subfolders, as the real server sends them.
FOLDERS = [
    {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
    {"uid": OTHER_SHARED_FOLDER_UID, "name": "Applications", "parent": None},
    {"uid": DATABASES_UID, "name": "Databases", "parent": SHARED_FOLDER_UID},
    {"uid": PRODUCTION_UID, "name": "Production", "parent": DATABASES_UID},
    {"uid": EU_UID, "name": "EU", "parent": PRODUCTION_UID},
    {"uid": STAGING_UID, "name": "Staging", "parent": DATABASES_UID},
    {"uid": SLASH_UID, "name": "Prod/EU", "parent": SHARED_FOLDER_UID},
    {"uid": YEAR_UID, "name": "2024", "parent": SHARED_FOLDER_UID},
    {"uid": UNICODE_UID, "name": "Données 数据库 🔐", "parent": SHARED_FOLDER_UID},
    {"uid": DUP_1_UID, "name": "Dup", "parent": OTHER_SHARED_FOLDER_UID},
    {"uid": DUP_2_UID, "name": "Dup", "parent": OTHER_SHARED_FOLDER_UID},
    {"uid": LEAF_UID, "name": "Leaf", "parent": DUP_2_UID},
]

RECORDS = [
    {"uid": "RECORD_UID", "title": "Database Login", "folder": SHARED_FOLDER_UID, "inner": DATABASES_UID},
]

VARS = {
    "shared_folder_uid": SHARED_FOLDER_UID,
    "other_shared_folder_uid": OTHER_SHARED_FOLDER_UID,
    "databases_uid": DATABASES_UID,
    "production_uid": PRODUCTION_UID,
    "eu_uid": EU_UID,
    "staging_uid": STAGING_UID,
    "slash_uid": SLASH_UID,
    "year_uid": YEAR_UID,
    "unicode_uid": UNICODE_UID,
    "dup_1_uid": DUP_1_UID,
    "dup_2_uid": DUP_2_UID,
}

RECAP = re.compile(r"localhost\s+:\s+ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)\s+skipped=(\d+)"
                   r"\s+rescued=(\d+)\s+ignored=(\d+)")


def expected_recap(ok, changed=0, failed=0, ignored=0, rescued=0):
    """The full PLAY RECAP that a test expects, in the format of AnsibleTestFramework.run()."""
    return {"ok": ok, "changed": changed, "unreachable": 0, "failed": failed, "skipped": 0, "rescued": rescued,
            "ignored": ignored}


def recap_from_text(text):
    """
    Read the PLAY RECAP counts from the playbook output. AnsibleTestFramework.run() returns {} when a task fails
    without ignore_errors, but the output still has the recap line.
    """
    match = RECAP.search(text)
    if match is None:
        return None
    names = ["ok", "changed", "unreachable", "failed", "skipped", "rescued", "ignored"]
    return dict(zip(names, (int(count) for count in match.groups())))


def in_output(message, text):
    """A message is in the output as plain text, or JSON-escaped inside a result dictionary."""
    return message in text or json.dumps(message)[1:-1] in text


def unchanged(folders):
    return [{"uid": f["uid"], "name": f["name"], "parent": f["parent"]} for f in folders]


class PlaybookRun:
    """The outcome of one playbook run, with a snapshot of the fake server taken before its cleanup."""

    def __init__(self, playbook, folders, records=None, extra_vars=None):
        server = FakeKeeperServer(folders=folders, records=records)
        try:
            with server.patch():
                self.result, self.out, self.err = AnsibleTestFramework(playbook=playbook, vars=extra_vars).run()
            self.calls = server.calls()
            self.folders = server.folders()
            self.records = server.records()
        finally:
            server.cleanup()
        self.output = self.out + self.err

    def paths(self):
        return [call["path"] for call in self.calls]


class KeeperGetFolderPlaybookTest(unittest.TestCase):
    """Successful lookups, each checked by an assert task in the playbook."""

    def test_lookups(self):
        run = PlaybookRun("keeper_get_folder.yml", FOLDERS, RECORDS, VARS)

        # 16 lookups and 1 assert task. No task fails, and no task reports a change, check mode included.
        self.assertEqual(run.result, expected_recap(ok=17), "a task failed or did not run: " + run.output)

        # Read-only: one get_folders request for each lookup, and nothing else.
        self.assertEqual(run.paths(), ["get_folders"] * 16)
        self.assertEqual(run.folders, unchanged(FOLDERS))
        self.assertEqual(run.records, RECORDS)


class KeeperGetFolderErrorsPlaybookTest(unittest.TestCase):
    """Failed lookups, with ignore_errors, and the full message checked by an assert task."""

    def test_errors(self):
        run = PlaybookRun("keeper_get_folder_errors.yml", FOLDERS, RECORDS, VARS)

        # 27 lookups that fail on purpose, and 1 assert task that checks each of them.
        self.assertEqual(run.result, expected_recap(ok=28, ignored=27), "unexpected recap: " + run.output)
        self.assertNotIn("Assertion failed", run.output)

        # A failed lookup is read-only too. The option errors fail before the request, so the count is lower.
        self.assertTrue(set(run.paths()) <= {"get_folders"}, run.paths())
        self.assertEqual(run.folders, unchanged(FOLDERS))


class KeeperGetFolderBadOptionsPlaybookTest(unittest.TestCase):
    """
    Option errors: typos, two exclusive options, a value that is not a boolean, and values that are not strings,
    also the unquoted numbers and dates that YAML reads as another type.
    """

    def test_bad_options_fail_before_any_request(self):
        run = PlaybookRun("keeper_get_folder_bad_options.yml", FOLDERS, RECORDS, VARS)

        # 11 lookups that fail on purpose, and 1 assert task.
        self.assertEqual(run.result, expected_recap(ok=12, ignored=11), "unexpected recap: " + run.output)

        # The options are checked before the connection, so the server received nothing at all.
        self.assertEqual(run.calls, [])


class KeeperGetFolderNullOptionsPlaybookTest(unittest.TestCase):
    """
    A null variable for each option: every such task fails before it sends a request. Only the last lookup, where
    default(omit, true) removes the option, reaches the server.
    """

    def test_null_options_fail_without_a_request(self):
        run = PlaybookRun("keeper_get_folder_null_options.yml", FOLDERS, RECORDS, VARS)

        # 7 lookups that fail on purpose, 1 assert task, 1 lookup that works, and 1 assert task.
        self.assertEqual(run.result, expected_recap(ok=10, ignored=7), "unexpected recap: " + run.output)
        self.assertEqual(run.paths(), ["get_folders"])


class KeeperGetFolderFailedWhenPlaybookTest(unittest.TestCase):
    """failed_when and rescue work on a failed lookup and on an option error, because the plugin returns them."""

    def test_failed_when_and_rescue(self):
        run = PlaybookRun("keeper_get_folder_failed_when.yml", FOLDERS, RECORDS, VARS)

        # 4 lookups that failed_when turns into ok, 1 rescued lookup, 1 rescue task, and 1 assert task. The task
        # after the failed lookup in the block does not run.
        self.assertEqual(run.result, expected_recap(ok=6, rescued=1), "unexpected recap: " + run.output)
        self.assertNotIn("A Task After The Failed Lookup", run.output)

        # The misspelled option makes no request. The 4 other lookups make one each.
        self.assertEqual(run.paths(), ["get_folders"] * 4)


class KeeperGetFolderQuotingPlaybookTest(unittest.TestCase):
    """Folder names with a double quote, a tab, or a newline, through the real SDK and the playbook result."""

    FOLDERS = [
        {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
        {"uid": "QUOTE_UID", "name": 'Say "hi"', "parent": SHARED_FOLDER_UID},
        {"uid": "TWIN_1_UID", "name": 'Twin "A"', "parent": SHARED_FOLDER_UID},
        {"uid": "TWIN_2_UID", "name": 'Twin "A"', "parent": SHARED_FOLDER_UID},
        {"uid": "TAB_UID", "name": "Ops\tEU", "parent": SHARED_FOLDER_UID},
    ]

    def test_names_are_quoted_in_messages(self):
        run = PlaybookRun("keeper_get_folder_quoting.yml", self.FOLDERS, None, VARS)

        # 2 lookups that find a folder, 5 lookups that fail on purpose, and 1 assert task.
        self.assertEqual(run.result, expected_recap(ok=8, ignored=5), "unexpected recap: " + run.output)
        self.assertEqual(run.paths(), ["get_folders"] * 7)


class KeeperGetFolderGroupDefaultsPlaybookTest(unittest.TestCase):
    """
    module_defaults for the Keeper action group, in a real ansible-playbook run.

    A group default reaches keeper_get_folder only through a collection that has the action group, so the test
    builds one in a temporary directory: meta/runtime.yml from ansible_galaxy, and the keeper_get_folder plugin
    files of this package. Ansible finds it because it is next to the playbook. This also checks that the
    plugin reads the real shape of module_defaults, which a fake task cannot prove.
    """

    PLAYBOOK = "keeper_get_folder_group_defaults.yml"

    def build(self, root):
        tests_dir = os.path.dirname(os.path.realpath(__file__))
        component_dir = os.path.dirname(tests_dir)
        plugins_dir = os.path.dirname(os.path.realpath(keeper_secrets_manager_ansible.plugins.__file__))
        collection = os.path.join(root, "collections", "ansible_collections", "keepersecurity",
                                  "keeper_secrets_manager")
        os.makedirs(os.path.join(collection, "meta"))
        shutil.copyfile(
            os.path.join(component_dir, "ansible_galaxy", "keepersecurity", "keeper_secrets_manager", "meta",
                         "runtime.yml"),
            os.path.join(collection, "meta", "runtime.yml"))
        for kind in ("action", "modules"):
            os.makedirs(os.path.join(collection, "plugins", kind))
            shutil.copyfile(os.path.join(plugins_dir, kind, "keeper_get_folder.py"),
                            os.path.join(collection, "plugins", kind, "keeper_get_folder.py"))
        playbook = os.path.join(root, self.PLAYBOOK)
        shutil.copyfile(os.path.join(tests_dir, "ansible_example", "playbooks", self.PLAYBOOK), playbook)
        return playbook

    def test_group_defaults(self):
        root = tempfile.mkdtemp(prefix="ksm_get_folder_group_defaults_")
        try:
            # AnsibleTestFramework joins the playbook to its playbooks directory, and an absolute path wins.
            run = PlaybookRun(self.build(root), FOLDERS, RECORDS, VARS)
        finally:
            shutil.rmtree(root, ignore_errors=True)

        # First play: 2 lookups (the misspelled one fails on purpose) and 1 assert task. Second play: 1 lookup
        # that fails on purpose, and 1 assert task.
        self.assertEqual(run.result, expected_recap(ok=5, ignored=2), "unexpected recap: " + run.output)
        # Only the first lookup is valid, so it is the only request.
        self.assertEqual(run.paths(), ["get_folders"])


class KeeperGetFolderTestInstructionsTest(unittest.TestCase):
    """
    The QA test instructions: (1) a shared folder with a subfolder, shared to the KSM application; (2) a lookup
    with the shared folder UID and the subfolder name; (3) the task returns the subfolder UID; (4) the same task
    with a name that does not exist fails with a clear error, not an empty value.
    """

    # Step 1.
    FOLDERS = [
        {"uid": "SHARED_FOLDER_UID", "name": "Infrastructure", "parent": None},
        {"uid": "SUBFOLDER_UID", "name": "Databases", "parent": "SHARED_FOLDER_UID"},
    ]
    RECORDS = [
        {"uid": "RECORD_UID", "title": "Database Login", "folder": "SHARED_FOLDER_UID", "inner": "SUBFOLDER_UID"},
    ]
    VARS = {
        "shared_folder_uid": "SHARED_FOLDER_UID",
        "shared_folder_name": "Infrastructure",
        "subfolder_uid": "SUBFOLDER_UID",
        "subfolder_name": "Databases",
        "missing_name": "Web Servers",
    }
    EXPECTED = ('Could not look up folder: No folder named "Web Servers" was found in the folder "Infrastructure" '
                '(UID SHARED_FOLDER_UID).')

    def test_steps_with_ignore_errors(self):
        run = PlaybookRun("keeper_get_folder_test_instructions.yml", self.FOLDERS, self.RECORDS, self.VARS)

        # Steps 2 and 4 are lookups, and steps 3 and 4 each have an assert task. Step 4 fails on purpose.
        self.assertEqual(run.result, expected_recap(ok=4, ignored=1), "unexpected recap: " + run.output)
        self.assertEqual(run.paths(), ["get_folders", "get_folders"])
        self.assertTrue(in_output(self.EXPECTED, run.output), run.output)

    def test_steps_without_ignore_errors_stop_the_play(self):
        """
        Without ignore_errors the failed lookup stops the play. AnsibleTestFramework.run() then returns {}, so
        the output is checked instead: the lookup before it found the subfolder, the error is the clear message,
        and the task after it did not run.
        """
        run = PlaybookRun("keeper_get_folder_not_found.yml", self.FOLDERS, self.RECORDS, self.VARS)

        self.assertEqual(run.result, {}, "expected the play to fail, not to report a normal PLAY RECAP")
        self.assertIn("FOUND_SUBFOLDER_UID=SUBFOLDER_UID", run.output)
        self.assertTrue(in_output(self.EXPECTED, run.output), "the clear error is not in the output: " + run.output)
        self.assertNotIn("AFTER_FAILED_LOOKUP_MARKER", run.output)
        self.assertEqual(recap_from_text(run.output), expected_recap(ok=2, failed=1))
        self.assertEqual(run.paths(), ["get_folders", "get_folders"])


class KeeperGetFolderChainPlaybookTest(unittest.TestCase):
    """The folder UID from keeper_get_folder is used by keeper_create_folder in the next task."""

    def test_folder_uid_feeds_keeper_create_folder(self):
        run = PlaybookRun("keeper_get_folder_chain.yml", FOLDERS, RECORDS, VARS)

        # 3 lookups, 1 create, and 1 assert task. Only the create changes the vault.
        self.assertEqual(run.result, expected_recap(ok=5, changed=1), "a task failed or did not run: " + run.output)

        before = {f["uid"] for f in FOLDERS}
        new_folders = [f for f in run.folders if f["uid"] not in before]
        self.assertEqual(len(new_folders), 1, run.folders)
        self.assertEqual(new_folders[0]["name"], "Canary")
        self.assertEqual(new_folders[0]["parent"], PRODUCTION_UID, "the folder was created under the wrong parent")

        creates = [call for call in run.calls if call["path"] == "create_folder"]
        self.assertEqual(len(creates), 1)
        self.assertEqual(creates[0]["shared_folder_uid"], SHARED_FOLDER_UID)
        self.assertEqual(creates[0]["parent_uid"], PRODUCTION_UID)
        self.assertEqual(creates[0]["folder_name"], "Canary")
        self.assertEqual(creates[0]["folder_uid"], new_folders[0]["uid"])

        # get_folders for the first lookup, get_folders and create_folder for keeper_create_folder, then the
        # two lookups that see the new folder.
        self.assertEqual(run.paths(), ["get_folders", "get_folders", "create_folder", "get_folders", "get_folders"])


if __name__ == "__main__":
    unittest.main()
