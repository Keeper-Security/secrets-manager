import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from keeper_secrets_manager_core.dto.payload import CreateOptions
from keeper_secrets_manager_core.mock import Record, Response
from keeper_secrets_manager_ansible import KeeperAnsible
from .ansible_test_framework import AnsibleTestFramework


class KeeperCreateSubfolderTest(unittest.TestCase):
    """
    Unit tests for KeeperAnsible.create_record() subfolder support (KSM-845).

    Tests that folder_uid flows through to CreateOptions.subfolder_uid,
    and that omitting folder_uid preserves backward-compatible None behavior.
    """

    def _make_keeper(self):
        mock_client = MagicMock()
        mock_client.create_secret_with_options.return_value = "NEW_UID"
        keeper = object.__new__(KeeperAnsible)
        keeper.client = mock_client
        return keeper, mock_client

    def test_folder_uid_passed_as_subfolder_uid(self):
        keeper, mock_client = self._make_keeper()
        keeper.create_record(MagicMock(), "SHARED_UID", folder_uid="SUB_UID")
        create_options = mock_client.create_secret_with_options.call_args[0][0]
        self.assertIsInstance(create_options, CreateOptions)
        self.assertEqual(create_options.folder_uid, "SHARED_UID")
        self.assertEqual(create_options.subfolder_uid, "SUB_UID")

    def test_no_folder_uid_defaults_to_none(self):
        keeper, mock_client = self._make_keeper()
        keeper.create_record(MagicMock(), "SHARED_UID")
        create_options = mock_client.create_secret_with_options.call_args[0][0]
        self.assertIsInstance(create_options, CreateOptions)
        self.assertEqual(create_options.folder_uid, "SHARED_UID")
        self.assertIsNone(create_options.subfolder_uid)


class KeeperCreateSubfolderPlaybookTest(unittest.TestCase):
    """
    Integration test for the keeper_create_subfolder.yml example playbook (KSM-845).

    Unlike KeeperCreateSubfolderTest above, this runs the actual playbook YAML
    through ansible-playbook (via AnsibleTestFramework), the same way every other
    example playbook in tests/ansible_example/playbooks/ is verified elsewhere in
    this suite. It catches breakage in the YAML/Jinja/action-plugin wiring that a
    pure Python unit test on create_record() cannot see.

    Ansible executes each task's action plugin in a forked worker process, so a
    mocked side_effect cannot report back to the test via an in-memory closure
    (the fork gets its own copy of that state). It writes what it saw to a temp
    file instead, which is visible to the parent process after the fork exits.
    """

    def test_keeper_create_subfolder_playbook(self):
        mock_response = Response()
        mock_record = Record(title="Record 1", record_type="login")
        mock_record.field("password", "MYPASSWORD")
        mock_response.add_record(record=mock_record)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            capture_path = tmp.name
        os.remove(capture_path)

        def mocked_create_secret(*args):
            create_options = args[0]
            with open(capture_path, "w") as fh:
                json.dump({
                    "folder_uid": create_options.folder_uid,
                    "subfolder_uid": create_options.subfolder_uid,
                }, fh)
            return "NEW_UID"

        try:
            with patch(
                "keeper_secrets_manager_core.core.SecretsManager.create_secret_with_options",
                side_effect=mocked_create_secret,
            ):
                a = AnsibleTestFramework(
                    playbook="keeper_create_subfolder.yml",
                    vars={
                        "shared_folder_uid": "SHARED_UID",
                        "folder_uid": "SUB_UID",
                    },
                    mock_responses=[mock_response]
                )
                result, out, err = a.run()

            self.assertEqual(result["ok"], 2, "2 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")

            self.assertTrue(os.path.exists(capture_path), "create_secret_with_options was never called")
            with open(capture_path) as fh:
                captured = json.load(fh)
            self.assertEqual(captured.get("folder_uid"), "SHARED_UID")
            self.assertEqual(captured.get("subfolder_uid"), "SUB_UID")
        finally:
            if os.path.exists(capture_path):
                os.remove(capture_path)
