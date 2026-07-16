import unittest
from unittest.mock import MagicMock
from keeper_secrets_manager_core.dto.payload import CreateOptions
from keeper_secrets_manager_ansible import KeeperAnsible


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
