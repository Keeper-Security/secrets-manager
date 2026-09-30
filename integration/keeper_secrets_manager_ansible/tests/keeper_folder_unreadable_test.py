import logging
import sys
import unittest
from unittest.mock import MagicMock, patch

from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.dto.dtos import KeeperFolder
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFolderError
from .ansible_test_framework import AnsibleTestFramework
from .folder_fake_server import FakeKeeperServer

KEY = b"k" * 32

# The warning that keeper-secrets-manager-core 17.4.0 and later log when they skip a folder that they cannot decrypt.
SKIP_MESSAGE = "Folder %s skipped due to error: %s"

NOTE = (" keeper-secrets-manager-core could not read 1 folder(s) (UNREADABLE_UID), so the folder can be one of them. "
        "A newer keeper-secrets-manager-core can read more folder formats.")


def readable_folders():
    return [
        KeeperFolder(KEY, "SF", "", "Infrastructure"),
        KeeperFolder(KEY, "EMPTY", "SF", "Temporary"),
    ]


def skipping_get_folders(*args, **kwargs):
    # What SDK 17.4.0 does with a folder that it cannot decrypt: log a warning, and leave the folder out.
    logging.getLogger(logger_name).warning(SKIP_MESSAGE, "UNREADABLE_UID", "Invalid padding bytes.")
    return readable_folders()


def keeper_with(get_folders):
    keeper = object.__new__(KeeperAnsible)
    keeper.client = MagicMock()
    keeper.client.get_folders.side_effect = get_folders
    keeper.client.get_secrets.return_value = []
    keeper.client.delete_folder.return_value = [{"folderUid": "EMPTY", "responseCode": "ok"}]
    return keeper


class UnreadableFolderTest(unittest.TestCase):
    """
    keeper-secrets-manager-core 17.4.0 and later leave a folder that they cannot decrypt out of get_folders(), with
    only a warning in the log. A folder that exists must never be reported as "not found, nothing to delete".
    """

    def test_delete_of_a_folder_that_the_sdk_skipped_fails_and_deletes_nothing(self):
        keeper = keeper_with(skipping_get_folders)
        with self.assertRaises(KeeperFolderError) as ctx:
            keeper.delete_folder("UNREADABLE_UID")
        self.assertEqual(
            str(ctx.exception),
            "The folder UNREADABLE_UID exists, but keeper-secrets-manager-core could not read it (Invalid padding "
            "bytes.). Nothing was deleted. A newer keeper-secrets-manager-core can read more folder formats.")
        keeper.client.delete_folder.assert_not_called()

    def test_forced_delete_of_a_folder_that_the_sdk_skipped_also_fails(self):
        keeper = keeper_with(skipping_get_folders)
        with self.assertRaises(KeeperFolderError):
            keeper.delete_folder("UNREADABLE_UID", force=True)
        keeper.client.delete_folder.assert_not_called()

    def test_a_folder_that_does_not_exist_is_still_not_found(self):
        keeper = keeper_with(skipping_get_folders)
        result = keeper.delete_folder("NO_SUCH_UID")
        self.assertEqual(result["changed"], False)
        self.assertIsNone(result["folder_name"])
        keeper.client.delete_folder.assert_not_called()

    def test_a_readable_folder_is_deleted_with_a_warning_about_the_unreadable_ones(self):
        keeper = keeper_with(skipping_get_folders)
        with patch("keeper_secrets_manager_ansible.display.warning") as warning:
            result = keeper.delete_folder("EMPTY")
        self.assertEqual(result["changed"], True)
        keeper.client.delete_folder.assert_called_once_with(["EMPTY"], force_deletion=False)
        warning.assert_called_once()
        self.assertIn("could not read 1 folder(s) (UNREADABLE_UID)", warning.call_args[0][0])

    def test_no_warning_for_a_forced_delete(self):
        # With force, the contents are deleted anyway, so the count of the contents does not matter.
        keeper = keeper_with(skipping_get_folders)
        with patch("keeper_secrets_manager_ansible.display.warning") as warning:
            keeper.delete_folder("EMPTY", force=True)
        warning.assert_not_called()

    def test_lookup_not_found_messages_name_the_unreadable_folders(self):
        keeper = keeper_with(skipping_get_folders)
        cases = [
            (dict(shared_folder_uid="SF", folder_name="Missing"),
             'No folder named "Missing" was found in the folder "Infrastructure" (UID SF).'),
            (dict(shared_folder_uid="NO_SF"),
             "The shared folder NO_SF was not found, or it is not shared to this KSM application."),
            (dict(subfolder_uid="NO_SUB"),
             "The subfolder NO_SUB was not found, or it is not shared to this KSM application."),
        ]
        for kwargs, message in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(KeeperFolderError) as ctx:
                    keeper.get_folder(**kwargs)
                self.assertEqual(str(ctx.exception), message + NOTE)

    def test_rename_not_found_message_names_the_unreadable_folders(self):
        keeper = keeper_with(skipping_get_folders)
        with self.assertRaises(KeeperFolderError) as ctx:
            keeper.update_folder("UNREADABLE_UID", "New Name")
        self.assertEqual(
            str(ctx.exception),
            "The folder UNREADABLE_UID was not found, or it is not shared to this KSM application." + NOTE)
        keeper.client.update_folder.assert_not_called()

    def test_messages_have_no_note_when_every_folder_was_read(self):
        keeper = keeper_with(lambda *a, **k: readable_folders())
        with self.assertRaises(KeeperFolderError) as ctx:
            keeper.update_folder("NO_SUCH_UID", "New Name")
        self.assertEqual(
            str(ctx.exception), "The folder NO_SUCH_UID was not found, or it is not shared to this KSM application.")

    def test_subfolder_list_warns_about_the_unreadable_folders(self):
        keeper = keeper_with(skipping_get_folders)
        with patch("keeper_secrets_manager_ansible.display.warning") as warning:
            result = keeper.get_folder(shared_folder_uid="SF", include_subfolders=True)
        self.assertEqual([f["folder_uid"] for f in result["subfolders"]], ["EMPTY"])
        warning.assert_called_once()
        self.assertIn("they are not in subfolders", warning.call_args[0][0])


class SdkLoggerStateTest(unittest.TestCase):
    """The capture must leave the SDK logger as it was, and must not show the warning on the SDK's own handler."""

    def setUp(self):
        self.logger = logging.getLogger(logger_name)
        self.saved = (self.logger.level, self.logger.disabled, list(self.logger.handlers))

    def tearDown(self):
        self.logger.setLevel(self.saved[0])
        self.logger.disabled = self.saved[1]
        self.logger.handlers[:] = self.saved[2]

    def test_level_handlers_and_disabled_are_restored(self):
        for level, disabled in ((logging.ERROR, False), (logging.DEBUG, False), (logging.ERROR, True)):
            with self.subTest(level=level, disabled=disabled):
                self.logger.setLevel(level)
                self.logger.disabled = disabled
                handlers = list(self.logger.handlers)
                folders, unreadable = keeper_with(skipping_get_folders)._read_folders()
                self.assertEqual(unreadable, {"UNREADABLE_UID": "Invalid padding bytes."})
                self.assertEqual(self.logger.level, level)
                self.assertEqual(self.logger.disabled, disabled)
                self.assertEqual(self.logger.handlers, handlers)

    def test_state_is_restored_when_get_folders_fails(self):
        self.logger.setLevel(logging.ERROR)
        handlers = list(self.logger.handlers)

        def failing(*args, **kwargs):
            raise ConnectionError("connection reset")

        with self.assertRaises(KeeperFolderError):
            keeper_with(failing)._read_folders()
        self.assertEqual(self.logger.level, logging.ERROR)
        self.assertEqual(self.logger.handlers, handlers)

    def test_the_sdk_handler_at_error_does_not_show_the_warning(self):
        # The SDK adds a handler at the log level of the task (ERROR by default). The capture lowers the logger level
        # to WARNING, but the handler keeps its own level, so the output does not change.
        shown = []

        class Recorder(logging.Handler):
            def emit(self, record):
                shown.append(record)

        recorder = Recorder(level=logging.ERROR)
        self.logger.addHandler(recorder)
        self.logger.setLevel(logging.ERROR)
        keeper_with(skipping_get_folders)._read_folders()
        self.assertEqual(shown, [])


class RealSdkUnreadableFolderTest(unittest.TestCase):
    """
    The real SDK against FakeKeeperServer, with a subfolder in the AES-GCM format that SDK 18.0.0 creates. SDK 17.3.0
    fails to read the folder list, SDK 17.4.0 skips the folder, and SDK 18.0.0 reads it. On every version, a delete of
    that folder must fail or delete it. It must never report "not found" while the folder still exists.
    """

    def test_delete_of_a_gcm_folder_never_reports_a_false_not_found(self):
        server = FakeKeeperServer(folders=[
            {"uid": "SF", "name": "Infrastructure", "parent": None},
            {"uid": "GCM_UID", "name": "New Format", "parent": "SF", "gcm": True},
        ])
        try:
            keeper = object.__new__(KeeperAnsible)
            keeper.client = SecretsManager(config=InMemoryKeyValueStorage(config=mock.MockConfig.make_base64()),
                                           log_level="ERROR")
            with server.patch():
                try:
                    sdk_folders = [f.folder_uid for f in keeper.client.get_folders()]
                    sdk_behavior = "reads" if "GCM_UID" in sdk_folders else "skips"
                except Exception:
                    sdk_behavior = "fails"

                try:
                    result = keeper.delete_folder("GCM_UID")
                    outcome, message = ("deleted" if result["changed"] else "not found"), result.get("msg")
                except KeeperFolderError as err:
                    outcome, message = "failed", str(err)

            self.assertNotEqual(outcome, "not found", "a folder that exists was reported as not found")
            if sdk_behavior == "reads":
                self.assertEqual(outcome, "deleted")
                self.assertIsNone(server.folder("GCM_UID"))
            elif sdk_behavior == "skips":
                self.assertEqual(outcome, "failed")
                self.assertIn("exists, but keeper-secrets-manager-core could not read it", message)
                self.assertIsNotNone(server.folder("GCM_UID"))
            else:
                self.assertEqual(outcome, "failed")
                self.assertTrue(message.startswith("Cannot get folders: "), message)
                self.assertIsNotNone(server.folder("GCM_UID"))
        finally:
            server.cleanup()


class UnreadableFolderPlaybookTest(unittest.TestCase):
    """The capture also works in the forked Ansible worker, where the action plugin runs."""

    @classmethod
    def setUpClass(cls):
        for module in list(sys.modules):
            if module.startswith("ansible"):
                sys.modules.pop(module, None)

    def test_delete_task_fails_for_a_folder_that_the_sdk_skipped(self):
        server = FakeKeeperServer(folders=[
            {"uid": "SF", "name": "Infrastructure", "parent": None},
            {"uid": "UNREADABLE_UID", "name": "Hidden", "parent": "SF"},
        ])

        def get_folders_that_skips(sm):
            # The real SDK reads the folders from the fake server; then the one folder is dropped, with the same
            # warning that SDK 17.4.0 logs.
            folders = SecretsManager.fetch_and_decrypt_folders(sm)
            sm.logger.warning(SKIP_MESSAGE, "UNREADABLE_UID", "Invalid padding bytes.")
            return [f for f in folders if f.folder_uid != "UNREADABLE_UID"]

        try:
            with server.patch(), patch.object(SecretsManager, "get_folders", autospec=True,
                                              side_effect=get_folders_that_skips):
                a = AnsibleTestFramework(playbook="keeper_folder_unreadable.yml", vars={"folder_uid": "UNREADABLE_UID"})
                result, out, err = a.run()
            self.assertEqual(result.get("failed"), 0, out + err)
            self.assertEqual(result.get("ignored"), 1, out + err)
            self.assertEqual(server.calls("delete_folder"), [], "nothing may be deleted")
            self.assertIsNotNone(server.folder("UNREADABLE_UID"))
        finally:
            server.cleanup()
