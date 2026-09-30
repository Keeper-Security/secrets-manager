import contextlib
import datetime
import importlib
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

from keeper_secrets_manager_core.dto.dtos import KeeperFolder

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperArgumentError, KeeperFolderError


def _plugin():
    # The action plugin module, imported only when a test needs it. Do not import it at the top of this file:
    # an action plugin import loads ansible.plugins.loader, and a loader that is loaded before
    # AnsibleTestFramework sets the action plugin path cannot find the keeper actions. pytest imports every
    # test file before the first test runs, so a top-level import here breaks the first playbook test of the
    # suite with "couldn't resolve module/action".
    return importlib.import_module("keeper_secrets_manager_ansible.plugins.action.keeper_delete_folder")


def tearDownModule():
    # The plugin import above loaded ansible.plugins.loader with the default plugin path. Unload the ansible
    # modules, as AnsibleTestFramework does after each playbook run, so that the next playbook test imports a
    # fresh loader that uses its path.
    for module in list(sys.modules):
        if module.startswith("ansible"):
            sys.modules.pop(module, None)


# The folder tree that most tests use. A shared folder has the parent UID "", as the SDK returns it.
#
#   Infrastructure (SHARED_UID)                 shared folder
#     Staging (EMPTY_UID)                       no records, no subfolders
#     Databases (DB_UID)                        one subfolder
#       Production (PROD_UID)                   one subfolder
#         Archive (ARCHIVE_UID)
#     Web (WEB_UID)
#   Operations (OPS_UID)                        shared folder with no subfolders
SHARED = "SHARED_UID"
EMPTY = "EMPTY_UID"
DATABASES = "DB_UID"
PRODUCTION = "PROD_UID"
ARCHIVE = "ARCHIVE_UID"
WEB = "WEB_UID"
OPERATIONS = "OPS_UID"
MISSING = "MISSING_UID"

EMPTY_LABEL = '"Infrastructure/Staging" (UID EMPTY_UID)'
DATABASES_LABEL = '"Infrastructure/Databases" (UID DB_UID)'


NULL_MESSAGE = "The {} option is null. Give it a value, or leave the option out of the task."
NOT_A_STRING_MESSAGE = ("The folder_uid option must be a string, but it is {}. Put quotes around the value, or "
                        "use the string filter.")
SUPPORTED = {"folder_uid", "force_deletion"}


def _not_found(folder_uid):
    # The result for a folder that is not in the folder list of the application.
    return {
        "changed": False,
        "folder_uid": folder_uid,
        "folder_name": None,
        "msg": "The folder {} was not found, or it is not shared to this KSM application. Nothing was "
               "deleted.".format(folder_uid),
    }


def _failure(msg):
    # What the action plugin returns for a failure. It returns it, so that failed_when and rescue work on it.
    return {"failed": True, "changed": False, "msg": msg}


def _assert_unsupported(test, message, *options):
    # The message for misspelled options. On ansible-core 2.12 the names after "Supported parameters include:"
    # are in set order, and on later versions they are sorted, so they are compared as a set. The text before
    # them is compared exactly.
    before, marker, after = message.partition("Supported parameters include: ")
    test.assertEqual(
        before, "Unsupported parameters for (keeper_delete_folder) module: {}. ".format(", ".join(sorted(options))))
    test.assertEqual(marker, "Supported parameters include: ", message)
    test.assertTrue(after.endswith("."), message)
    test.assertEqual(set(after[:-1].split(", ")), SUPPORTED)


def _folder(uid, parent_uid, name):
    return KeeperFolder(b"k" * 32, uid, parent_uid, name)


def _tree():
    return [
        _folder(SHARED, "", "Infrastructure"),
        _folder(OPERATIONS, "", "Operations"),
        _folder(EMPTY, SHARED, "Staging"),
        _folder(DATABASES, SHARED, "Databases"),
        _folder(PRODUCTION, DATABASES, "Production"),
        _folder(ARCHIVE, PRODUCTION, "Archive"),
        _folder(WEB, SHARED, "Web"),
    ]


def _without(folders, *uids):
    return [f for f in folders if f.folder_uid not in uids]


def _record(uid, folder_uid, inner_folder_uid=None):
    # A plain object, not a MagicMock. A MagicMock record has a truthy MagicMock inner_folder_uid, so every
    # record would look like it is in some subfolder, and the top-level record rules would never run.
    return types.SimpleNamespace(uid=uid, title=uid, folder_uid=folder_uid, inner_folder_uid=inner_folder_uid)


def _ok_for_each(folder_uids, force_deletion=False):
    return [{"folderUid": uid, "responseCode": "ok"} for uid in folder_uids]


class _Sdk(object):
    """
    A fake SDK client. get_folders returns `folders` until delete_folder is called, then `folders_after`
    (the tree without the deleted folder, unless the test says otherwise). This matches the server: a folder
    that was deleted is not in the next get_folders response.
    """

    def __init__(self, folders=None, records=None, delete_response=_ok_for_each, folders_after=None,
                 deleted_uids=None):
        self.client = MagicMock()
        before = list(_tree() if folders is None else folders)
        if folders_after is None:
            folders_after = _without(before, *(deleted_uids or []))
        after = list(folders_after)
        self.client.get_folders.side_effect = lambda: list(after if self.client.delete_folder.called else before)
        self.client.get_secrets.return_value = list(records or [])
        if callable(delete_response):
            self.client.delete_folder.side_effect = delete_response
        else:
            self.client.delete_folder.return_value = delete_response

    def keeper(self):
        keeper = object.__new__(KeeperAnsible)
        keeper.client = self.client
        return keeper


def _delete(sdk, folder_uid, **kwargs):
    return sdk.keeper().delete_folder(folder_uid, **kwargs)


class KeeperDeleteFolderAcceptanceTest(unittest.TestCase):
    """The three scenarios of the delete folder feature, each against KeeperAnsible.delete_folder directly."""

    def test_empty_folder_is_deleted_and_reports_changed(self):
        """An existing, empty folder is deleted, and the result says changed."""
        sdk = _Sdk(deleted_uids=[EMPTY])
        result = _delete(sdk, EMPTY)

        self.assertEqual(result, {"changed": True, "folder_uid": EMPTY, "folder_name": "Staging"})
        sdk.client.delete_folder.assert_called_once_with([EMPTY], force_deletion=False)
        self.assertIs(sdk.client.delete_folder.call_args.kwargs["force_deletion"], False)

    def test_folder_with_a_record_fails_without_force(self):
        """A folder that contains a record must fail, and nothing may be deleted."""
        sdk = _Sdk(records=[_record("R1", SHARED, EMPTY)])
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY)

        self.assertIn("is not empty", str(ctx.exception))
        self.assertIn("Set force_deletion to true", str(ctx.exception))
        sdk.client.delete_folder.assert_not_called()

    def test_folder_with_a_subfolder_fails_without_force(self):
        """A folder that contains a subfolder, and no records, must fail, and nothing may be deleted."""
        sdk = _Sdk()
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, PRODUCTION)

        self.assertIn("is not empty", str(ctx.exception))
        sdk.client.delete_folder.assert_not_called()

    def test_folder_that_does_not_exist_reports_not_changed(self):
        """
        A second run after a delete must not fail. The module reports changed false with a message that says
        that nothing was deleted, and it must not read the records or send a delete for a folder that it cannot see.
        """
        sdk = _Sdk()
        result = _delete(sdk, MISSING)

        self.assertEqual(result, _not_found(MISSING))
        sdk.client.get_secrets.assert_not_called()
        sdk.client.delete_folder.assert_not_called()

    def test_folder_that_does_not_exist_with_force_reports_not_changed(self):
        """Force must not change the not-found result: there is still nothing to delete and no request."""
        sdk = _Sdk()
        result = _delete(sdk, MISSING, force=True)

        self.assertEqual(result, _not_found(MISSING))
        sdk.client.get_secrets.assert_not_called()
        sdk.client.delete_folder.assert_not_called()

    def test_folder_not_found_when_the_sdk_returns_no_folders(self):
        """get_folders can return None. That is an empty list, so the folder is not found, and nothing is sent."""
        sdk = _Sdk()
        sdk.client.get_folders.side_effect = None
        sdk.client.get_folders.return_value = None
        result = _delete(sdk, EMPTY)

        self.assertEqual(result, _not_found(EMPTY))
        sdk.client.delete_folder.assert_not_called()


class KeeperDeleteFolderEmptinessTest(unittest.TestCase):
    """
    Without force, only DIRECT content makes a folder not empty: a subfolder whose parent is the folder, or a
    record that is directly in the folder. A folder that is not empty must never reach the delete call.
    """

    def assertNotEmpty(self, sdk, folder_uid, records_count, subfolders_count):
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, folder_uid)
        self.assertIn("is not empty. It contains {} record(s) and {} subfolder(s).".format(
            records_count, subfolders_count), str(ctx.exception))
        sdk.client.delete_folder.assert_not_called()
        return str(ctx.exception)

    def assertDeleted(self, sdk, folder_uid):
        result = _delete(sdk, folder_uid)
        self.assertIs(result["changed"], True)
        sdk.client.delete_folder.assert_called_once_with([folder_uid], force_deletion=False)
        return result

    def test_direct_subfolder_only_makes_the_folder_not_empty(self):
        """A folder with a subfolder and no records at all is not empty."""
        self.assertNotEmpty(_Sdk(), PRODUCTION, 0, 1)

    def test_direct_record_in_a_subfolder_makes_it_not_empty(self):
        """A record in a subfolder has the subfolder UID in inner_folder_uid, and folder_uid is the shared folder."""
        sdk = _Sdk(records=[_record("R1", SHARED, EMPTY)])
        self.assertNotEmpty(sdk, EMPTY, 1, 0)

    def test_record_at_the_top_of_a_shared_folder_makes_it_not_empty(self):
        """A record at the top of a shared folder has no inner_folder_uid, only folder_uid."""
        sdk = _Sdk(records=[_record("R1", OPERATIONS, None)])
        self.assertNotEmpty(sdk, OPERATIONS, 1, 0)

    def test_record_with_an_empty_string_inner_folder_uid_is_a_top_level_record(self):
        """The SDK default for inner_folder_uid is "". It must count the same as None, or the record is missed."""
        sdk = _Sdk(records=[_record("R1", OPERATIONS, "")])
        self.assertNotEmpty(sdk, OPERATIONS, 1, 0)

    def test_record_with_inner_folder_uid_equal_to_the_shared_folder_counts(self):
        """If the server sets inner_folder_uid to the shared folder itself, the record is still directly in it."""
        sdk = _Sdk(records=[_record("R1", OPERATIONS, OPERATIONS)])
        self.assertNotEmpty(sdk, OPERATIONS, 1, 0)

    def test_records_and_subfolders_are_both_counted_in_the_message(self):
        """The message gives the exact counts, so the playbook author knows what force would delete."""
        sdk = _Sdk(records=[
            _record("R1", SHARED, DATABASES),
            _record("R2", SHARED, DATABASES),
            _record("R3", SHARED, WEB),
        ])
        message = self.assertNotEmpty(sdk, DATABASES, 2, 1)
        self.assertEqual(
            message,
            'The folder "Infrastructure/Databases" (UID DB_UID) is not empty. It contains 2 record(s) and '
            '1 subfolder(s). Set force_deletion to true to delete the folder and everything in it.')

    def test_record_in_a_sibling_subfolder_does_not_count(self):
        """A record in a different subfolder of the same shared folder is not in this folder."""
        sdk = _Sdk(records=[_record("R1", SHARED, WEB)], deleted_uids=[EMPTY])
        self.assertDeleted(sdk, EMPTY)

    def test_record_at_the_top_of_the_shared_folder_does_not_count_for_a_subfolder(self):
        """A top-level record has folder_uid == the shared folder. It is not in the subfolder that is deleted."""
        sdk = _Sdk(records=[_record("R1", SHARED, None), _record("R2", SHARED, "")], deleted_uids=[EMPTY])
        self.assertDeleted(sdk, EMPTY)

    def test_record_in_another_shared_folder_does_not_count(self):
        sdk = _Sdk(records=[_record("R1", OPERATIONS, None)], deleted_uids=[EMPTY])
        self.assertDeleted(sdk, EMPTY)

    def test_record_shared_directly_to_the_application_does_not_count(self):
        """A record shared directly to the KSM application has no folder. It is in no folder that can be deleted."""
        sdk = _Sdk(records=[_record("R1", "", None)], deleted_uids=[OPERATIONS])
        self.assertDeleted(sdk, OPERATIONS)

    def test_record_in_a_subfolder_does_not_count_as_a_direct_record_of_the_shared_folder(self):
        """For the shared folder, a record in its subfolder is not direct (the subfolder is counted instead)."""
        folders = [_folder(SHARED, "", "Infrastructure"), _folder(EMPTY, SHARED, "Staging")]
        sdk = _Sdk(folders=folders, records=[_record("R1", SHARED, EMPTY)])
        self.assertNotEmpty(sdk, SHARED, 0, 1)

    def test_record_in_a_grandchild_folder_is_not_counted_as_a_direct_record(self):
        """
        The direct subfolder already makes the folder not empty, but the record count must stay direct-only,
        so the message does not claim records that are deeper in the tree.
        """
        sdk = _Sdk(records=[_record("R1", SHARED, PRODUCTION), _record("R2", SHARED, ARCHIVE)])
        self.assertNotEmpty(sdk, DATABASES, 0, 1)

    def test_grandchild_folders_are_not_counted_as_direct_subfolders(self):
        """Databases has one child (Production) and a grandchild (Archive). Only the child is counted."""
        self.assertNotEmpty(_Sdk(), DATABASES, 0, 1)

    def test_every_direct_subfolder_is_counted(self):
        folders = _tree() + [_folder("SECOND_CHILD", DATABASES, "Development")]
        self.assertNotEmpty(_Sdk(folders=folders), DATABASES, 0, 2)

    def test_emptiness_check_reads_all_records_once(self):
        """The records check must ask for every record (no UID filter), or records of the folder can be missed."""
        sdk = _Sdk(deleted_uids=[EMPTY])
        _delete(sdk, EMPTY)
        sdk.client.get_secrets.assert_called_once_with()


class KeeperDeleteFolderForceTest(unittest.TestCase):
    """
    Force deletes a folder with everything in it. It must be on only for the value True. A string such as
    "false", or any other truthy value, must never delete the contents of a folder.
    """

    NOT_TRUE_VALUES = ["true", "True", "yes", "false", "1", 1, 1.0, [True], (True,), {"force": True}, object()]

    def test_force_true_skips_the_records_check_and_forces_the_delete(self):
        """With force, the records are not read at all, and the server is told to delete the contents."""
        sdk = _Sdk(records=[_record("R1", SHARED, DATABASES)], deleted_uids=[DATABASES, PRODUCTION, ARCHIVE])
        result = _delete(sdk, DATABASES, force=True)

        self.assertEqual(result, {"changed": True, "folder_uid": DATABASES, "folder_name": "Databases"})
        sdk.client.get_secrets.assert_not_called()
        sdk.client.delete_folder.assert_called_once_with([DATABASES], force_deletion=True)
        self.assertIs(sdk.client.delete_folder.call_args.kwargs["force_deletion"], True)

    def test_force_true_on_an_empty_folder_also_sends_force(self):
        sdk = _Sdk(deleted_uids=[EMPTY])
        _delete(sdk, EMPTY, force=True)

        sdk.client.get_secrets.assert_not_called()
        sdk.client.delete_folder.assert_called_once_with([EMPTY], force_deletion=True)

    def test_default_delete_does_not_force(self):
        sdk = _Sdk(deleted_uids=[EMPTY])
        _delete(sdk, EMPTY)
        self.assertIs(sdk.client.delete_folder.call_args.kwargs["force_deletion"], False)

    def test_truthy_values_that_are_not_true_do_not_force_a_folder_that_is_not_empty(self):
        """The dangerous direction: each of these values must leave a folder that is not empty in place."""
        for value in self.NOT_TRUE_VALUES:
            with self.subTest(force=value):
                sdk = _Sdk(records=[_record("R1", SHARED, WEB)])
                with self.assertRaises(KeeperFolderError) as ctx:
                    _delete(sdk, WEB, force=value)
                self.assertIn("is not empty", str(ctx.exception))
                sdk.client.get_secrets.assert_called_once_with()
                sdk.client.delete_folder.assert_not_called()

    def test_truthy_values_that_are_not_true_never_send_force_deletion(self):
        """For an empty folder, the delete is sent, but force_deletion must be the bool False."""
        for value in self.NOT_TRUE_VALUES:
            with self.subTest(force=value):
                sdk = _Sdk(deleted_uids=[EMPTY])
                _delete(sdk, EMPTY, force=value)
                sdk.client.delete_folder.assert_called_once_with([EMPTY], force_deletion=False)
                self.assertIs(sdk.client.delete_folder.call_args.kwargs["force_deletion"], False)

    def test_false_values_do_not_force(self):
        for value in [False, None, 0, "", "no"]:
            with self.subTest(force=value):
                sdk = _Sdk()
                with self.assertRaises(KeeperFolderError):
                    _delete(sdk, DATABASES, force=value)
                sdk.client.delete_folder.assert_not_called()


class KeeperDeleteFolderCheckModeTest(unittest.TestCase):
    """In check mode every check still runs, and the delete request is never sent."""

    def test_check_mode_reports_changed_for_a_deletable_folder_without_deleting(self):
        sdk = _Sdk()
        result = _delete(sdk, EMPTY, check_mode=True)

        self.assertEqual(result, {"changed": True, "folder_uid": EMPTY, "folder_name": "Staging"})
        sdk.client.get_secrets.assert_called_once_with()
        sdk.client.delete_folder.assert_not_called()

    def test_check_mode_still_fails_for_a_folder_with_a_record(self):
        """Check mode must predict the real run: a real run fails here, so check mode must fail too."""
        sdk = _Sdk(records=[_record("R1", SHARED, EMPTY)])
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY, check_mode=True)

        self.assertIn("It contains 1 record(s) and 0 subfolder(s)", str(ctx.exception))
        sdk.client.delete_folder.assert_not_called()

    def test_check_mode_still_fails_for_a_folder_with_a_subfolder(self):
        sdk = _Sdk()
        with self.assertRaises(KeeperFolderError):
            _delete(sdk, DATABASES, check_mode=True)
        sdk.client.delete_folder.assert_not_called()

    def test_check_mode_still_reports_not_changed_for_a_missing_folder(self):
        sdk = _Sdk()
        result = _delete(sdk, MISSING, check_mode=True)

        self.assertEqual(result, _not_found(MISSING))
        sdk.client.get_secrets.assert_not_called()
        sdk.client.delete_folder.assert_not_called()

    def test_check_mode_with_force_reports_changed_without_reading_records_or_deleting(self):
        sdk = _Sdk(records=[_record("R1", SHARED, DATABASES)])
        result = _delete(sdk, DATABASES, force=True, check_mode=True)

        self.assertEqual(result, {"changed": True, "folder_uid": DATABASES, "folder_name": "Databases"})
        sdk.client.get_secrets.assert_not_called()
        sdk.client.delete_folder.assert_not_called()

    def test_check_mode_still_rejects_a_padded_uid(self):
        sdk = _Sdk()
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY + " ", check_mode=True)
        self.assertIn("has leading or trailing whitespace", str(ctx.exception))
        sdk.client.delete_folder.assert_not_called()

    def test_check_mode_still_reports_a_records_read_error(self):
        sdk = _Sdk()
        sdk.client.get_secrets.side_effect = Exception("records unavailable")
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY, check_mode=True)
        self.assertIn("Cannot get records to check if the folder", str(ctx.exception))
        sdk.client.delete_folder.assert_not_called()


class KeeperDeleteFolderServerStatusTest(unittest.TestCase):
    """
    The server does not raise an error when it refuses a delete. It returns a status for each folder. The
    module must read the status of this folder, and it must never report a delete that did not happen.
    """

    def test_ok_status_reports_changed_without_a_second_folder_read(self):
        sdk = _Sdk(delete_response=[{"folderUid": EMPTY, "responseCode": "ok"}], deleted_uids=[EMPTY])
        result = _delete(sdk, EMPTY)

        self.assertEqual(result, {"changed": True, "folder_uid": EMPTY, "folder_name": "Staging"})
        self.assertEqual(sdk.client.get_folders.call_count, 1, "an ok status needs no second get_folders")

    def test_access_denied_status_fails_with_the_server_message(self):
        sdk = _Sdk(delete_response=[{
            "folderUid": EMPTY, "responseCode": "access_denied",
            "errorMessage": "User does not have permission to delete this folder"}])
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY)

        self.assertEqual(
            str(ctx.exception),
            'The Keeper server did not delete the folder "Infrastructure/Staging" (UID EMPTY_UID). It returned '
            'access_denied: User does not have permission to delete this folder.')

    def test_access_denied_status_fails_a_forced_delete_too(self):
        sdk = _Sdk(delete_response=[{"folderUid": DATABASES, "responseCode": "access_denied",
                                     "errorMessage": "User does not have permission to delete this folder"}])
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, DATABASES, force=True)
        self.assertIn("did not delete the folder " + DATABASES_LABEL, str(ctx.exception))
        self.assertIn("It returned access_denied: User does not have permission", str(ctx.exception))

    def test_non_ok_code_without_an_error_message(self):
        sdk = _Sdk(delete_response=[{"folderUid": EMPTY, "responseCode": "folder_not_empty"}])
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY)
        self.assertEqual(
            str(ctx.exception),
            "The Keeper server did not delete the folder {}. It returned folder_not_empty.".format(EMPTY_LABEL))

    def test_non_ok_code_with_a_blank_error_message(self):
        """An empty errorMessage must not leave a dangling ": " in the message."""
        for message in ["", None]:
            with self.subTest(errorMessage=message):
                sdk = _Sdk(delete_response=[{"folderUid": EMPTY, "responseCode": "folder_not_empty",
                                             "errorMessage": message}])
                with self.assertRaises(KeeperFolderError) as ctx:
                    _delete(sdk, EMPTY)
                self.assertTrue(str(ctx.exception).endswith("It returned folder_not_empty."), str(ctx.exception))

    def test_status_without_a_response_code(self):
        """A status for this folder with no responseCode is not a success."""
        for status in [{"folderUid": EMPTY}, {"folderUid": EMPTY, "responseCode": None},
                       {"folderUid": EMPTY, "responseCode": ""}]:
            with self.subTest(status=status):
                sdk = _Sdk(delete_response=[status])
                with self.assertRaises(KeeperFolderError) as ctx:
                    _delete(sdk, EMPTY)
                self.assertEqual(
                    str(ctx.exception),
                    "The Keeper server did not delete the folder {}. It returned no response code.".format(
                        EMPTY_LABEL))

    def test_status_without_a_response_code_keeps_the_error_message(self):
        sdk = _Sdk(delete_response=[{"folderUid": EMPTY, "errorMessage": "Something went wrong"}])
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY)
        self.assertIn("It returned no response code: Something went wrong.", str(ctx.exception))

    def test_only_the_exact_ok_code_is_a_success(self):
        """Any code other than "ok" is a refusal. A near match must not be read as a success."""
        for code in ["OK", "Ok", "ok ", "success", "deleted", True, 1]:
            with self.subTest(responseCode=code):
                sdk = _Sdk(delete_response=[{"folderUid": EMPTY, "responseCode": code}])
                with self.assertRaises(KeeperFolderError) as ctx:
                    _delete(sdk, EMPTY)
                self.assertIn("did not delete the folder", str(ctx.exception))

    def test_status_is_found_by_folder_uid_not_by_position(self):
        """The ok of another folder must not hide the refusal of this folder, and the reverse."""
        denied = {"folderUid": EMPTY, "responseCode": "access_denied", "errorMessage": "No"}
        other_ok = {"folderUid": WEB, "responseCode": "ok"}
        sdk = _Sdk(delete_response=[other_ok, denied])
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY)
        self.assertIn("It returned access_denied: No.", str(ctx.exception))

        other_denied = {"folderUid": WEB, "responseCode": "access_denied", "errorMessage": "No"}
        this_ok = {"folderUid": EMPTY, "responseCode": "ok"}
        sdk = _Sdk(delete_response=[other_denied, this_ok], deleted_uids=[EMPTY])
        self.assertIs(_delete(sdk, EMPTY)["changed"], True)
        self.assertEqual(sdk.client.get_folders.call_count, 1)

    def test_ok_status_without_a_folder_uid_is_not_trusted(self):
        """An ok that does not name this folder is not a status for it. The folder still exists: fail."""
        sdk = _Sdk(delete_response=[{"responseCode": "ok"}], folders_after=_tree())
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY)
        self.assertIn("did not confirm the delete", str(ctx.exception))

    def test_status_only_for_other_folders_falls_back_to_a_folder_read(self):
        """No status for this folder: the module reads the folders again, and the folder is gone, so success."""
        sdk = _Sdk(delete_response=[{"folderUid": WEB, "responseCode": "ok"}], deleted_uids=[EMPTY])
        result = _delete(sdk, EMPTY)

        self.assertEqual(result, {"changed": True, "folder_uid": EMPTY, "folder_name": "Staging"})
        self.assertEqual(sdk.client.get_folders.call_count, 2)

    def test_status_only_for_other_folders_and_the_folder_still_exists_fails(self):
        sdk = _Sdk(delete_response=[{"folderUid": WEB, "responseCode": "ok"}], folders_after=_tree())
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY)
        self.assertEqual(
            str(ctx.exception),
            "The Keeper server did not confirm the delete of the folder {}, and the folder still exists.".format(
                EMPTY_LABEL))
        self.assertEqual(sdk.client.get_folders.call_count, 2)

    # Responses that contain no status for the folder: SDK 17.3.0 returns {} when the server sends no
    # "folders", None when it sends "folders": null, and later SDKs return a list.
    NO_STATUS_RESPONSES = [
        [], {}, None, "garbage", 42, b"bytes", {"folders": None}, {"folders": []}, {"folders": {}},
        {"something": "else"}, [None, "EMPTY_UID", 5, ["folderUid", "EMPTY_UID"], ("folderUid", "EMPTY_UID")],
        ({"folderUid": "EMPTY_UID", "responseCode": "ok"},),
    ]

    def test_no_status_and_the_folder_is_gone_reports_changed(self):
        for response in self.NO_STATUS_RESPONSES:
            with self.subTest(response=response):
                sdk = _Sdk(delete_response=response, deleted_uids=[EMPTY])
                result = _delete(sdk, EMPTY)
                self.assertEqual(result, {"changed": True, "folder_uid": EMPTY, "folder_name": "Staging"})
                self.assertEqual(sdk.client.get_folders.call_count, 2, "the folders must be read again")

    def test_no_status_and_the_folder_still_exists_fails(self):
        """The core safety check: without a status, a folder that still exists is a failed delete."""
        for response in self.NO_STATUS_RESPONSES:
            with self.subTest(response=response):
                sdk = _Sdk(delete_response=response, folders_after=_tree())
                with self.assertRaises(KeeperFolderError) as ctx:
                    _delete(sdk, EMPTY)
                self.assertIn(
                    "did not confirm the delete of the folder {}, and the folder still exists.".format(EMPTY_LABEL),
                    str(ctx.exception))

    def test_non_dict_items_before_the_status_are_skipped(self):
        """A list with junk in it must still find the real status of the folder."""
        sdk = _Sdk(delete_response=["junk", None, {"folderUid": EMPTY, "responseCode": "ok"}], deleted_uids=[EMPTY])
        self.assertIs(_delete(sdk, EMPTY)["changed"], True)
        self.assertEqual(sdk.client.get_folders.call_count, 1)

        sdk = _Sdk(delete_response=["junk", {"folderUid": EMPTY, "responseCode": "access_denied"}])
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY)
        self.assertIn("It returned access_denied.", str(ctx.exception))

    def test_sdk_list_and_dict_response_shapes_both_work(self):
        """SDK 17.3.0 returns the server's "folders" list. A dict with "folders" must be read the same way."""
        ok = [{"folderUid": EMPTY, "responseCode": "ok"}]
        denied = [{"folderUid": EMPTY, "responseCode": "access_denied", "errorMessage": "No"}]
        for response in [ok, {"folders": ok}]:
            with self.subTest(response=response):
                sdk = _Sdk(delete_response=response, folders_after=_tree())
                self.assertIs(_delete(sdk, EMPTY)["changed"], True)
                self.assertEqual(sdk.client.get_folders.call_count, 1, "the ok status must be read, no fallback")
        for response in [denied, {"folders": denied}]:
            with self.subTest(response=response):
                sdk = _Sdk(delete_response=response, deleted_uids=[EMPTY])
                with self.assertRaises(KeeperFolderError) as ctx:
                    _delete(sdk, EMPTY)
                self.assertIn("It returned access_denied: No.", str(ctx.exception))

    def test_second_folder_read_error_does_not_report_success(self):
        """
        If the fallback read fails, the module cannot know if the folder is gone. It must not say changed, and
        the message must say that the delete was sent and that the folder can still exist.
        """
        for response in [[], {}, None, [{"folderUid": WEB, "responseCode": "ok"}]]:
            for force in [False, True]:
                with self.subTest(response=response, force=force):
                    sdk = _Sdk(delete_response=response)
                    sdk.client.get_folders.side_effect = [_tree(), Exception("connection reset")]
                    with self.assertRaises(KeeperFolderError) as ctx:
                        _delete(sdk, EMPTY, force=force)
                    self.assertEqual(
                        str(ctx.exception),
                        "The Keeper server sent no result for the delete of the folder {}, and the check of the "
                        "folder list after it failed, so the folder can still exist. Cannot get folders: "
                        "connection reset".format(EMPTY_LABEL))
                    sdk.client.delete_folder.assert_called_once_with([EMPTY], force_deletion=force)

    def test_fallback_uses_the_exact_folder_uid(self):
        """A folder with a similar UID that still exists must not make a deleted folder look present."""
        folders = _tree() + [_folder("EMPTY_UID_2", SHARED, "Staging")]
        sdk = _Sdk(folders=folders, delete_response=[], deleted_uids=[EMPTY])
        self.assertIs(_delete(sdk, EMPTY)["changed"], True)


class KeeperDeleteFolderSdkErrorTest(unittest.TestCase):
    """An SDK exception becomes a KeeperFolderError that says which step failed, and nothing more is sent."""

    def test_get_folders_error(self):
        sdk = _Sdk()
        sdk.client.get_folders.side_effect = Exception("network is down")
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY)

        self.assertEqual(str(ctx.exception), "Cannot get folders: network is down")
        sdk.client.get_secrets.assert_not_called()
        sdk.client.delete_folder.assert_not_called()

    def test_get_secrets_error(self):
        sdk = _Sdk()
        sdk.client.get_secrets.side_effect = Exception("records unavailable")
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY)

        self.assertEqual(
            str(ctx.exception),
            "Cannot get records to check if the folder {} is empty: records unavailable".format(EMPTY_LABEL))
        sdk.client.delete_folder.assert_not_called()

    def test_delete_folder_error(self):
        sdk = _Sdk(delete_response=None)
        sdk.client.delete_folder.side_effect = Exception("access denied by policy")
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, EMPTY)

        self.assertEqual(str(ctx.exception),
                         "Cannot delete the folder {}: access denied by policy".format(EMPTY_LABEL))

    def test_delete_folder_error_with_force(self):
        sdk = _Sdk(delete_response=None)
        sdk.client.delete_folder.side_effect = Exception("timeout")
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, DATABASES, force=True)
        self.assertEqual(str(ctx.exception), "Cannot delete the folder {}: timeout".format(DATABASES_LABEL))


class KeeperDeleteFolderUidTest(unittest.TestCase):
    """
    A blank or padded folder_uid usually comes from an empty template variable or a stray newline. It must fail.
    If it were looked up, it would match no folder, and the task would silently report changed false.
    """

    BLANK = [None, "", " ", "   ", "\t", "\n", " \r\n "]
    PADDED = [" " + EMPTY, EMPTY + " ", EMPTY + "\n", "\t" + EMPTY, "\n" + EMPTY + "\n", EMPTY + "\r\n"]

    def test_blank_uid_fails(self):
        for value in self.BLANK:
            with self.subTest(folder_uid=value):
                sdk = _Sdk()
                with self.assertRaises(KeeperFolderError) as ctx:
                    _delete(sdk, value)
                self.assertEqual(str(ctx.exception), "The folder_uid is blank.")
                sdk.client.get_secrets.assert_not_called()
                sdk.client.delete_folder.assert_not_called()

    def test_blank_uid_fails_with_force(self):
        sdk = _Sdk()
        with self.assertRaises(KeeperFolderError):
            _delete(sdk, "", force=True)
        sdk.client.delete_folder.assert_not_called()

    def test_padded_uid_fails_even_when_the_trimmed_uid_exists(self):
        for value in self.PADDED:
            with self.subTest(folder_uid=value):
                sdk = _Sdk()
                with self.assertRaises(KeeperFolderError) as ctx:
                    _delete(sdk, value)
                self.assertEqual(
                    str(ctx.exception), "The folder_uid {!r} has leading or trailing whitespace.".format(value))
                sdk.client.get_secrets.assert_not_called()
                sdk.client.delete_folder.assert_not_called()

    def test_padded_uid_of_a_missing_folder_fails_instead_of_reporting_not_changed(self):
        """This is the silent case: without the check, the result would be changed false, and no error."""
        for value in [" " + MISSING, MISSING + "\n"]:
            with self.subTest(folder_uid=value):
                sdk = _Sdk()
                with self.assertRaises(KeeperFolderError) as ctx:
                    _delete(sdk, value)
                self.assertIn("has leading or trailing whitespace", str(ctx.exception))

    def test_padded_uid_with_force_fails_and_deletes_nothing(self):
        sdk = _Sdk()
        with self.assertRaises(KeeperFolderError):
            _delete(sdk, DATABASES + "\n", force=True)
        sdk.client.delete_folder.assert_not_called()

    def test_uid_is_matched_exactly(self):
        """A UID in a different case is a different folder, so it is not found, and nothing is deleted."""
        sdk = _Sdk()
        result = _delete(sdk, EMPTY.lower())
        self.assertEqual(result, _not_found(EMPTY.lower()))
        sdk.client.delete_folder.assert_not_called()


class KeeperDeleteFolderArgumentSpecTest(unittest.TestCase):
    """validate_task_args with the module's own ARGUMENT_SPEC and options, the same call that the plugin makes."""

    @staticmethod
    def _validate(task_args):
        spec = _plugin().ActionModule.ARGUMENT_SPEC
        return KeeperAnsible.validate_task_args("keeper_delete_folder", task_args, spec)

    def _error(self, task_args):
        with self.assertRaises(KeeperArgumentError) as ctx:
            self._validate(task_args)
        return str(ctx.exception)

    def test_argument_spec_has_only_the_documented_options(self):
        """The option is force_deletion, not force: keeper_copy has force, and a group default for it must not
        reach this module as an option."""
        spec = _plugin().ActionModule.ARGUMENT_SPEC
        self.assertEqual(set(spec), SUPPORTED)
        self.assertEqual(spec["folder_uid"].get("type"), "str")
        self.assertIs(spec["folder_uid"].get("required"), True)
        self.assertEqual(spec["force_deletion"].get("type"), "bool")
        self.assertIs(spec["force_deletion"].get("default"), False)

    def test_missing_folder_uid_fails(self):
        self.assertEqual(self._error({}), "missing required arguments: folder_uid")
        self.assertEqual(self._error({"force_deletion": True}), "missing required arguments: folder_uid")

    def test_the_old_option_name_force_fails(self):
        """A task that still writes force must fail. If force were ignored, the task would delete without it."""
        for value in [True, "yes", False]:
            with self.subTest(force=value):
                _assert_unsupported(self, self._error({"folder_uid": EMPTY, "force": value}), "force")

    def test_misspelled_options_fail(self):
        """A misspelled force_deletion must fail. If it were ignored, the task would run without force_deletion."""
        for option in ["force_delete", "forcedeletion", "Force_deletion", "forse", "folder_name", "folder", "uid",
                       "shared_folder_uid"]:
            with self.subTest(option=option):
                _assert_unsupported(self, self._error({"folder_uid": EMPTY, option: True}), option)

    def test_two_misspelled_options_are_both_named(self):
        _assert_unsupported(self, self._error({"folder_uid": EMPTY, "force": True, "force_delete": "yes"}),
                            "force", "force_delete")

    def test_missing_folder_uid_and_a_misspelled_option_are_both_reported(self):
        """The first validator message does not end with a period, so the next one follows after "; "."""
        message = self._error({"force": True})
        before, separator, rest = message.partition("; ")
        self.assertEqual((before, separator), ("missing required arguments: folder_uid", "; "), message)
        _assert_unsupported(self, rest, "force")

    def test_force_deletion_that_is_not_a_boolean_fails(self):
        """The type error text is the text of ansible-core, which differs a little between versions."""
        for value, detail in [("maybe", "The value 'maybe' is not a valid boolean."),
                              ("", "The value '' is not a valid boolean."),
                              ("1.0", "The value '1.0' is not a valid boolean."),
                              (2, "The value '2' is not a valid boolean."),
                              ([True], "cannot be converted to a bool")]:
            with self.subTest(force_deletion=value):
                message = self._error({"folder_uid": EMPTY, "force_deletion": value})
                self.assertTrue(message.startswith("argument 'force_deletion' is of type "), message)
                self.assertIn(" and we were unable to convert to bool: ", message)
                self.assertIn(detail, message)
                self.assertNotIn("; ", message)

    def test_null_options_fail(self):
        """A template variable with no value gives null. For force_deletion, null must never mean a default."""
        self.assertEqual(self._error({"folder_uid": None}), NULL_MESSAGE.format("folder_uid"))
        self.assertEqual(self._error({"folder_uid": EMPTY, "force_deletion": None}),
                         NULL_MESSAGE.format("force_deletion"))
        self.assertEqual(self._error({"folder_uid": None, "force_deletion": None}),
                         NULL_MESSAGE.format("folder_uid") + " " + NULL_MESSAGE.format("force_deletion"))

    def test_a_null_option_stops_the_other_checks(self):
        """When a pre-check fails, the validator does not run, so only the pre-check messages are shown."""
        self.assertEqual(self._error({"folder_uid": None, "force": True}), NULL_MESSAGE.format("folder_uid"))
        self.assertEqual(self._error({"force_deletion": None}), NULL_MESSAGE.format("force_deletion"))

    def test_folder_uid_that_is_not_a_string_fails(self):
        """
        YAML gives a value with no quotes its own type, and its text can differ from what the playbook author
        wrote (0012 becomes the number 10). A folder UID must be a string, so these values fail.
        """
        for value, kind in [([EMPTY], "a list"), ((EMPTY,), "a list"), ({EMPTY}, "a list"), ([], "a list"),
                            ({"uid": EMPTY}, "a dictionary"), (True, "a boolean (True)"),
                            (False, "a boolean (False)"), (12345, "a number (12345)"), (10, "a number (10)"),
                            (0, "a number (0)"), (1.1, "a number (1.1)"),
                            (datetime.date(2026, 9, 29), "a date (2026-09-29)"),
                            (datetime.datetime(2026, 9, 29, 10, 0), "a date and time (2026-09-29 10:00:00)"),
                            (b"EMPTY_UID", "a byte string")]:
            with self.subTest(folder_uid=value):
                self.assertEqual(self._error({"folder_uid": value}), NOT_A_STRING_MESSAGE.format(kind))

    def test_quoted_number_is_a_valid_folder_uid(self):
        """With quotes, YAML keeps the text of a UID of digits, so it is a string and it is used as it is."""
        for value in ["12345", "0012", "1_000"]:
            with self.subTest(folder_uid=value):
                self.assertEqual(self._validate({"folder_uid": value}), {"folder_uid": value, "force_deletion": False})

    def test_pre_check_messages_are_joined_in_option_order(self):
        """The first message ends with a period, so the next one follows after a space."""
        self.assertEqual(self._error({"force_deletion": None, "folder_uid": [EMPTY]}),
                         NOT_A_STRING_MESSAGE.format("a list") + " " + NULL_MESSAGE.format("force_deletion"))

    def test_force_deletion_defaults_to_false(self):
        args = self._validate({"folder_uid": EMPTY})
        self.assertEqual(args, {"folder_uid": EMPTY, "force_deletion": False})
        self.assertIs(args["force_deletion"], False)

    def test_true_values_become_true(self):
        for value in ["yes", "true", "True", "on", "1", 1, 1.0, True]:
            with self.subTest(force_deletion=value):
                self.assertIs(self._validate({"folder_uid": EMPTY, "force_deletion": value})["force_deletion"], True)

    def test_false_values_become_false(self):
        for value in ["no", "false", "False", "off", "0", 0, False]:
            with self.subTest(force_deletion=value):
                self.assertIs(self._validate({"folder_uid": EMPTY, "force_deletion": value})["force_deletion"], False)

    def test_folder_uid_whitespace_is_kept_for_the_uid_check(self):
        """The argument spec must not strip the UID, or the whitespace check in delete_folder can never run."""
        self.assertEqual(self._validate({"folder_uid": " " + EMPTY + "\n"})["folder_uid"], " " + EMPTY + "\n")


GROUP = "group/keepersecurity.keeper_secrets_manager.keeper_secrets_manager"


class _Task(object):
    def __init__(self, args, check_mode, module_defaults=None):
        self.args = args
        self.check_mode = check_mode
        self.async_val = 0
        self.action = "keeper_delete_folder"
        self.module_defaults = module_defaults


def _action(task_args, check_mode=False, module_defaults=None):
    connection = types.SimpleNamespace(_shell=types.SimpleNamespace(tmpdir="/nonexistent"))
    task = _Task(dict(task_args), check_mode, module_defaults)
    # ActionBase.run of ansible-core 2.12 reads check_mode from the play context, later versions from the task.
    play_context = types.SimpleNamespace(check_mode=bool(check_mode))
    return _plugin().ActionModule(task, connection, play_context, None, None, None)


def _init_with(client):
    # Replaces KeeperAnsible.__init__, so the plugin gets a KeeperAnsible with a fake SDK client and no config.
    def __init__(self, task_vars, action_module=None, task_attributes=None, force_in_memory=False):
        self.client = client
    return __init__


class _ConfigError(Exception):
    pass


def _vault_value(plaintext):
    """
    A real Ansible Vault value of the installed ansible-core, and a context in which it can be decrypted. It is
    what the plugin gets for a !vault value in the task: EncryptedString on ansible-core 2.19 and later (in a
    playbook these versions give the plugin the decrypted string instead), AnsibleVaultEncryptedUnicode before.
    """
    vault = importlib.import_module("ansible.parsing.vault")
    secret = vault.VaultSecret(b"keeper-delete-folder-test-only")
    ciphertext = vault.VaultLib([("default", secret)]).encrypt(plaintext)
    (vault_class,) = KeeperAnsible._vault_string_types()
    if vault_class.__name__ == "EncryptedString":
        context = vault.VaultSecretsContext([("default", secret)])
        return vault_class(ciphertext=ciphertext.decode()), patch.object(vault.VaultSecretsContext, "_current", context)
    value = vault_class(ciphertext)
    value.vault = vault.VaultLib([("default", secret)])
    return value, contextlib.nullcontext()


C17_MESSAGE = "Unsupported parameters for (keeper_delete_folder) module: {}. An option name must be a string."
DATABASES_NOT_EMPTY = ("Could not delete folder: The folder {} is not empty. It contains 0 record(s) and 1 "
                       "subfolder(s). Set force_deletion to true to delete the folder and everything in "
                       "it.".format(DATABASES_LABEL))


class KeeperDeleteFolderActionPluginTest(unittest.TestCase):
    """
    The action plugin: it checks the options before it connects, it passes only a real bool for force_deletion and
    check mode, and it returns a failure instead of raising it, so that failed_when, ignore_errors, and rescue work.
    """

    def _run_with_mock_method(self, task_args, check_mode=False, result=None, module_defaults=None):
        with patch.object(KeeperAnsible, "__init__", return_value=None) as init, \
                patch.object(KeeperAnsible, "delete_folder", return_value=result or {"changed": False}) as method:
            output = _action(task_args, check_mode, module_defaults).run(task_vars={})
        return output, init, method

    def _run_with_sdk(self, sdk, task_args, module_defaults=None):
        with patch.object(KeeperAnsible, "__init__", _init_with(sdk.client)):
            return _action(task_args, module_defaults=module_defaults).run(task_vars={})

    def test_misspelled_option_returns_a_failure_before_keeper_ansible_is_created(self):
        """A misspelled option fails before the plugin builds the SDK client or reads any config."""
        output, init, method = self._run_with_mock_method({"folder_uid": EMPTY, "force_delete": True})
        self.assertEqual(sorted(output), ["changed", "failed", "msg"])
        self.assertIs(output["failed"], True)
        self.assertIs(output["changed"], False)
        _assert_unsupported(self, output["msg"], "force_delete")
        init.assert_not_called()
        method.assert_not_called()

    def test_the_old_force_option_returns_a_failure_and_deletes_nothing(self):
        """
        A task that still writes force fails as an unsupported option. The folder has a subfolder: if force were
        read as force_deletion, its contents would be deleted, and if it were ignored, the task would not fail.
        """
        for value in [True, "yes"]:
            with self.subTest(force=value):
                output, init, method = self._run_with_mock_method({"folder_uid": DATABASES, "force": value})
                self.assertIs(output["failed"], True)
                _assert_unsupported(self, output["msg"], "force")
                init.assert_not_called()
                method.assert_not_called()

        sdk = _Sdk()
        output = self._run_with_sdk(sdk, {"folder_uid": DATABASES, "force": True})
        _assert_unsupported(self, output["msg"], "force")
        sdk.client.get_folders.assert_not_called()
        sdk.client.delete_folder.assert_not_called()

    def test_option_name_that_is_not_a_string_returns_a_failure_before_anything_connects(self):
        """
        YAML reads an unquoted key such as 1 as a number. The name check runs before every other check: before
        the null check, the misspelled-option check, and the required check. Nothing connects to the server.
        """
        cases = [
            ({"folder_uid": EMPTY, 1: "x"}, "1"),
            ({"folder_uid": None, "force": True, 1: "x"}, "1"),
            ({1: "x"}, "1"),
            ({"folder_uid": EMPTY, "force_deletion": True, 2.5: "x", None: "y", 1: "z"}, "1, 2.5, None"),
        ]
        for task_args, names in cases:
            with self.subTest(task_args=task_args):
                output, init, method = self._run_with_mock_method(task_args)
                self.assertEqual(output, _failure(C17_MESSAGE.format(names)))
                init.assert_not_called()
                method.assert_not_called()

        sdk = _Sdk()
        self.assertEqual(self._run_with_sdk(sdk, {"folder_uid": DATABASES, "force_deletion": True, 1: "x"}),
                         _failure(C17_MESSAGE.format("1")))
        self.assertEqual(sdk.client.mock_calls, [], "nothing may reach the SDK client")

    def test_missing_folder_uid_returns_a_failure_before_keeper_ansible_is_created(self):
        output, init, method = self._run_with_mock_method({"force_deletion": True})
        self.assertEqual(output, _failure("missing required arguments: folder_uid"))
        init.assert_not_called()
        method.assert_not_called()

    def test_null_options_return_a_failure_before_keeper_ansible_is_created(self):
        for task_args, message in [
                ({"folder_uid": None}, NULL_MESSAGE.format("folder_uid")),
                ({"folder_uid": EMPTY, "force_deletion": None}, NULL_MESSAGE.format("force_deletion")),
                ({"folder_uid": None, "force_deletion": None},
                 NULL_MESSAGE.format("folder_uid") + " " + NULL_MESSAGE.format("force_deletion"))]:
            with self.subTest(task_args=task_args):
                output, init, method = self._run_with_mock_method(task_args)
                self.assertEqual(output, _failure(message))
                init.assert_not_called()
                method.assert_not_called()

    def test_folder_uid_that_is_not_a_string_returns_a_failure(self):
        for value, kind in [([EMPTY], "a list"), ({"uid": EMPTY}, "a dictionary"), (True, "a boolean (True)"),
                            (1.1, "a number (1.1)"), (12345, "a number (12345)"),
                            (datetime.date(2026, 9, 29), "a date (2026-09-29)")]:
            with self.subTest(folder_uid=value):
                output, init, method = self._run_with_mock_method({"folder_uid": value, "force_deletion": True})
                self.assertEqual(output, _failure(NOT_A_STRING_MESSAGE.format(kind)))
                init.assert_not_called()
                method.assert_not_called()

    def test_vault_encrypted_folder_uid_is_accepted(self):
        """
        A folder_uid that Ansible Vault encrypts is not a str, but it is a string value. The option check must
        accept it, and the method must get the decrypted UID.
        """
        value, context = _vault_value(EMPTY)
        self.assertNotIsInstance(value, str, "the test must give the plugin the vault value itself")
        sdk = _Sdk(deleted_uids=[EMPTY])
        with context:
            output = self._run_with_sdk(sdk, {"folder_uid": value})
        self.assertEqual(output, {"changed": True, "folder_uid": EMPTY, "folder_name": "Staging"})
        sdk.client.delete_folder.assert_called_once_with([EMPTY], force_deletion=False)

    def test_quoted_number_folder_uid_reaches_the_method(self):
        _, _, method = self._run_with_mock_method({"folder_uid": "12345"})
        method.assert_called_once_with("12345", force=False, check_mode=False)

    def test_force_deletion_is_passed_as_the_validated_bool(self):
        """The task option is force_deletion. The method parameter is still named force."""
        for value, expected in [("yes", True), ("true", True), (True, True), ("no", False), ("false", False),
                                (False, False)]:
            with self.subTest(force_deletion=value):
                _, _, method = self._run_with_mock_method({"folder_uid": EMPTY, "force_deletion": value})
                method.assert_called_once_with(EMPTY, force=expected, check_mode=False)
                self.assertIs(method.call_args.kwargs["force"], expected)

    def test_force_deletion_defaults_to_false(self):
        _, _, method = self._run_with_mock_method({"folder_uid": EMPTY})
        self.assertIs(method.call_args.kwargs["force"], False)

    def test_force_is_a_real_bool_even_if_the_validated_value_is_not(self):
        """
        The plugin passes force=(validated force_deletion is True). If the argument validation of some
        ansible-core version left a raw value, such as None or the string "yes", the plugin must still pass a
        real bool, and only True may force.
        """
        for value, expected in [("yes", False), ("true", False), (1, False), (None, False), (True, True)]:
            with self.subTest(force_deletion=value):
                validated = {"folder_uid": EMPTY, "force_deletion": value}
                with patch.object(KeeperAnsible, "validate_task_args", return_value=validated):
                    _, _, method = self._run_with_mock_method({"folder_uid": EMPTY, "force_deletion": True})
                self.assertIs(method.call_args.kwargs["force"], expected)

    def test_check_mode_is_passed_as_a_bool(self):
        for value, expected in [(True, True), (False, False), (None, False)]:
            with self.subTest(check_mode=value):
                _, _, method = self._run_with_mock_method({"folder_uid": EMPTY}, check_mode=value)
                self.assertIs(method.call_args.kwargs["check_mode"], expected)

    def test_result_of_the_method_is_the_task_result(self):
        for expected in [{"changed": True, "folder_uid": EMPTY, "folder_name": "Staging"}, _not_found(MISSING)]:
            with self.subTest(result=expected):
                output, _, _ = self._run_with_mock_method({"folder_uid": EMPTY}, result=dict(expected))
                self.assertEqual(output, expected)

    def test_method_errors_are_returned_with_the_prefix(self):
        """Any exception from the method, not only KeeperFolderError, is returned as a failure."""
        for error in [KeeperFolderError("The folder_uid is blank."), RuntimeError("unexpected"),
                      AttributeError("'NoneType' object has no attribute 'folder_uid'")]:
            with self.subTest(error=error):
                with patch.object(KeeperAnsible, "__init__", return_value=None), \
                        patch.object(KeeperAnsible, "delete_folder", side_effect=error):
                    output = _action({"folder_uid": EMPTY}).run(task_vars={})
                self.assertEqual(output, _failure("Could not delete folder: {}".format(error)))

    def test_config_error_from_keeper_ansible_is_still_raised(self):
        """KeeperAnsible() is created outside the try, so a config error is raised, not returned."""
        with patch.object(KeeperAnsible, "__init__", side_effect=_ConfigError("Keeper Ansible error: no config")), \
                patch.object(KeeperAnsible, "delete_folder") as method:
            with self.assertRaises(_ConfigError):
                _action({"folder_uid": EMPTY}).run(task_vars={})
        method.assert_not_called()

    def test_group_default_options_are_passed_as_ignore(self):
        action = _action({"folder_uid": EMPTY, "cache": "x"})
        with patch.object(KeeperAnsible, "group_default_options", return_value={"cache"}) as defaults, \
                patch.object(KeeperAnsible, "__init__", return_value=None), \
                patch.object(KeeperAnsible, "delete_folder", return_value={"changed": True}) as method:
            output = action.run(task_vars={})
        defaults.assert_called_once_with(action._task, action._templar)
        method.assert_called_once_with(EMPTY, force=False, check_mode=False)
        self.assertEqual(output, {"changed": True})

    def test_group_default_that_this_module_does_not_have_does_not_fail(self):
        """
        module_defaults for the keeper action group gives its options to every module of the group. Ansible
        merges them into the task options, so the delete must ignore the options that it does not have.
        """
        defaults = [{GROUP: {"shared_folder_uid": "S", "cache": "x"}}]
        task_args = {"folder_uid": EMPTY, "shared_folder_uid": "S", "cache": "x"}
        output, _, method = self._run_with_mock_method(task_args, module_defaults=defaults)
        self.assertEqual(output, {"changed": False})
        method.assert_called_once_with(EMPTY, force=False, check_mode=False)

    def test_misspelled_option_still_fails_with_group_defaults(self):
        defaults = [{GROUP: {"shared_folder_uid": "S"}}]
        task_args = {"folder_uid": EMPTY, "shared_folder_uid": "S", "force_delete": True}
        output, init, method = self._run_with_mock_method(task_args, module_defaults=defaults)
        _assert_unsupported(self, output["msg"], "force_delete")
        init.assert_not_called()
        method.assert_not_called()

    def test_group_default_force_does_not_force_the_delete(self):
        """
        keeper_copy has an option named force, so a play can set force: yes in module_defaults for the action
        group of this collection. Ansible merges it into the task options of this module too. This module does
        not have force, so the plugin ignores it, and the delete is not forced: a folder that is not empty still
        fails, and the SDK delete of an empty folder is sent with force_deletion False.
        """
        defaults = [{GROUP: {"force": True}}]
        _, _, method = self._run_with_mock_method({"folder_uid": EMPTY, "force": True}, module_defaults=defaults)
        method.assert_called_once_with(EMPTY, force=False, check_mode=False)

        sdk = _Sdk()
        output = self._run_with_sdk(sdk, {"folder_uid": DATABASES, "force": True}, module_defaults=defaults)
        self.assertEqual(output, _failure(DATABASES_NOT_EMPTY))
        sdk.client.delete_folder.assert_not_called()

        sdk = _Sdk(deleted_uids=[EMPTY])
        output = self._run_with_sdk(sdk, {"folder_uid": EMPTY, "force": True}, module_defaults=defaults)
        self.assertEqual(output, {"changed": True, "folder_uid": EMPTY, "folder_name": "Staging"})
        sdk.client.delete_folder.assert_called_once_with([EMPTY], force_deletion=False)
        self.assertIs(sdk.client.delete_folder.call_args.kwargs["force_deletion"], False)

    def test_force_from_the_group_of_another_collection_is_not_ignored(self):
        """
        Ansible gives a group default only to the modules of that group. So when the only group default that
        has force is for another collection, the force in the task options came from the task, and it must fail.
        """
        defaults = [{"group/community.general.example": {"force": True}}]
        output, init, method = self._run_with_mock_method({"folder_uid": DATABASES, "force": True},
                                                          module_defaults=defaults)
        _assert_unsupported(self, output["msg"], "force")
        init.assert_not_called()
        method.assert_not_called()

    def test_group_default_force_deletion_is_used(self):
        """
        This module has force_deletion, so a group default for it applies to every keeper_delete_folder task of
        the play, as it does for any option of any module. This test documents that normal module_defaults
        behavior. A task can still turn it off, and a null group default still fails.
        """
        defaults = [{GROUP: {"force_deletion": True}}]
        _, _, method = self._run_with_mock_method({"folder_uid": EMPTY, "force_deletion": True},
                                                  module_defaults=defaults)
        method.assert_called_once_with(EMPTY, force=True, check_mode=False)

        _, _, method = self._run_with_mock_method({"folder_uid": EMPTY, "force_deletion": False},
                                                  module_defaults=defaults)
        method.assert_called_once_with(EMPTY, force=False, check_mode=False)

        defaults = [{GROUP: {"force_deletion": None}}]
        output, _, method = self._run_with_mock_method({"folder_uid": EMPTY, "force_deletion": None},
                                                       module_defaults=defaults)
        self.assertEqual(output, _failure(NULL_MESSAGE.format("force_deletion")))
        method.assert_not_called()

    def test_plugin_with_the_real_method_deletes_an_empty_folder(self):
        sdk = _Sdk(deleted_uids=[EMPTY])
        output = self._run_with_sdk(sdk, {"folder_uid": EMPTY})
        self.assertEqual(output, {"changed": True, "folder_uid": EMPTY, "folder_name": "Staging"})
        sdk.client.delete_folder.assert_called_once_with([EMPTY], force_deletion=False)

    def test_plugin_with_the_real_method_reports_a_missing_folder(self):
        sdk = _Sdk()
        output = self._run_with_sdk(sdk, {"folder_uid": MISSING, "force_deletion": True})
        self.assertEqual(output, _not_found(MISSING))
        sdk.client.delete_folder.assert_not_called()

    def test_plugin_with_the_real_method_forces_for_a_yes_string(self):
        """force_deletion: "yes" (a quoted string in YAML) must reach the method as True, after the argument spec."""
        sdk = _Sdk(records=[_record("R1", SHARED, DATABASES)], deleted_uids=[DATABASES, PRODUCTION, ARCHIVE])
        output = self._run_with_sdk(sdk, {"folder_uid": DATABASES, "force_deletion": "yes"})
        self.assertEqual(output, {"changed": True, "folder_uid": DATABASES, "folder_name": "Databases"})
        sdk.client.get_secrets.assert_not_called()
        sdk.client.delete_folder.assert_called_once_with([DATABASES], force_deletion=True)

    def test_plugin_with_the_real_method_does_not_force_for_a_false_string(self):
        sdk = _Sdk()
        output = self._run_with_sdk(sdk, {"folder_uid": DATABASES, "force_deletion": "false"})
        self.assertEqual(output, _failure(DATABASES_NOT_EMPTY))
        sdk.client.delete_folder.assert_not_called()

    def test_plugin_with_the_real_method_in_check_mode_sends_no_delete(self):
        sdk = _Sdk()
        with patch.object(KeeperAnsible, "__init__", _init_with(sdk.client)):
            output = _action({"folder_uid": EMPTY}, check_mode=True).run(task_vars={})
        self.assertEqual(output, {"changed": True, "folder_uid": EMPTY, "folder_name": "Staging"})
        sdk.client.delete_folder.assert_not_called()

    def test_plugin_with_the_real_method_rejects_a_padded_uid(self):
        """The plugin must pass the UID as it is. If it stripped the UID, the whitespace check could never fail."""
        sdk = _Sdk()
        output = self._run_with_sdk(sdk, {"folder_uid": EMPTY + "\n", "force_deletion": True})
        self.assertEqual(output, _failure(
            "Could not delete folder: The folder_uid 'EMPTY_UID\\n' has leading or trailing whitespace."))
        sdk.client.delete_folder.assert_not_called()

    def test_plugin_with_the_real_method_rejects_a_blank_uid(self):
        """An empty string is not null, so the argument check passes it. The method must still reject it."""
        sdk = _Sdk()
        output = self._run_with_sdk(sdk, {"folder_uid": "  ", "force_deletion": True})
        self.assertEqual(output, _failure("Could not delete folder: The folder_uid is blank."))
        sdk.client.get_folders.assert_not_called()
        sdk.client.delete_folder.assert_not_called()


class KeeperDeleteFolderQuotedNameTest(unittest.TestCase):
    """
    Folder names in messages are in JSON quotes. A newline, a tab, a backslash, or a double quote in a name is
    shown as an escape, so a stray character is visible and cannot make the message point at another folder.
    """

    @staticmethod
    def _folders():
        return [
            _folder(SHARED, "", "Infrastructure"),
            _folder("QUOTE_UID", SHARED, 'Data"bases'),
            _folder("QUOTE_CHILD_UID", "QUOTE_UID", "Child"),
            _folder("NEWLINE_UID", SHARED, "Staging\n"),
            _folder("TAB_UID", SHARED, "Tab\tBack\\slash"),
            _folder("ACCENT_UID", SHARED, "Donn\u00e9es"),
            _folder("QUOTED_SHARED_UID", "", 'Infra"structure'),
            _folder("UNDER_QUOTED_UID", "QUOTED_SHARED_UID", "Staging"),
        ]

    def _error(self, folder_uid, **sdk_kwargs):
        sdk = _Sdk(folders=self._folders(), **sdk_kwargs)
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, folder_uid)
        return str(ctx.exception), sdk

    def test_double_quote_in_the_not_empty_message(self):
        message, sdk = self._error("QUOTE_UID")
        self.assertEqual(message, r'The folder "Infrastructure/Data\"bases" (UID QUOTE_UID) is not empty. It '
                                  r'contains 0 record(s) and 1 subfolder(s). Set force_deletion to true to delete the '
                                  r'folder and everything in it.')
        sdk.client.delete_folder.assert_not_called()

    def test_double_quote_in_the_shared_folder_name(self):
        message, _ = self._error("UNDER_QUOTED_UID", records=[_record("R1", "QUOTED_SHARED_UID", "UNDER_QUOTED_UID")])
        self.assertEqual(message, r'The folder "Infra\"structure/Staging" (UID UNDER_QUOTED_UID) is not empty. It '
                                  r'contains 1 record(s) and 0 subfolder(s). Set force_deletion to true to delete the '
                                  r'folder and everything in it.')

    def test_newline_in_the_refused_message(self):
        message, _ = self._error("NEWLINE_UID", delete_response=[
            {"folderUid": "NEWLINE_UID", "responseCode": "access_denied", "errorMessage": "No"}])
        self.assertEqual(message, r'The Keeper server did not delete the folder "Infrastructure/Staging\n" '
                                  r'(UID NEWLINE_UID). It returned access_denied: No.')

    def test_tab_and_backslash_in_the_did_not_confirm_message(self):
        message, _ = self._error("TAB_UID", delete_response=[], folders_after=self._folders())
        self.assertEqual(message, r'The Keeper server did not confirm the delete of the folder '
                                  r'"Infrastructure/Tab\tBack\\slash" (UID TAB_UID), and the folder still exists.')

    def test_non_ascii_name_is_not_escaped(self):
        message, _ = self._error("ACCENT_UID", delete_response=[
            {"folderUid": "ACCENT_UID", "responseCode": "access_denied", "errorMessage": "No"}])
        self.assertEqual(message, 'The Keeper server did not delete the folder "Infrastructure/Donn\u00e9es" '
                                  '(UID ACCENT_UID). It returned access_denied: No.')

    def test_quoted_label_in_the_records_and_delete_errors(self):
        sdk = _Sdk(folders=self._folders())
        sdk.client.get_secrets.side_effect = Exception("boom")
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, "NEWLINE_UID")
        self.assertEqual(str(ctx.exception), r'Cannot get records to check if the folder "Infrastructure/Staging\n" '
                                             r'(UID NEWLINE_UID) is empty: boom')

        sdk = _Sdk(folders=self._folders())
        sdk.client.delete_folder.side_effect = Exception("boom")
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, "QUOTE_UID", force=True)
        self.assertEqual(str(ctx.exception), r'Cannot delete the folder "Infrastructure/Data\"bases" (UID QUOTE_UID): '
                                             r'boom')

    def test_quoted_label_in_the_fallback_error(self):
        sdk = _Sdk(folders=self._folders(), delete_response={})
        sdk.client.get_folders.side_effect = [self._folders(), Exception("connection reset")]
        with self.assertRaises(KeeperFolderError) as ctx:
            _delete(sdk, "NEWLINE_UID")
        self.assertEqual(str(ctx.exception),
                         r'The Keeper server sent no result for the delete of the folder "Infrastructure/Staging\n" '
                         r'(UID NEWLINE_UID), and the check of the folder list after it failed, so the folder can '
                         r'still exist. Cannot get folders: connection reset')

    def test_not_found_message_shows_the_uid_as_given(self):
        """The folder UID in the not-found message is the option value, not a folder name, so it is not quoted."""
        sdk = _Sdk(folders=self._folders())
        self.assertEqual(_delete(sdk, "NO_SUCH_UID"), _not_found("NO_SUCH_UID"))


class KeeperDeleteFolderDocumentationTest(unittest.TestCase):
    """The module documentation must match what the plugin does, and the docs stub must match the plugin."""

    COMPONENT_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    @staticmethod
    def _docs():
        import yaml
        stub = importlib.import_module("keeper_secrets_manager_ansible.plugins.modules.keeper_delete_folder")
        return _plugin(), stub, yaml

    def test_docs_stub_is_the_same_as_the_action_plugin_docs(self):
        action, stub, _ = self._docs()
        for name in ["DOCUMENTATION", "EXAMPLES", "RETURN"]:
            with self.subTest(section=name):
                self.assertEqual(getattr(stub, name), getattr(action, name))

    def test_documented_options_match_the_argument_spec(self):
        action, _, yaml = self._docs()
        options = yaml.safe_load(action.DOCUMENTATION)["options"]
        spec = action.ActionModule.ARGUMENT_SPEC
        self.assertEqual(set(options), set(spec))
        for name, doc in options.items():
            with self.subTest(option=name):
                self.assertEqual(doc["type"], spec[name]["type"])
                self.assertEqual(bool(doc.get("required", False)), spec[name].get("required", False))
        self.assertIs(options["force_deletion"]["default"], spec["force_deletion"]["default"])

    def test_docs_name_force_deletion_and_explain_why_it_is_not_force(self):
        action, _, yaml = self._docs()
        docs = yaml.safe_load(action.DOCUMENTATION)
        self.assertIn("unless force_deletion is true.", " ".join(docs["description"]))
        self.assertEqual(
            docs["options"]["force_deletion"]["description"][2],
            "The name is not force, because keeper_copy has a force option with a different meaning, and a "
            "module_defaults entry for the action group of this collection gives its options to every module in it.")
        self.assertIn("There is one exception. An option that a module_defaults entry for an action group of this "
                      "collection sets, and that this module does not have, is ignored.", " ".join(docs["description"]))

    def test_return_documents_the_not_found_message(self):
        action, _, yaml = self._docs()
        returned = yaml.safe_load(action.RETURN)
        self.assertEqual(set(returned), {"folder_uid", "folder_name", "msg"})
        self.assertEqual(returned["msg"]["returned"], "when the folder was not found")
        self.assertEqual(returned["msg"]["sample"], _delete(_Sdk(), "XXXX")["msg"])

    def test_examples_use_only_documented_options(self):
        action, _, yaml = self._docs()
        options = set(yaml.safe_load(action.DOCUMENTATION)["options"])
        deletes = [task["keeper_delete_folder"] for task in yaml.safe_load(action.EXAMPLES)
                   if "keeper_delete_folder" in task]
        self.assertEqual(len(deletes), 4)
        for task_args in deletes:
            self.assertLessEqual(set(task_args), options)
        self.assertEqual([task_args.get("force_deletion") for task_args in deletes], [None, True, None, None],
                         "only the example that deletes everything in the folder sets force_deletion")

    def test_readmes_name_force_deletion(self):
        """Both READMEs must tell the playbook author the new option name, and not the old one."""
        for path in [os.path.join(self.COMPONENT_DIR, "README.md"),
                     os.path.join(self.COMPONENT_DIR, "ansible_galaxy", "keepersecurity", "keeper_secrets_manager",
                                  "README.md")]:
            with self.subTest(readme=path):
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
                self.assertIn("Deletes only an empty folder, unless `force_deletion: yes` is set.", text)
                self.assertNotIn("`force: yes`", text)

    def test_playbook_test_runs_the_documented_idempotent_pattern(self):
        """The playbook test of the idempotent pattern must run the tasks of EXAMPLES, not a variant of them."""
        action, _, yaml = self._docs()
        examples = yaml.safe_load(action.EXAMPLES)
        index = next(i for i, task in enumerate(examples) if "keeper_get_folder" in task)
        lookup, delete = examples[index], examples[index + 1]
        path = os.path.join(os.path.dirname(__file__), "ansible_example", "playbooks",
                            "keeper_delete_folder_idempotent.yml")
        with open(path) as fh:
            tasks = yaml.safe_load(fh)[0]["tasks"]
        for run in [tasks[0:2], tasks[2:4]]:
            with self.subTest(task=run[0]["name"]):
                self.assertEqual(set(run[0]["keeper_get_folder"]), set(lookup["keeper_get_folder"]))
                self.assertEqual(run[0]["keeper_get_folder"]["folder_name"], lookup["keeper_get_folder"]["folder_name"])
                self.assertEqual(run[0]["register"], lookup["register"])
                self.assertEqual(run[0]["failed_when"], lookup["failed_when"])
                self.assertEqual(run[1]["keeper_delete_folder"], delete["keeper_delete_folder"])
                self.assertEqual(run[1]["when"], delete["when"])


if __name__ == "__main__":
    unittest.main()
