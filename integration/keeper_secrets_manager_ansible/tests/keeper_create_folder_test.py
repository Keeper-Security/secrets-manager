import unittest
from unittest.mock import patch
from keeper_secrets_manager_core.mock import Response
from keeper_secrets_manager_core.dto.dtos import KeeperFolder
from .ansible_test_framework import AnsibleTestFramework
import tempfile


mock_response = Response()


def mocked_get_folders_empty(*args, **kwargs):
    # No folders exist yet, so both tasks in the playbook should go on to create one.
    return []


def mocked_get_folders_existing(*args, **kwargs):
    # A folder matching each task's target name/parent already exists.
    return [
        KeeperFolder(b"fake_key", "EXISTING_FOLDER_UID", "SHARED_FOLDER_UID", "My New Folder"),
        KeeperFolder(b"fake_key", "EXISTING_NESTED_FOLDER_UID", "SUBFOLDER_UID", "My New Nested Folder"),
    ]


# This is tied to the test playbook. If additional tasks are added, they will need their own
# entry in this mock.
def mocked_create_folder(*args, **kwargs):

    # args[0] is a CreateOptions object (folder_uid, subfolder_uid)
    # args[1] is the folder_name
    create_options = args[0]
    folder_name = args[1]

    if create_options.folder_uid != "SHARED_FOLDER_UID":
        raise AssertionError(
            "The shared folder uid was not passed to CreateOptions. Got {}".format(create_options.folder_uid)
        )

    # First task in the playbook creates a folder directly in the shared folder, no subfolder_uid.
    if create_options.subfolder_uid is None:
        if folder_name != "My New Folder":
            raise AssertionError("Unexpected folder name for shared folder create: {}".format(folder_name))
        return "NEW_FOLDER_UID"

    # Second task in the playbook creates a folder nested in a subfolder.
    if create_options.subfolder_uid != "SUBFOLDER_UID":
        raise AssertionError(
            "The subfolder uid was not passed to CreateOptions. Got {}".format(create_options.subfolder_uid)
        )
    if folder_name != "My New Nested Folder":
        raise AssertionError("Unexpected folder name for nested create: {}".format(folder_name))

    return "NEW_NESTED_FOLDER_UID"


def mocked_create_folder_should_not_be_called(*args, **kwargs):
    raise AssertionError("create_folder should not have been called - a matching folder already exists")


class KeeperCreateFolderTest(unittest.TestCase):

    @patch("keeper_secrets_manager_core.core.SecretsManager.get_folders", side_effect=mocked_get_folders_empty)
    @patch("keeper_secrets_manager_core.core.SecretsManager.create_folder", side_effect=mocked_create_folder)
    def test_keeper_create_folder(self, mock_create_folder, mock_get_folders):
        # Neither target folder exists yet, so both tasks should create one and report changed.
        with tempfile.TemporaryDirectory() as _:
            a = AnsibleTestFramework(
                playbook="keeper_create_folder.yml",
                vars={
                    "shared_folder_uid": "SHARED_FOLDER_UID",
                    "subfolder_uid": "SUBFOLDER_UID"
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 4, "4 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 2, "the 2 create tasks should have reported changed")

    @patch(
        "keeper_secrets_manager_core.core.SecretsManager.get_folders",
        side_effect=mocked_get_folders_existing
    )
    @patch(
        "keeper_secrets_manager_core.core.SecretsManager.create_folder",
        side_effect=mocked_create_folder_should_not_be_called
    )
    def test_keeper_create_folder_is_idempotent(self, mock_create_folder, mock_get_folders):
        # Both target folders already exist, so re-running should not create duplicates and
        # should report changed=False for both tasks.
        with tempfile.TemporaryDirectory() as _:
            a = AnsibleTestFramework(
                playbook="keeper_create_folder.yml",
                vars={
                    "shared_folder_uid": "SHARED_FOLDER_UID",
                    "subfolder_uid": "SUBFOLDER_UID"
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 4, "4 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "no folders should have been created on the second run")
