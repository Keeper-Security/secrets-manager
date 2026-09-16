import unittest
from unittest.mock import patch
from keeper_secrets_manager_core.mock import Record, Response
from .ansible_test_framework import AnsibleTestFramework
import tempfile


mock_response = Response()
mock_record = Record(title="Record 1", record_type="login")
mock_record.field("password", "MYPASSWORD")
mock_response.add_record(record=mock_record)


# This is tied to the test. If additional tests are added, they will need their own create_secret mock method.
def mocked_create_secret(*args):

    # args[0] is a CreateOptions object (folder_uid, subfolder_uid)
    create_options = args[0]

    if create_options.folder_uid != "SHARED_FOLDER_UID":
        raise AssertionError(
            "The shared folder uid was not passed to CreateOptions. Got {}".format(create_options.folder_uid)
        )
    if create_options.subfolder_uid != "SUBFOLDER_UID":
        raise AssertionError(
            "The subfolder uid was not passed to CreateOptions. Got {}".format(create_options.subfolder_uid)
        )

    return "NEW_UID"


class KeeperCreateSubfolderTest(unittest.TestCase):

    @patch("keeper_secrets_manager_core.core.SecretsManager.create_secret_with_options", side_effect=mocked_create_secret)
    def test_keeper_create_in_subfolder(self, mock_create):
        with tempfile.TemporaryDirectory() as _:
            a = AnsibleTestFramework(
                playbook="keeper_create_subfolder.yml",
                vars={
                    "shared_folder_uid": "SHARED_FOLDER_UID",
                    "subfolder_uid": "SUBFOLDER_UID"
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 2, "2 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
