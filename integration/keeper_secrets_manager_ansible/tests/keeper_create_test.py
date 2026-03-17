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
    _ = args[0]
    record_create = args[1]

    if len(record_create.fields) < 1:
        raise AssertionError("Record create doesn't have enough fields.")
    if len(record_create.fields[1].value) != 1:
        raise AssertionError("Record create doesn't have one password.")

    password_value = None
    for field in record_create.fields:
        if field.type == "password":
            password_value = field.value
            break
    if password_value is None:
        raise AssertionError("Could not find password field in record")
    if len(password_value) == 0:
        raise AssertionError("Found password field, but the value is blank.")

    password = password_value[0]
    if len(password) != 128:
        raise AssertionError("Record create password is not 128 chars long, only {}.".format(len(password)))

    # Make sure the lowercase letter are not in the password. We are filtering them out.
    for index in range(0, 25):
        char = "abcdefghijklmnopqrstuvwxyz"[index]
        if char in password:
            raise AssertionError("Found a lowercase letter in the password. Not allowed in this test.")

    return "NEW_UID"


class KeeperCreateTest(unittest.TestCase):

    @patch("keeper_secrets_manager_core.core.SecretsManager.create_secret_with_options", side_effect=mocked_create_secret)
    def test_keeper_create(self, mock_create):
        with tempfile.TemporaryDirectory() as _:
            a = AnsibleTestFramework(
                playbook="keeper_create.yml",
                vars={
                    "shared_folder_uid": "XXXXX"
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 2, "2 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
