import unittest
from keeper_secrets_manager_core.mock import Record, Response
from .ansible_test_framework import AnsibleTestFramework
import tempfile


mock_response = Response()
mock_record = Record(title="Record 1", record_type="login")
mock_record.field("login", "MYLOGIN")
mock_record.field("password", "MYPASSWORD")
mock_record.field("text", "TEXT", "Text Label")
mock_record.field("phone", [
    {
        "number": "15551234",
        "type": "Home"
    },
    {
        "number": "15557890",
        "type": "Work"
    }
])
mock_record.field("fileRef", ["XXXXX", "YYYYY"])
mock_record.custom_field("C1","CUSTOM 1", field_type="text")
mock_record.custom_field("D1", "DUP 1", field_type="text")
mock_record.custom_field("D1", "DUP 2", field_type="text")
mock_record.custom_field("This! **I$** A Bad Label...", "BAD", field_type="text")
mock_record.custom_field("  This! **I$** A Bad Label...", "BAD 2", field_type="text")
mock_response.add_record(record=mock_record)

class KeeperGetRecordTest(unittest.TestCase):

    def test_keeper_get_record(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_get_record.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": mock_record.uid,
                    "title": mock_record.title
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 8, "8 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")



    def test_keeper_get_record_cache(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_get_record_cache.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid":  mock_record.uid,
                    "title": mock_record.title
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 7, "7 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            self.assertRegex(out, r'MYPASSWORD', "Did not find the password in the stdout")
