import unittest
from keeper_secrets_manager_core.mock import Record, Response
from .ansible_test_framework import AnsibleTestFramework
import tempfile


mock_response = Response()
mock_record = Record(title="Record 1", record_type="login")
mock_record.field("password", "MYPASSWORD")
mock_response.add_record(record=mock_record)


class KeeperGetTest(unittest.TestCase):

    def test_keeper_get(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_get.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": mock_record.uid,
                    "title": mock_record.title
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 4, "4 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            self.assertRegex(out, r'BY UID MYPASSWORD', "Did not find the password in the stdout")
            self.assertRegex(out, r'BY TITLE MYPASSWORD', "Did not find the password in the stdout")

    def test_keeper_get_cache(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_get_cache.yml",
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
