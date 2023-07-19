import unittest
from keeper_secrets_manager_core.mock import Record, Response
from .ansible_test_framework import AnsibleTestFramework
import tempfile


mock_response = Response()
mock_record = Record(title="Record 1", record_type="login")
mock_record.field("password", "MYPASSWORD")
mock_response.add_record(record=mock_record)


class KeeperGetTest(unittest.TestCase):

    def test_keeper_set(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_set.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": mock_record.uid,
                    "title": mock_record.title,
                    "new_password": "NEWPASSWORD"
                },
                mock_responses=[mock_response, mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 3, "3 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            assert '"updated": true' in out

    def test_keeper_set_cache(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_set_cache.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid":  mock_record.uid,
                    "title": mock_record.title,
                    "new_password": "NEWPASSWORD"
                },
                mock_responses=[mock_response, mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 6, "6 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            assert '"updated": true' in out
