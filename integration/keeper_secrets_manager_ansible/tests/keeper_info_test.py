import unittest
from keeper_secrets_manager_core.mock import Record, Response
from .ansible_test_framework import AnsibleTestFramework
import tempfile


mock_response = Response()
mock_record = Record(title="Record 1", record_type="login")
mock_record.field("password", "MYPASSWORD")
mock_response.add_record(record=mock_record)


class KeeperInfoTest(unittest.TestCase):

    def test_keeper_info(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_info.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": mock_record.uid
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 1, "1 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            assert "field_type_list" in out
            assert "record_type_list" in out
            assert "CUSTOM RECORD" in out
