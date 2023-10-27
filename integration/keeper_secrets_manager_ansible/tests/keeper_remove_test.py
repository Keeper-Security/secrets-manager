import unittest
from unittest.mock import patch
from keeper_secrets_manager_core.mock import Record, Response
from .ansible_test_framework import AnsibleTestFramework
import tempfile



mock_record_1 = Record(title="Record 1", record_type="login")
mock_record_1.field("password", "PASS 1")
mock_record_2 = Record(title="Record 2", record_type="login")
mock_record_2.field("password", "PASS 2")

mock_response_1 = Response()
mock_response_1.add_record(record=mock_record_1)
mock_response_1.add_record(record=mock_record_2)
mock_response_1.add_record(record=mock_record_1)
mock_response_1.add_record(record=mock_record_2)


mock_response_2 = Response()
mock_response_2.add_record(record=mock_record_1)
mock_response_2.add_record(record=mock_record_2)
mock_response_2.add_record(record=mock_record_1)
mock_response_2.add_record(record=mock_record_2)


class KeeperRemoveTest(unittest.TestCase):

    def test_keeper_remove(self):

        with patch(f'keeper_secrets_manager_core.SecretsManager.delete_secret') as mock_delete:
            mock_delete.return_value = None

            with tempfile.TemporaryDirectory() as temp_dir:
                a = AnsibleTestFramework(
                    playbook="keeper_remove.yml",
                    vars={
                        "tmp_dir": temp_dir,
                        "uid": mock_record_1.uid,
                        "title": mock_record_2.title
                    },
                    mock_responses=[mock_response_1]
                )
                result, out, err = a.run()
                self.assertEqual(result["ok"], 2, "2 things didn't happen")
                self.assertEqual(result["failed"], 0, "failed was not 0")
                self.assertEqual(result["changed"], 0, "0 things didn't change")

    def test_keeper_remove_cache(self):

        with patch(f'keeper_secrets_manager_core.SecretsManager.delete_secret') as mock_delete:
            mock_delete.return_value = None

            with tempfile.TemporaryDirectory() as temp_dir:
                a = AnsibleTestFramework(
                    playbook="keeper_remove_cache.yml",
                    vars={
                        "tmp_dir": temp_dir,
                        "uid":  mock_record_1.uid,
                        "title": mock_record_2.title
                    },
                    mock_responses=[mock_response_2]
                )
                result, out, err = a.run()
                self.assertEqual(result["ok"], 5, "5 things didn't happen")
                self.assertEqual(result["failed"], 0, "failed was not 0")
                self.assertEqual(result["changed"], 0, "0 things didn't change")
