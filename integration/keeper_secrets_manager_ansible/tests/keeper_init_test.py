import unittest
from .ansible_test_framework import AnsibleTestFramework
from keeper_secrets_manager_core.mock import Record, Response
import tempfile
import os


mock_response = Response()
mock_record = Record(title="Record 1", record_type="login")
mock_record.field("password", "MYPASSWORD")
mock_response.add_record(record=mock_record)


class KeeperInitTest(unittest.TestCase):

    def test_keeper_init_yaml(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            yml_file = os.path.join(os.path.join(temp_dir, "test_keeper.yml"))
            a = AnsibleTestFramework(
                playbook="keeper_init.yml",
                vars={
                    "keeper_token": "US:XXXXXX",
                    "keeper_config_file": yml_file,
                    "show_config": True
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 1, "1 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")

            self.assertTrue(os.path.exists(yml_file), "test_keeper.yml does not exist")
            del a

    def test_keeper_init_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            json_file = os.path.join(os.path.join(temp_dir, "test_keeper.json"))
            a = AnsibleTestFramework(
                playbook="keeper_init.yml",
                vars={
                    "keeper_token": "US:XXXXXX",
                    "keeper_config_file": json_file,
                    "show_config": False
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 1, "1 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")

            self.assertTrue(os.path.exists(json_file), "test_keeper.json does not exist")
            del a
