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

    def test_keeper_init(self):
        # The config file is written for a YAML name and for a JSON name, with and without show_config.
        for file_name, show_config in (("test_keeper.yml", True), ("test_keeper.json", False)):
            with self.subTest(file_name=file_name), tempfile.TemporaryDirectory() as temp_dir:
                config_file = os.path.join(temp_dir, file_name)
                a = AnsibleTestFramework(
                    playbook="keeper_init.yml",
                    vars={
                        "keeper_token": "US:XXXXXX",
                        "keeper_config_file": config_file,
                        "show_config": show_config
                    },
                    mock_responses=[mock_response]
                )
                result, out, err = a.run()
                self.assertEqual(result["ok"], 1, "1 things didn't happen")
                self.assertEqual(result["failed"], 0, "failed was not 0")
                self.assertEqual(result["changed"], 1, "initialization should report changed")

                self.assertTrue(os.path.exists(config_file), file_name + " does not exist")
                del a
