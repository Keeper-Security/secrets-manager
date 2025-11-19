import unittest
from keeper_secrets_manager_ansible.plugins.callback.keeper_redact import CallbackModule


class KeeperRedactTest(unittest.TestCase):

    def test_redact_keeper_test(self):
        my_dict = {
            "keeper_config": "ABCDEF",
            "keeper_client_id": "1234",
            "keeper_private_key": "ZXY",
            "Keeper_nothing": "ABC"

        }
        CallbackModule._remove_special_keeper_values(my_dict)
        self.assertEqual(my_dict["keeper_config"], "****")
        self.assertEqual(my_dict["keeper_client_id"], "****")
        self.assertEqual(my_dict["keeper_private_key"], "****")
        self.assertEqual(my_dict["Keeper_nothing"], "ABC")

        real_example = {
          "ansible_included_var_files": [
            "/runner/project/defaults/secrets.yml"
          ],
          "ansible_facts": {
            "keeper_config": "ewo ... p9"
          },
          "_ansible_no_log": False,
          "changed": False
        }
        CallbackModule._remove_special_keeper_values(real_example)
        self.assertEqual(real_example["ansible_facts"]["keeper_config"], "****")
