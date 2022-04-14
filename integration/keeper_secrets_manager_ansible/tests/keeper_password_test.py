import unittest
from unittest.mock import patch
import os
from .ansible_test_framework import AnsibleTestFramework, RecordMaker
import keeper_secrets_manager_ansible.plugins
import tempfile


records = {
    "TRd_567FkHy-CeGsAzs8aA": RecordMaker.make_record(
        uid="TRd_567FkHy-CeGsAzs8aA",
        title="JW-F1-R1",
        fields={
          "password": "ddd"
        }
    ),
}


def mocked_get_secrets(*args):

    if len(args) > 0:
        uid = args[0][0]
        ret = [records[uid]]
    else:
        ret = [records[x] for x in records]
    return ret


class KeeperPasswordTest(unittest.TestCase):

    def setUp(self):

        # Add in addition Python libs. This includes the base
        # module for Keeper Ansible and the Keeper SDK.
        self.base_dir = os.path.dirname(os.path.realpath(__file__))
        self.ansible_base_dir = os.path.join(self.base_dir, "ansible_example")

    def _common(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                base_dir=self.ansible_base_dir,
                playbook=os.path.join("playbooks", "keeper_password.yml"),
                inventory=os.path.join("inventory", "all"),
                plugin_base_dir=os.path.join(os.path.dirname(keeper_secrets_manager_ansible.plugins.__file__))
            )
            r, out, err = a.run()
            result = r[0]["localhost"]
            print("OUT", out)
            print("ERR", err)
            self.assertEqual(result["ok"], 5, "5 things didn't happen")
            self.assertEqual(result["failures"], 0, "failures was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")

    # @unittest.skip
    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=mocked_get_secrets)
    def test_keeper_password_mock(self, _):
        self._common()

    @unittest.skip
    def test_keeper_password_live(self):
        self._common()
