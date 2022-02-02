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
    "A_7YpGBUgRTeDEQLhVRo0Q": RecordMaker.make_file(
        uid="A_7YpGBUgRTeDEQLhVRo0Q",
        title="JW-F1-R2-File",
        files=[
            {"name": "nailing it.mp4", "type": "video/mp4", "url": "http://localhost/abc", "data": "ABC123"},
            {"name": "video_file.mp4", "type": "video/mp4", "url": "http://localhost/xzy", "data": "XYZ123"},
        ]
    )
}


def mocked_get_secrets(*args):

    if len(args) > 0:
        uid = args[0][0]
        ret = [records[uid]]
    else:
        ret = [records[x] for x in records]
    return ret


class KeeperInitTest(unittest.TestCase):

    def setUp(self):

        self.yml_file_name = "test_keeper.yml"
        self.json_file_name = "test_keeper.json"

        # Add in addition Python libs. This includes the base
        # module for Keeper Ansible and the Keeper SDK.
        self.base_dir = os.path.dirname(os.path.realpath(__file__))
        self.ansible_base_dir = os.path.join(self.base_dir, "ansible_example")
        self.yml_file = os.path.join(os.path.join(self.ansible_base_dir, self.yml_file_name))
        self.json_file = os.path.join(os.path.join(self.ansible_base_dir, self.json_file_name))
        for file in [self.yml_file, self.json_file]:
            if os.path.exists(file) is True:
                os.unlink(file)

    def tearDown(self):
        for file in [self.yml_file, self.json_file]:
            if os.path.exists(file) is True:
                os.unlink(file)

    def _common(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                base_dir=self.ansible_base_dir,
                playbook=os.path.join("playbooks", "keeper_init.yml"),
                inventory=os.path.join("inventory", "all"),
                plugin_base_dir=os.path.join(os.path.dirname(keeper_secrets_manager_ansible.plugins.__file__)),
                vars={
                    "keeper_token": "US:XXXXXX",
                    "keeper_config_file": self.yml_file_name,
                    "show_config": True
                }
            )
            r, out, err = a.run()
            result = r[0]["localhost"]
            self.assertEqual(result["ok"], 2, "1 things didn't happen")
            self.assertEqual(result["failures"], 0, "failures was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")

            self.assertTrue(os.path.exists(self.yml_file), "test_keeper.yml does not exist")

            a = AnsibleTestFramework(
                base_dir=self.ansible_base_dir,
                playbook=os.path.join("playbooks", "keeper_init.yml"),
                inventory=os.path.join("inventory", "all"),
                plugin_base_dir=os.path.join(os.path.dirname(keeper_secrets_manager_ansible.plugins.__file__)),
                vars={
                    "keeper_token": "US:XXXXXX",
                    "keeper_config_file": self.json_file_name,
                    "show_config": False
                }
            )
            r, out, err = a.run()
            result = r[0]["localhost"]
            self.assertEqual(result["ok"], 2, "1 things didn't happen")
            self.assertEqual(result["failures"], 0, "failures was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")

            self.assertTrue(os.path.exists(self.json_file), "test_keeper.json does not exist")

    # @unittest.skip
    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=mocked_get_secrets)
    def test_keeper_get_mock(self, _):
        self._common()

    @unittest.skip
    def test_keeper_get_live(self):
        self._common()
