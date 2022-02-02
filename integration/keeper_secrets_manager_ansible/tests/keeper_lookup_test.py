import unittest
from unittest.mock import patch
import os
import keeper_secrets_manager_ansible.plugins
from .ansible_test_framework import AnsibleTestFramework, RecordMaker
import tempfile


records = {
    "TRd_567FkHy-CeGsAzs8aA": RecordMaker.make_record(
        uid="TRd_567FkHy-CeGsAzs8aA",
        title="JW-F1-R1",
        fields={
            "password": "ddd",
            "login": "aaa",
            "phone": [
                {'number': '(555) 123-2222', 'type': 'Work', 'ext': '6666'},
                {'number': '(555) 789-3333', 'type': 'Mobile'}
            ]
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


def get_secrets(*args):

    if len(args) > 0:
        uid = args[0][0]
        ret = [records[uid]]
    else:
        ret = [records[x] for x in records]
    return ret


class KeeperLookupTest(unittest.TestCase):

    def setUp(self):

        # Add in addition Python libs. This includes the base
        # module for Keeper Ansible and the Keeper SDK.
        self.base_dir = os.path.dirname(os.path.realpath(__file__))
        self.ansible_base_dir = os.path.join(self.base_dir, "ansible_example")

    def _common(self):
        with tempfile.TemporaryDirectory() as temp_dir:

            a = AnsibleTestFramework(
                base_dir=self.ansible_base_dir,
                playbook=os.path.join("playbooks", "keeper_lookup.yml"),
                inventory=os.path.join("inventory", "all"),
                plugin_base_dir=os.path.join(os.path.dirname(keeper_secrets_manager_ansible.plugins.__file__)),
                vars={
                    "tmp_dir": temp_dir,
                    "uid": "TRd_567FkHy-CeGsAzs8aA"
                }
            )
            r, out, err = a.run()
            result = r[0]["localhost"]
            self.assertEqual(result["ok"], 5, "5 things didn't happen")
            self.assertEqual(result["failures"], 0, "failures was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")

            self.assertRegex(out, r'My password is ddd', "did not find the password debug message")
            self.assertRegex(out, r'My login is aaa', "did not find the login debug message")

            self.assertRegex(out, r"My phone_1 is \{'number': '\(555\) 123-2222",
                             "did not find the phone_1 debug message")
            self.assertRegex(out, r"My phone_2 is \[\{'number': '\(555\) 123-2222.*'number': '\(555\) 789-3333'",
                             "did not find the phone_2 debug message")

    # @unittest.skip
    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=get_secrets)
    def test_keeper_lookup_mock(self, _):
        self._common()

    @unittest.skip
    def test_keeper_lookup_live(self):
        self._common()
