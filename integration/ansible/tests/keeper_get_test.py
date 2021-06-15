import unittest
from unittest.mock import patch
import os
import sys
from .ansible_test_framework import AnsibleTestFramework, RecordMaker
import tempfile


records = {
    "EG6KdJaaLG7esRZbMnfbFA": RecordMaker.make_record(
        uid="EG6KdJaaLG7esRZbMnfbFA",
        title="JW-F1-R1",
        value="aaa"
    ),
    "TRd_567FkHy-CeGsAzs8aA": RecordMaker.make_record(
        uid="TRd_567FkHy-CeGsAzs8aA",
        title="JW-F1-R1",
        value="ddd"
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


def mocked_commander_get_secrets(*args):

    if len(args) > 0:
        uid = args[0][0]
        ret = [records[uid]]
    else:
        ret = [records[x] for x in records]
    return ret


class KeeperGetTest(unittest.TestCase):

    def setUp(self):

        # Add in addition Python libs. This includes the base
        # module for Keeper Ansible and the Keeper SDK.
        self.base_dir = os.path.dirname(os.path.realpath(__file__))
        sys.path.append(os.path.join(self.base_dir, "..", "modules"))
        sys.path.append(os.path.join(self.base_dir, "..", "..", "..", "..", "sdk", "python", "core"))

        self.ansible_base_dir = os.path.join(self.base_dir, "ansible_example")

    def _common(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                base_dir=self.ansible_base_dir,
                playbook=os.path.join("playbooks", "keeper_get.yml"),
                inventory=os.path.join("inventory", "all"),
                plugin_base_dir=os.path.join(self.base_dir, "..", "plugins"),
                vars={
                    "tmp_dir": temp_dir,
                    "uid": "TRd_567FkHy-CeGsAzs8aA"
                }
            )
            r, out, err = a.run()
            result = r[0]["localhost"]
            self.assertEqual(result["ok"], 3, "3 things didn't happen")
            self.assertEqual(result["failures"], 0, "failures was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            self.assertRegex(out, r'password_ddd', "Did not find the password in the stdout")

    #@unittest.skip
    @patch("keepercommandersm.Commander.get_secrets", side_effect=mocked_commander_get_secrets)
    def test_keeper_get_mock(self, mock_commander_get_secrets):
        self._common()

    @unittest.skip
    def test_keeper_get_live(self):
        self._common()
