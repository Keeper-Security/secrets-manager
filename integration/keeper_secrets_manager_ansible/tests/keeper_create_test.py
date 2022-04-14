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
    )
}


def mocked_get_secrets(*args):

    if len(args) > 0:
        uid = args[0][0]
        ret = [records[uid]]
    else:
        ret = [records[x] for x in records]
    return ret


# This is tied to the test. If additional tests are added, they will need their own create_secret mock method.
def mocked_create_secret(*args):

    # First one in the shared folder uid
    _ = args[0]
    record_create = args[1]

    if len(record_create.fields) < 1:
        raise AssertionError("Record create doesn't have enough fields.")
    if len(record_create.fields[1].value) != 1:
        raise AssertionError("Record create doesn't have one password.")

    password = record_create.fields[1].value[0]
    if len(password) != 128:
        raise AssertionError("Record create password is not 128 chars long, only {}.".format(len(password)))

    # Make sure the lowercase letter are not in the password. We are filtering them out.
    for index in range(0, 25):
        char = "abcdefghijklmnopqrstuvwxyz"[index]
        if char in password:
            raise AssertionError("Found a lowercase letter in the password. Not allowed in this test.")

    return "NEW_UID"


class KeeperCreateTest(unittest.TestCase):

    def setUp(self):

        # Add in addition Python libs. This includes the base
        # module for Keeper Ansible and the Keeper SDK.
        self.base_dir = os.path.dirname(os.path.realpath(__file__))
        self.ansible_base_dir = os.path.join(self.base_dir, "ansible_example")

    def _common(self):
        with tempfile.TemporaryDirectory() as _:
            a = AnsibleTestFramework(
                base_dir=self.ansible_base_dir,
                playbook=os.path.join("playbooks", "keeper_create.yml"),
                inventory=os.path.join("inventory", "all"),
                plugin_base_dir=os.path.join(os.path.dirname(keeper_secrets_manager_ansible.plugins.__file__)),
                vars={
                    "shared_folder_uid": "XXXXX"
                }
            )
            r, out, err = a.run()
            result = r[0]["localhost"]
            print("OUT", out)
            print("ERR", err)
            self.assertEqual(result["ok"], 3, "3 things didn't happen")
            self.assertEqual(result["failures"], 0, "failures was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")

    # @unittest.skip
    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=mocked_get_secrets)
    @patch("keeper_secrets_manager_core.core.SecretsManager.create_secret", side_effect=mocked_create_secret)
    def test_keeper_create_mock(self, mock_create, mock_get):
        self._common()

    @unittest.skip
    def test_keeper_create_live(self):
        self._common()
