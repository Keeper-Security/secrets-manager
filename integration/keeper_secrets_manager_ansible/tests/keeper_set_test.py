import unittest
from unittest.mock import patch
import os
import sys
from .ansible_test_framework import AnsibleTestFramework, RecordMaker
import tempfile
import json
import pickle


os.environ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "Yes"


# Our fake data. Two login records and a file record with two attached files.
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
            {"name": "some.crt", "type": "video/mp4", "url": "http://localhost/xzy", "data": "XYZ123"},
        ]
    )
}

# Pickle? That's right. For some reason, mocked method protect variable outside of their scope. That means
# if we save a record, there is no way to update the dictionary. Tried multiple ways, whenever the mock method
# is exited the changes are lost. So instead we are going to create a file on disk and we are going to pickle our
# dictionary. When we want to read it, we un-pickle the file. When we want to save it, we pickle and overwrite the
# existing file.
pickle_file_name = "default_pickle_file"


def get_secrets(*args):

    global pickle_file_name
    with open(pickle_file_name, "rb") as fh:
        local_records = pickle.load(fh)
        fh.close()

        if len(args) > 0:
            uid = args[0][0]
            record = local_records[uid]
            ret = [record]
        else:
            ret = [local_records[x] for x in local_records]
        return ret


def save(*args):

    global pickle_file_name
    with open(pickle_file_name, "rb") as fh:
        local_records = pickle.load(fh)
        fh.close()

        record = args[0]
        record.dict = json.loads(record.raw_json)
        password_field = next((item for item in record.dict["fields"] if item["type"] == "password"), None)
        record.password = password_field.get('value')[0]
        local_records.update({record.uid: record})

        with open(pickle_file_name, "wb") as fh:
            pickle.dump(local_records, fh)
            fh.close()


class KeeperSetTest(unittest.TestCase):

    def setUp(self):

        # Add in addition Python libs. This includes the base
        # module for Keeper Ansible and the Keeper SDK.
        self.base_dir = os.path.dirname(os.path.realpath(__file__))
        self.ansible_base_dir = os.path.join(self.base_dir, "ansible_example")

        # Create a temp place to the record files. Delete it in the tear down of the test.
        self.records_file = tempfile.NamedTemporaryFile(delete=False)

        # The mock methods are global, need to place the name of the pickle jar globally.
        global pickle_file_name
        pickle_file_name = self.records_file.name

        with open(pickle_file_name, "wb") as fh:
            pickle.dump(records, fh)
            fh.close()

    def tearDown(self):
        os.remove(self.records_file .name)

    def _common(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            a = AnsibleTestFramework(
                base_dir= self.ansible_base_dir,
                playbook=os.path.join("playbooks", "keeper_set.yml"),
                inventory=os.path.join("inventory", "all"),
                plugin_base_dir=os.path.join(self.base_dir, "..", "plugins"),
                vars={
                    "tmp_dir": temp_dir,
                    "uid": "TRd_567FkHy-CeGsAzs8aA",
                    "new_password": "NEW PASSWORD"
                }
            )
            r, out, err = a.run()
            print("OUT", out)
            print("ERR", err)
            result = r[0]["localhost"]

            self.assertEqual(result["ok"], 7, "6 things didn't happen")
            self.assertEqual(result["failures"], 0, "failures was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")

            self.assertRegex(out, r'Current Password password_ddd', "did not find current password")
            self.assertRegex(out, r'New Password NEW PASSWORD', "did not find new password")

    #@unittest.skip
    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=get_secrets)
    @patch("keeper_secrets_manager_core.core.SecretsManager.save", side_effect=save)
    def test_keeper_lookup_mock(self, mock_get_secrets, mock_save):
        self._common()

    @unittest.skip
    def test_keeper_lookup_live(self):
        self._common()
