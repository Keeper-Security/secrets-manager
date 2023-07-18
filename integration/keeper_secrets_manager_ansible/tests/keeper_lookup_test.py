import unittest
from keeper_secrets_manager_core.mock import Record, Response
from .ansible_test_framework import AnsibleTestFramework
import tempfile

mock_response = Response()
mock_record = Record(title="Record 1", record_type="login")
mock_record.field("login", "MYLOGIN")
mock_record.field("password", "MYPASSWORD")
mock_record.field("phone", [
    {'number': '(555) 123-2222', 'type': 'Work', 'ext': '6666'},
    {'number': '(555) 789-3333', 'type': 'Mobile'}
])
mock_response.add_record(record=mock_record)


class KeeperLookupTest(unittest.TestCase):

    def test_keeper_lookup(self):
        with tempfile.TemporaryDirectory() as temp_dir:

            a = AnsibleTestFramework(
                playbook="keeper_lookup.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": mock_record.uid,
                    "title": mock_record.title
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 6, "6 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")

            self.assertRegex(out, r'My password is MYPASSWORD')
            self.assertRegex(out, r'My login is MYLOGIN')
            self.assertRegex(out, r"My phone_1 is \{'number': '\(555\) 123-2222")
            self.assertRegex(out, r"My phone_2 is \[\{'number': '\(555\) 123-2222.*'number': '\(555\) 789-3333'",)
            self.assertRegex(out, r"My phone_2 number by UID is \(555\) 789-3333")
            self.assertRegex(out, r"My phone_2 number by TITLE is \(555\) 789-3333")

    def test_keeper_lookup_cache(self):
        with tempfile.TemporaryDirectory() as temp_dir:

            a = AnsibleTestFramework(
                playbook="keeper_lookup_cache.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": mock_record.uid,
                    "title": mock_record.title
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 9, "9 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")

            self.assertRegex(out, r'My password is MYPASSWORD')
            self.assertRegex(out, r'My login is MYLOGIN')
            self.assertRegex(out, r"My phone_1 is \{'number': '\(555\) 123-2222")
            self.assertRegex(out, r"My phone_2 is \[\{'number': '\(555\) 123-2222.*'number': '\(555\) 789-3333'",)
            self.assertRegex(out, r"My phone_2 number by UID is \(555\) 789-3333")
            self.assertRegex(out, r"My phone_2 number by TITLE is \(555\) 789-3333")


