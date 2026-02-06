import unittest
from keeper_secrets_manager_core.mock import Record, Response
from .ansible_test_framework import AnsibleTestFramework
import tempfile


mock_response = Response()
mock_record = Record(title="Record 1", record_type="login")
mock_record.field("password", "MYPASSWORD")
mock_response.add_record(record=mock_record)


class KeeperGetTest(unittest.TestCase):

    def test_keeper_get(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_get.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": mock_record.uid,
                    "title": mock_record.title
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 4, "4 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            self.assertRegex(out, r'BY UID MYPASSWORD', "Did not find the password in the stdout")
            self.assertRegex(out, r'BY TITLE MYPASSWORD', "Did not find the password in the stdout")

    def test_keeper_get_cache(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_get_cache.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid":  mock_record.uid,
                    "title": mock_record.title
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 7, "7 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            self.assertRegex(out, r'MYPASSWORD', "Did not find the password in the stdout")

    def test_keeper_get_notes(self):
        """Test retrieving notes field from a record"""

        # Create a mock response with a record containing notes
        notes_response = Response()
        notes_record = Record(title="Record With Notes", record_type="login")
        notes_record.field("password", "TESTPASSWORD")
        notes_record.notes = "These are my secret notes"
        notes_response.add_record(record=notes_record)

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_get_notes.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": notes_record.uid,
                    "title": notes_record.title
                },
                mock_responses=[notes_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 2, "2 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            self.assertRegex(out, r'NOTES: These are my secret notes', "Did not find the notes in the stdout")

    def test_keeper_get_notes_empty(self):
        """Test retrieving notes field from a record with empty notes - should fail gracefully"""

        # Create a mock response with a record WITHOUT notes
        empty_notes_response = Response()
        empty_notes_record = Record(title="Record Without Notes", record_type="login")
        empty_notes_record.field("password", "TESTPASSWORD")
        # Explicitly do NOT set notes_record.notes
        empty_notes_response.add_record(record=empty_notes_record)

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_get_notes_empty.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": empty_notes_record.uid,
                },
                mock_responses=[empty_notes_response]
            )
            result, out, err = a.run()

            # Verify the error message does NOT say "Cannot find key True"
            self.assertNotIn("Cannot find key True", err,
                           "Should not show 'Cannot find key True' error")
            self.assertNotIn("Cannot find key True", out,
                           "Should not show 'Cannot find key True' error")
