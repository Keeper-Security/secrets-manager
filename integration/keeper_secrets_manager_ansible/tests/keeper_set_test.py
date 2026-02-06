import unittest
from keeper_secrets_manager_core.mock import Record, Response
from .ansible_test_framework import AnsibleTestFramework
import tempfile


mock_response = Response()
mock_record = Record(title="Record 1", record_type="login")
mock_record.field("password", "MYPASSWORD")
mock_response.add_record(record=mock_record)


class KeeperGetTest(unittest.TestCase):

    def test_keeper_set(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_set.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": mock_record.uid,
                    "title": mock_record.title,
                    "new_password": "NEWPASSWORD"
                },
                mock_responses=[mock_response, mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 3, "3 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            assert '"updated": true' in out

    def test_keeper_set_cache(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_set_cache.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid":  mock_record.uid,
                    "title": mock_record.title,
                    "new_password": "NEWPASSWORD"
                },
                mock_responses=[mock_response, mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 6, "6 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            assert '"updated": true' in out

    def test_keeper_set_notes(self):
        """Test setting notes field value using keeper_set with notes: yes parameter"""

        # Create a mock response with a record that has initial notes
        notes_response = Response()
        notes_record = Record(title="Record With Notes", record_type="login")
        notes_record.field("password", "TESTPASSWORD")
        notes_record.notes = "Initial notes content"
        notes_response.add_record(record=notes_record)

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_set_notes.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": notes_record.uid,
                    "new_notes": "Updated notes content"
                },
                mock_responses=[notes_response, notes_response]
            )
            result, out, err = a.run()

            # Verify all tasks succeeded
            self.assertEqual(result["failed"], 0, "Task should not fail")
            self.assertEqual(result["ok"], 4, "4 tasks should succeed")

            # Verify the set operation reported success
            self.assertIn('"updated": true', out,
                         "Set operation should report updated: true")

            # Verify the new notes value appears in output
            self.assertIn("Updated notes content", out,
                         "Retrieved notes should match the value we set")
