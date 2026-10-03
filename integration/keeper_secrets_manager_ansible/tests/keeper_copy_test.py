import unittest
from unittest.mock import patch
from keeper_secrets_manager_core.mock import Record, Response as MockResponse
from .ansible_test_framework import AnsibleTestFramework
import tempfile
from requests import Response
import os


all_respones = MockResponse()

mock_record_1 = Record(title="Password Record", record_type="login")
mock_record_1.field("login", "MYLOGIN_1")
mock_record_1.field("password", "MYPASSWORD_2")
mock_file_1 = mock_record_1.add_file(name='nailing it.mp4', title='Nailing It', url="http://localhost/abc",
                                     content='ABC123')
mock_file_2 = mock_record_1.add_file(name='some.crt', title='Some Sert', url="http://localhost/xzy",
                                     content='XYZ123')
all_respones.add_record(record=mock_record_1)


lookup = {
    mock_record_1.uid: mock_record_1,
}


def mock_download_get(url, **kwargs):
    mock_res = Response()
    mock_res.status_code = 200
    mock_res.reason = "OK"
    mock_res._content = mock_file_1.downloadable_content()
    return mock_res


class KeeperCopyTest(unittest.TestCase):

    def test_keeper_copy(self):

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('requests.get', side_effect=mock_download_get) as _:
                a = AnsibleTestFramework(
                    playbook="keeper_copy.yml",
                    vars={
                        "tmp_dir": temp_dir,
                        "password_uid": mock_record_1.uid,
                        "password_title": mock_record_1.title,
                        "file_uid": mock_record_1.uid,
                        "file_name": "Nailing It"
                    },
                    mock_responses=[all_respones]
                )
                result, out, err = a.run()
                self.assertEqual(result["ok"], 4, "4 things didn't happen")
                self.assertEqual(result["failed"], 0, "failed was not 0")
                self.assertEqual(result["changed"], 3, "3 things didn't change")
                ls = os.listdir(temp_dir)
                self.assertTrue("password" in ls, "did not find file password")
                self.assertTrue("video.mp4" in ls, "did not find file video.mp4")

    def test_keeper_copy_cache(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('requests.get', side_effect=mock_download_get) as _:
                a = AnsibleTestFramework(
                    playbook="keeper_copy_cache.yml",
                    vars={
                        "tmp_dir": temp_dir,
                        "password_uid": mock_record_1.uid,
                        "password_title": mock_record_1.title,
                        "file_uid": mock_record_1.uid,
                        "file_name": "Nailing It"
                    },
                    mock_responses=[all_respones]
                )
                result, out, err = a.run()
                self.assertEqual(result["ok"], 7, "7 things didn't happen")
                self.assertEqual(result["failed"], 0, "failed was not 0")
                self.assertEqual(result["changed"], 3, "3 things didn't change")
                ls = os.listdir(temp_dir)
                self.assertTrue("password" in ls, "did not find file password")
                self.assertTrue("video.mp4" in ls, "did not find file video.mp4")

    def test_keeper_copy_notes(self):
        """Test copying notes field to a file using keeper_copy with notes: yes parameter"""

        # Create a mock response with a record containing notes
        notes_response = MockResponse()
        notes_record = Record(title="Record With Notes", record_type="login")
        notes_record.field("password", "TESTPASSWORD")
        notes_record.notes = "These are my secret notes"
        notes_response.add_record(record=notes_record)

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_copy_notes.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uid": notes_record.uid,
                },
                mock_responses=[notes_response]
            )
            result, out, err = a.run()

            # Verify the task succeeded
            self.assertEqual(result["failed"], 0, "Task should not fail")
            self.assertEqual(result["ok"], 4, "4 tasks should succeed")
            self.assertEqual(result["changed"], 2, "2 things should change (file copy + command)")

            # Verify notes were copied to file
            notes_file = os.path.join(temp_dir, "notes.txt")
            self.assertTrue(os.path.exists(notes_file), "Notes file should exist")

            # Verify file contents match the notes
            with open(notes_file, 'r') as f:
                content = f.read()
            self.assertEqual(content, "These are my secret notes",
                           "Notes content should match record notes")

            # Verify the output contains the notes
            self.assertRegex(out, r'NOTES: These are my secret notes',
                           "Output should contain the notes content")


class KeeperCopyDiffTest(unittest.TestCase):

    def test_keeper_copy_diff_does_not_show_the_secret(self):
        import sys
        # keeper_redact_test imports the callback. Then KeeperAnsible adds the _secrets key for it, but these runs
        # use the default callback, which prints the key.
        redact_modules = {name: module for name, module in sys.modules.items() if name.endswith(".keeper_redact")}
        for name in redact_modules:
            sys.modules.pop(name)
        self.addCleanup(sys.modules.update, redact_modules)
        for check_mode in (True, False):
            with self.subTest(check_mode=check_mode), tempfile.TemporaryDirectory() as temp_dir, \
                    patch('requests.get', side_effect=mock_download_get):
                result, out, err = AnsibleTestFramework(
                    playbook="keeper_copy.yml",
                    check_mode=check_mode,
                    diff=True,
                    vars={
                        "tmp_dir": temp_dir,
                        "password_uid": mock_record_1.uid,
                        "password_title": mock_record_1.title,
                        "file_uid": mock_record_1.uid,
                        "file_name": "Nailing It"
                    },
                    mock_responses=[all_respones]
                ).run()
                self.assertEqual(result["failed"], 0, out + err)
                self.assertEqual(result["ok"], 4, out + err)
                for secret in ("MYPASSWORD_2", "MYLOGIN_1"):
                    self.assertNotIn(secret, out + err)
                self.assertIn("the Keeper secret after the change is not shown", out + err)

    def test_hide_diff_content_keeps_the_headers_and_an_empty_side(self):
        import sys
        from keeper_secrets_manager_ansible.plugins.action.keeper_copy import ActionModule
        self.addCleanup(lambda: [sys.modules.pop(m, None) for m in list(sys.modules) if m.startswith("ansible")])
        result = {"diff": [
            {"before": "", "after": "SECRET", "before_header": "/tmp/a", "after_header": "dynamically generated"},
            {"before": "OLD SECRET", "after": "NEW SECRET"},
            {"dst_binary": 1, "after": "SECRET"},
            "not a dictionary",
        ]}
        ActionModule._hide_diff_content(result)
        hidden_after = "<the Keeper secret after the change is not shown>\n"
        self.assertEqual(result["diff"][0], {"before": "", "after": hidden_after,
                                             "before_header": "/tmp/a", "after_header": "dynamically generated"})
        self.assertEqual(result["diff"][1], {"before": "<the Keeper secret before the change is not shown>\n",
                                             "after": "<the Keeper secret after the change is not shown>\n"})
        self.assertEqual(result["diff"][2]["after"], "<the Keeper secret after the change is not shown>\n")
        single = {"diff": {"before": "OLD", "after": "NEW"}}
        ActionModule._hide_diff_content(single)
        self.assertNotIn("NEW", json_text(single))
        ActionModule._hide_diff_content({"msg": "no diff"})
        ActionModule._hide_diff_content("not a dictionary")


def json_text(value):
    import json
    return json.dumps(value)


class KeeperCopyNoLogTest(unittest.TestCase):

    def test_keeper_copy_with_no_log_runs_in_check_mode(self):
        import yaml
        playbook = os.path.join(os.path.dirname(__file__), "ansible_example", "playbooks", "keeper_copy.yml")
        with open(playbook) as fh:
            plays = yaml.safe_load(fh)
        for task in plays[0]["tasks"]:
            task["no_log"] = True
        for check_mode in (True, False):
            with self.subTest(check_mode=check_mode), tempfile.TemporaryDirectory() as temp_dir, \
                    patch('requests.get', side_effect=mock_download_get):
                destination = os.path.join(temp_dir, "no-log.yml")
                with open(destination, "w") as fh:
                    yaml.safe_dump(plays, fh)
                result, out, err = AnsibleTestFramework(
                    playbook=destination,
                    check_mode=check_mode,
                    vars={
                        "tmp_dir": temp_dir,
                        "password_uid": mock_record_1.uid,
                        "password_title": mock_record_1.title,
                        "file_uid": mock_record_1.uid,
                        "file_name": "Nailing It"
                    },
                    mock_responses=[all_respones]
                ).run()
                self.assertEqual(result["failed"], 0, out + err)
                self.assertEqual(result["ok"], 4, out + err)

    def test_remove_content_from_invocation_accepts_a_censored_invocation(self):
        import sys
        from keeper_secrets_manager_ansible.plugins.action.keeper_copy import ActionModule
        self.addCleanup(lambda: [sys.modules.pop(m, None) for m in list(sys.modules) if m.startswith("ansible")])
        for invocation in ("CENSORED: no_log is set", None, {"module_args": None}, {"module_args": "text"}):
            with self.subTest(invocation=invocation):
                result = {"invocation": invocation}
                ActionModule._remove_content_from_invocation(result)
                self.assertEqual(result, {"invocation": invocation})
        result = {"invocation": {"module_args": {"content": "SECRET", "src": "/tmp/x", "dest": "/tmp/y"}}}
        ActionModule._remove_content_from_invocation(result)
        self.assertEqual(result, {"invocation": {"module_args": {"dest": "/tmp/y"}}})
