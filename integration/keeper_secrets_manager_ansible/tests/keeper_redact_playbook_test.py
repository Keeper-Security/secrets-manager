import hashlib
import json
import unittest
from unittest.mock import patch
from keeper_secrets_manager_ansible import KeeperAnsible
from keeper_secrets_manager_core.mock import Record, Response as MockResponse
from .ansible_test_framework import AnsibleTestFramework

SPECIAL_PASSWORD = 'pa"ss\\word'
PEM_KEY = "-----BEGIN KEY-----\nMIIEvQIBADANBgkq\n-----END KEY-----"

special_record = Record(title="Special Record", record_type="login")
special_record.field("password", SPECIAL_PASSWORD)
key_record = Record(title="Key Record", record_type="login")
key_record.field("password", PEM_KEY)
responses = MockResponse()
responses.add_record(record=special_record)
responses.add_record(record=key_record)


def run_playbook(stdout_callback):
    result, out, err = AnsibleTestFramework(
        playbook="keeper_redact_secrets.yml",
        stdout_callback=stdout_callback,
        vars={"special_uid": special_record.uid, "key_uid": key_record.uid},
        mock_responses=[responses]
    ).run()
    return result, out + err


class KeeperRedactPlaybookTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.result, cls.output = run_playbook("keeper_redact")

    def test_the_run_used_keeper_redact(self):
        self.assertEqual(self.result["failed"], 0, self.output)
        self.assertEqual(self.result["ignored"], 2, self.output)
        self.assertIn("****", self.output)

    def assert_secrets_hidden(self, text):
        for secret in (SPECIAL_PASSWORD, PEM_KEY):
            for form in (secret, json.dumps(secret)[1:-1], repr(secret)[1:-1]):
                self.assertNotIn(form, text)
        self.assertNotIn("MIIEvQIBADANBgkq", text)

    def task_output(self, name, next_name=None):
        text = self.output.split("TASK [" + name + "]")[1]
        if next_name is not None:
            text = text.split("TASK [" + next_name + "]")[0]
        return text

    def test_secrets_with_special_characters_are_hidden(self):
        self.assert_secrets_hidden(self.output)

    def test_output_has_no_internal_redact_key(self):
        self.assertNotIn('"_secrets"', self.output)

    def test_a_later_task_that_prints_a_registered_result_is_hidden(self):
        text = self.task_output("Print the registered result of the first task",
                                "Fail with a message that holds a secret")
        self.assertIn("special", text)
        self.assert_secrets_hidden(text)

    def test_a_json_document_that_holds_the_secrets_is_hidden(self):
        text = self.task_output("Print a JSON document that holds the secrets")
        self.assertIn("ok: [localhost]", text)
        self.assert_secrets_hidden(text)

    def test_a_hash_of_a_secret_in_a_later_task_is_hidden(self):
        # A failed built-in copy prints the SHA-1 of its content. A hash of a short secret can be found by guessing.
        text = self.task_output("Copy a secret to a directory that does not exist")
        self.assertIn("FAILED", text)
        for algorithm in (hashlib.sha1, hashlib.md5, hashlib.sha256):
            self.assertNotIn(algorithm(SPECIAL_PASSWORD.encode(), usedforsecurity=False).hexdigest(), text)

    def test_a_failure_message_that_holds_a_secret_is_hidden(self):
        text = self.task_output("Fail with a message that holds a secret")
        self.assertIn("bad value", text)
        self.assert_secrets_hidden(text)


GENERATED_PASSWORD = 'Gen"Pass\\9z'
SHORT_SECRET = "~#q"
LONG_LOGIN = "Q7!zLoginValue"

actions_record = Record(title="Actions Record", record_type="login")
actions_record.field("login", LONG_LOGIN)
actions_record.field("password", SHORT_SECRET)
actions_responses = MockResponse()
actions_responses.add_record(record=actions_record)


class KeeperRedactActionsTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with patch.object(KeeperAnsible, "generate_password", return_value=GENERATED_PASSWORD):
            result, out, err = AnsibleTestFramework(
                playbook="keeper_redact_actions.yml",
                stdout_callback="keeper_redact",
                vars={"record_uid": actions_record.uid},
                mock_responses=[actions_responses]
            ).run()
        cls.result, cls.output = result, out + err

    def task_output(self, name, next_name=None):
        text = self.output.split("TASK [" + name + "]")[1]
        return text.split("TASK [" + next_name + "]")[0] if next_name is not None else text

    def test_a_generated_password_is_hidden_in_a_later_task(self):
        self.assertEqual(self.result["failed"], 0, self.output)
        text = self.task_output("Print the generated password", "Get the record")
        self.assertIn("generated", text)
        for form in (GENERATED_PASSWORD, json.dumps(GENERATED_PASSWORD)[1:-1]):
            self.assertNotIn(form, text)

    def test_a_record_is_hidden_and_a_short_value_is_hidden_in_its_own_task(self):
        # A value shorter than 4 characters is not searched for in other tasks, by design, so only the task that
        # returned it is checked for the short value.
        own = self.task_output("Get the record", "Print the record")
        self.assertNotIn(SHORT_SECRET, own)
        self.assertNotIn(LONG_LOGIN, self.output)


class KeeperDefaultCallbackTest(unittest.TestCase):

    def test_default_callback_output_has_no_internal_redact_key(self):
        # The module is loaded here, but the default callback is the one that prints.
        import importlib
        import sys
        importlib.import_module("keeper_secrets_manager_ansible.plugins.callback.keeper_redact")
        # The import starts ansible's plugin loader with the default paths. Unload it as conftest.py does.
        for name in list(sys.modules):
            if name.startswith("ansible"):
                sys.modules.pop(name)
        result, output = run_playbook(None)
        self.assertEqual(result["failed"], 0, output)
        self.assertNotIn('"_secrets"', output)
