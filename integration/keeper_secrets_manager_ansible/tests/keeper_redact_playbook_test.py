import copy
import hashlib
import json
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

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


@pytest.mark.parametrize("secret", [
    "-----BEGIN PRIVATE KEY-----\nFAKE_PRIVATE_KEY_MATERIAL_8092\nkey\n-----END PRIVATE KEY-----\n",
    "long-private-line\r\nx\r\n42\r\n",
    "ab\r\ncd\r\n",
    "ab\rcd\r",
    "ab\u2028x\r\ncd\r\n",
    "private-material-with-a-short-tail\nx\n\n",
    "x\ny\n",
    'escaped"line\\8092\n\nshort\nx',
    "private-\u20ac-line\u2028x\u2028private-last-line",
    "first-private-line\nlast-private-line",
    "user: bob\n    \npass: synthetic-8092!\n",
])
@pytest.mark.parametrize("action,key", [
    ("keeper_get", "value"), ("keeper_get_record", "record"), ("keeper_password", "password"),
])
def test_multiline_representations_hide_short_fragments_only_with_the_complete_sequence(secret, action, key):
    from keeper_secrets_manager_ansible.plugins.callback.keeper_redact import CallbackModule, REDACTED

    callback = CallbackModule()
    payload = {"password": secret} if action == "keeper_get_record" else secret
    callback._learn(action, {key: payload})
    lines = secret.splitlines()
    normalized = secret.rstrip("\r\n").splitlines()
    explicit = secret.split("\n")
    retained = secret.replace("\r\n", "\n").replace("\r", "\n")
    retained = list(dict.fromkeys((retained, retained.rstrip("\r\n"))))
    body = {
        "stdout": secret, "stdout_lines": lines, "stderr": secret, "stderr_lines": tuple(lines),
        "trimmed": secret.rstrip("\r\n"),
        "lf_text": "\n".join(lines),
        "retained_lf_forms": [form for value in retained for form in (
            value, json.dumps(value)[1:-1], repr(value)[1:-1], repr(value.encode())[2:-1])],
        "digests": [hashlib.new(name, value.encode(), usedforsecurity=False).hexdigest()
                    for value in retained for name in ("md5", "sha1", "sha256")],
        "normalized": normalized, "explicit": explicit,
        "binary": [line.encode("utf-8") for line in lines],
        "msg": ["public-before"] + lines + ["public-after"],
        "fragments": [{"isolated": line} for line in lines if len(line) >= callback.MIN_MATCH_LENGTH],
        "serialized": [repr(lines), json.dumps(lines), json.dumps(lines, ensure_ascii=False)],
        "normalized_serialized": [form for value in retained for form in (
            repr(value.split("\n")), json.dumps(value.split("\n")), json.dumps(value.split("\n"), ensure_ascii=False))
            if len(value.split("\n")) > 1],
        "public": ["key", "x", "42", "y"],
        "public_singletons": {"first": "ab", "second": "cd"},
    }
    original = copy.deepcopy(body)
    result = SimpleNamespace(result=dict(body), task=SimpleNamespace(action="command"))
    callback._scrub(result)
    assert result.result == {
        "stdout": REDACTED, "stdout_lines": [REDACTED] * len(lines),
        "trimmed": REDACTED,
        "lf_text": REDACTED,
        "retained_lf_forms": [REDACTED] * len(body["retained_lf_forms"]),
        "digests": [REDACTED] * len(body["digests"]),
        "stderr": REDACTED, "stderr_lines": [REDACTED] * len(lines),
        "normalized": [REDACTED] * len(normalized), "explicit": [REDACTED] * len(explicit),
        "binary": [REDACTED] * len(lines),
        "msg": ["public-before"] + [REDACTED] * len(lines) + ["public-after"],
        "fragments": body["fragments"], "serialized": [REDACTED] * 3, "public": body["public"],
        "normalized_serialized": [REDACTED] * len(body["normalized_serialized"]),
        "public_singletons": body["public_singletons"],
    }
    assert body == original
    assert CallbackModule()._redact(body) == dict(body, stderr_lines=list(lines), binary=list(lines))


def test_multiline_matching_and_learning_have_bounded_work():
    from keeper_secrets_manager_ansible.plugins.callback import keeper_redact

    class IncrementalForms:
        def __init__(self):
            self.values = set()

        def add(self, value):
            self.values.add(value)

        def update(self, values):
            self.values.update(values)

        def __iter__(self):
            raise AssertionError("Learning must update forms incrementally.")

    learning = keeper_redact.CallbackModule()
    assert isinstance(learning._forms, set)
    learning._forms = IncrementalForms()
    learning._learn("keeper_get", {"value": "\n".join("line-{}".format(index) for index in range(512))})

    comparisons = covered = 0
    count = 1024

    class Line(str):
        def __eq__(self, other):
            nonlocal comparisons
            comparisons += 1
            assert comparisons <= 12 * count
            return super().__eq__(other)

    class Protected(set):
        def update(self, indices):
            nonlocal covered
            covered += len(indices)
            assert covered <= 4 * count
            super().update(indices)

    callback = keeper_redact.CallbackModule()
    callback._learn("keeper_get", {"value": "x\n" * (count // 2)})
    body = ["public-before"] + [Line("x") for _ in range(count)] + ["public-after", "x"]
    original = [str(value) for value in body]
    with patch.object(keeper_redact, "set", Protected, create=True):
        assert callback._redact_lines(body) == (
            ["public-before"] + [keeper_redact.REDACTED] * count + ["public-after", "x"])
    assert [str(value) for value in body] == original


@pytest.mark.parametrize("secret,lines,protected", [
    ("x\ny\nx", ["x", "y", "x", "y", "x"], [True] * 5),
    ("x\nx\ny", ["x", "x", "x", "y"], [False, True, True, True]),
    ("x\ny\nx", ["x", "y", "z", "x", "y", "x"], [False] * 3 + [True] * 3),
])
def test_multiline_overlap_and_prefix_fallback_preserve_public_near_misses(secret, lines, protected):
    from keeper_secrets_manager_ansible.plugins.callback.keeper_redact import CallbackModule, REDACTED

    callback = CallbackModule()
    callback._learn("keeper_get", {"value": secret})
    body = ["public-before"] + lines + ["public-after", "x"]
    original = list(body)
    assert callback._redact_lines(body) == (
        ["public-before"] + [REDACTED if mask else value for value, mask in zip(lines, protected)] +
        ["public-after", "x"])
    assert body == original


MULTILINE_KEY = "-----BEGIN PRIVATE KEY-----\nFAKE_PRIVATE_KEY_MATERIAL_8092\nkey\n-----END PRIVATE KEY-----"


@pytest.mark.parametrize("secret,emitted,strip_empty_ends", [
    (MULTILINE_KEY, None, True),
    ("x\ny\n", None, True),
    ("ab\r\ncd\r\n", None, True),
    ("x\r\ny\r\n", None, True),
    ("ab\rcd\r", None, True),
    ("ab\u2028x\r\ncd\r\n", None, True),
    (MULTILINE_KEY + "\n", MULTILINE_KEY.replace("\n", "\r\n"), True),
    (MULTILINE_KEY + "\n", MULTILINE_KEY.replace("\n", "\r\n") + "\r\n", True),
    (MULTILINE_KEY + "\n", MULTILINE_KEY.replace("\n", "\r\n") + "\r\n", False),
], ids=[
    "key", "at-match-floor", "crlf", "crlf-below-normalized-floor", "bare-cr", "mixed-separators",
    "lf-key-to-crlf-without-ending", "lf-key-to-crlf-with-ending", "lf-key-to-crlf-retained-ending",
])
def test_native_multiline_command_results_and_registered_lines_are_redacted(
        tmp_path, secret, emitted, strip_empty_ends):
    record = Record(title="Multiline record", record_type="login")
    record.field("password", secret)
    response = MockResponse()
    response.add_record(record=record)
    attachment = tmp_path / "synthetic-key.txt"
    attachment.write_text(secret, encoding="utf-8")
    retained = secret.replace("\r\n", "\n").replace("\r", "\n")
    if emitted is None:
        emitted = retained + "\n"
    command_attachment = tmp_path / "synthetic-command-output.txt"
    command_attachment.write_bytes(emitted.encode("utf-8"))
    command_text = emitted.rstrip("\r\n") if strip_empty_ends else emitted
    expected_lines = command_text.splitlines()
    expected_digests = [hashlib.new(name, value.encode(), usedforsecurity=False).hexdigest()
                        for value in dict.fromkeys((retained, retained.rstrip("\r\n")))
                        for name in ("md5", "sha1", "sha256")]
    tasks = [
        {"name": "Read multiline secret", "keeper_get": {
            "uid": "{{ record_uid }}", "field": "password"}, "register": "fetched"},
        {"name": "Display complete secret", "debug": {"var": "fetched.value"}},
        {"name": "Display split secret", "debug": {"msg": "{{ fetched.value.splitlines() }}"}},
        {"name": "Return multiline output", "command": {"argv": [
            sys.executable, "-c",
            "import pathlib,sys; value=pathlib.Path(sys.argv[1]).read_bytes(); "
            "sys.stdout.buffer.write(value); sys.stderr.buffer.write(value)", str(command_attachment)],
            "strip_empty_ends": strip_empty_ends}, "register": "execution"},
        {"name": "Display registered lines", "debug": {"msg": {
            "out": "{{ execution.stdout_lines }}", "err": "{{ execution.stderr_lines }}",
            "text": "{{ execution.stdout }}", "error_text": "{{ execution.stderr }}",
            "as_array": "{{ execution.stdout.split(line_feed) }}",
            "as_json": "{{ execution.stdout.split(line_feed) | to_json }}", "public": "native-public-output"}}},
        {"name": "Return normalized text digests", "command": {"argv": [
            sys.executable, "-c",
            "import hashlib,json,pathlib,sys; value=pathlib.Path(sys.argv[1]).read_text().encode(); "
            "values=dict.fromkeys((value,value.rstrip(b'\\r\\n'))); "
            "print(json.dumps([hashlib.new(name,text,usedforsecurity=False).hexdigest() "
            "for text in values for name in ('md5','sha1','sha256')]))", str(attachment)]}, "register": "digests"},
        {"name": "Display normalized text digests", "debug": {"msg": "{{ digests.stdout | from_json }}"}},
        {"name": "Verify unchanged results", "assert": {"that": [
            "fetched.value == expected_key", "execution.stdout == command_text",
            "execution.stderr == command_text", "execution.stdout_lines == expected_lines",
            "execution.stderr_lines == expected_lines",
            "digests.stdout | from_json == expected_digests",
            "execution.stdout.split(line_feed) | to_json == expected_line_json",
        ]}, "no_log": True},
        {"name": "Display unrelated short word", "debug": {"msg": "key"}},
    ]
    playbook = tmp_path / "multiline.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "my_systems", "gather_facts": False,
        "vars": {"expected_key": secret, "command_text": command_text, "expected_digests": expected_digests,
                 "expected_lines": expected_lines, "line_feed": "\n",
                 "expected_line_json": json.dumps(command_text.split("\n"))},
        "tasks": tasks,
    }]), encoding="utf-8")
    # Direct callback probes can initialize the loader before the framework configures the Keeper plugin paths.
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)
    status, out, err = AnsibleTestFramework(
        playbook=str(playbook), stdout_callback="keeper_redact", mock_responses=[response],
        vars={"record_uid": record.uid, "ansible_python_interpreter": sys.executable},
    ).run()
    output = out + err
    assert status["ok"] == len(tasks) and status["failed"] == 0, output
    assert "Loading callback plugin keeper_redact" in output
    for line in secret.splitlines():
        if len(line) >= 4:
            assert line not in output
    for value in {secret, secret.rstrip("\r\n"), "\n".join(secret.splitlines()), retained, retained.rstrip("\r\n")}:
        for form in (value, json.dumps(value)[1:-1], repr(value)[1:-1]):
            assert form not in output
    for task in tasks[2:5]:
        shown = output.split("TASK [" + task["name"] + "]", 1)[1].split("TASK [", 1)[0]
        assert '"key"' not in shown and "****" in shown
        if task["name"] == "Return multiline output":
            assert '"stdout": "****"' in shown and '"stderr": "****"' in shown
        if task["name"] == "Display registered lines":
            assert '"as_json": "****"' in shown
            assert '"text": "****"' in shown and '"error_text": "****"' in shown
            assert '"public": "native-public-output"' in shown
    digest_panel = output.split("TASK [Display normalized text digests]", 1)[1].split("TASK [", 1)[0]
    assert "****" in digest_panel
    assert not any(value in digest_panel for value in expected_digests)
    assert '"key"' in output.split("TASK [Display unrelated short word]", 1)[1]
    assert "Callback dispatch" not in output and "Failure using" not in output
