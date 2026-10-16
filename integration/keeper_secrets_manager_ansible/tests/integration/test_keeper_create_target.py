import importlib
import json
import os
import sys
import tempfile
from unittest.mock import patch

import pytest

from keeper_secrets_manager_core.core import SecretsManager
from ..ansible_test_framework import AnsibleTestFramework
from ..folder_fake_server import FakeKeeperServer

TARGET = os.path.join(os.path.dirname(os.path.realpath(__file__)), "targets", "keeper_create", "playbook.yml")
FOLDERS = [
    {"uid": "SHARED_UID", "name": "Infrastructure", "parent": None},
    {"uid": "SUBFOLDER_UID", "name": "Databases", "parent": "SHARED_UID"},
]
EXPECTED = {"stale_key": "The folder_uid parameter for keeper_create has been renamed to subfolder_uid."}


def _unload_ansible():
    # A loaded ansible plugin loader has the default plugin path, and then the run fails with "couldn't resolve
    # module/action". AnsibleTestFramework unloads ansible after each run for the same reason.
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)


@pytest.fixture(scope="module")
def run():
    # Ansible runs each task in a forked worker, so the replacement of the SDK call writes what it received to a
    # file, which the test reads after the run.
    _unload_ansible()
    server = FakeKeeperServer(folders=FOLDERS)
    fd, capture = tempfile.mkstemp(prefix="ksm_create_capture_", suffix=".jsonl")
    os.close(fd)

    def create_secret_with_options(sm, options, record_create, *args, **kwargs):
        with open(capture, "a") as fh:
            fh.write(json.dumps([options.folder_uid, options.subfolder_uid]) + "\n")
        return "NEW_UID"

    try:
        with server.patch(), patch.object(SecretsManager, "create_secret_with_options", autospec=True,
                                          side_effect=create_secret_with_options):
            errors = importlib.import_module("ansible.errors")
            with patch("keeper_secrets_manager_ansible.AnsibleError", errors.AnsibleError):
                recap, out, err = AnsibleTestFramework(
                    playbook=TARGET, vars={"shared_uid": "SHARED_UID", "subfolder_uid": "SUBFOLDER_UID",
                                           "expected": EXPECTED}).run()
        with open(capture) as fh:
            received = [json.loads(line) for line in fh]
        yield server, recap, out + err, received
    finally:
        os.remove(capture)
        server.cleanup()
        _unload_ansible()


def test_playbook_passes(run):
    _, recap, output, _ = run
    expected = {"ok": 6, "changed": 4, "failed": 0, "unreachable": 0, "skipped": 0, "ignored": 1}
    assert {k: recap.get(k) for k in expected} == expected, output


def test_the_sdk_got_the_folder_options_of_the_real_creates_only(run):
    _, _, _, received = run
    # Check mode and the old folder_uid key sent nothing. An empty or omitted subfolder_uid is none.
    assert received == [["SHARED_UID", "SUBFOLDER_UID"], ["SHARED_UID", None], ["SHARED_UID", None]]


def test_check_mode_only_read_the_folders(run):
    server, _, _, _ = run
    assert {c["path"] for c in server.calls()} == {"get_folders"}
