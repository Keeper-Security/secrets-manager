import json
import os
import tempfile
from unittest.mock import patch

import pytest

from keeper_secrets_manager_core.core import SecretsManager
from ._helpers import run_target
from ..folder_fake_server import FakeKeeperServer

TARGET = os.path.join(os.path.dirname(os.path.realpath(__file__)), "targets", "keeper_create", "playbook.yml")
FOLDERS = [
    {"uid": "SHARED_UID", "name": "Infrastructure", "parent": None},
    {"uid": "SUBFOLDER_UID", "name": "Databases", "parent": "SHARED_UID"},
]
EXPECTED = {"stale_key": "The folder_uid parameter for keeper_create has been renamed to subfolder_uid."}


@pytest.fixture(scope="module")
def run():
    # Workers write the received SDK options to a file, since each task runs in a forked process.
    server = FakeKeeperServer(folders=FOLDERS)
    fd, capture = tempfile.mkstemp(prefix="ksm_create_capture_", suffix=".jsonl")
    os.close(fd)

    def create_secret_with_options(sm, options, record_create, *args, **kwargs):
        with open(capture, "a") as fh:
            fh.write(json.dumps([options.folder_uid, options.subfolder_uid]) + "\n")
        return "NEW_UID"

    variables = {"shared_uid": "SHARED_UID", "subfolder_uid": "SUBFOLDER_UID", "expected": EXPECTED}
    sdk_patch = patch.object(SecretsManager, "create_secret_with_options", autospec=True,
                             side_effect=create_secret_with_options)
    try:
        with run_target(server, TARGET, variables, sdk_patch=sdk_patch) as (recap, out, err):
            with open(capture) as fh:
                received = [json.loads(line) for line in fh]
            yield server, recap, out + err, received
    finally:
        os.remove(capture)


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
