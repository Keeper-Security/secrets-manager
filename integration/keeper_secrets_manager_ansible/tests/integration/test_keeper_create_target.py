import json
import os
import tempfile
from unittest.mock import patch

import pytest
import yaml

from keeper_secrets_manager_core.core import SecretsManager
from ._helpers import run_target
from ..folder_fake_server import FakeKeeperServer
from ..keeper_create_test import CREATE_FOLDERS, INVALID_CREATE_TARGETS, RecordCreateServer

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


def test_action_validates_record_hierarchy_in_normal_and_check_mode(tmp_path):
    invalid = [
        {"shared": shared, "subfolder": subfolder, "message": message, "check": check, "invalid": True}
        for shared, subfolder, message in (case.values for case in INVALID_CREATE_TARGETS)
        for check in (False, True)
    ]
    valid = [
        dict(options, shared="SHARED_A", check=check, invalid=False)
        for options in ({}, {"subfolder": None}, {"subfolder": ""}, {"subfolder": "PARENT_A"},
                        {"subfolder": "DEEP_A"})
        for check in (False, True)
    ]
    create = {
        "shared_folder_uid": "{{ item.shared }}", "subfolder_uid": "{{ item.subfolder | default(omit) }}",
        "record_type": "login", "title": "Synthetic action hierarchy record",
    }
    # Older engines abort a direct action loop on AnsibleError. Loop one reusable task pair instead.
    scenario = tmp_path / "record_hierarchy_scenario.yml"
    scenario.write_text(yaml.safe_dump([
        {"name": "Exercise selected target", "keeper_create": create, "check_mode": "{{ item.check }}",
         "register": "created", "ignore_errors": "{{ item.invalid }}"},
        {"name": "Check selected prediction", "assert": {"that": [
            "(created is failed) == item.invalid",
            "(item.invalid and item.message in created.msg) or (not item.invalid and created is changed)",
            "item.invalid or (item.check and created.record_uid is none) or "
            "(not item.check and created.record_uid is string)",
        ]}},
    ], sort_keys=False), encoding="utf-8")
    playbook = tmp_path / "record_hierarchy.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "my_systems", "gather_facts": False, "tasks": [
            {"name": "Validate every target", "include_tasks": str(scenario), "loop": "{{ create_targets }}"},
        ],
    }], sort_keys=False), encoding="utf-8")
    server = RecordCreateServer(folders=CREATE_FOLDERS)
    with run_target(server, str(playbook), {"create_targets": invalid + valid}) as (recap, out, err):
        assert recap.get("failed") == 0 and recap.get("unreachable") == 0, out + err
        assert recap.get("ignored") == len(invalid), out + err
        received = server.calls("create_secret")
        assert [(call["shared_folder_uid"], call["subfolder_uid"]) for call in received] == [
            ("SHARED_A", None), ("SHARED_A", None), ("SHARED_A", None), ("SHARED_A", "PARENT_A"),
            ("SHARED_A", "DEEP_A"),
        ]
        assert len(server.calls("get_folders")) == len(invalid) + len(valid)
        assert server.folders() == CREATE_FOLDERS
