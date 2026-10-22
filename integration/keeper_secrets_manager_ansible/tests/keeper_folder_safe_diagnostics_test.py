import importlib
import logging
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.keeper_globals import logger_name

from .ansible_test_framework import AnsibleTestFramework
from .folder_fake_server import FakeKeeperServer
from .integration._helpers import run_target


SHARED_UID = "PRIVATE_SHARED_UID_7163"
FOLDER_UID = "PRIVATE_FOLDER_UID_7163"
SHARED_NAME = "PRIVATE_SHARED_NAME_7163"
FOLDER_NAME = "PRIVATE_FOLDER_NAME_7163"
RUNTIME_DETAIL = "PRIVATE_RUNTIME_DETAIL_7163"
PRIVATE_MESSAGE = (
    "The folder operation failed. Diagnostic details are hidden because no_log is enabled.")
FOLDERS = [
    {"uid": SHARED_UID, "name": SHARED_NAME, "parent": None},
    {"uid": FOLDER_UID, "name": FOLDER_NAME, "parent": SHARED_UID},
]
RECORD_ARGS = {"shared_folder_uid": "{{ shared_uid }}", "record_type": "login", "title": "Synthetic record"}

SAFE_CASES = [
    ("renamed_create_option", "keeper_create", dict(RECORD_ARGS, folder_uid="{{ folder_uid }}"),
     "The folder_uid parameter for keeper_create has been renamed to subfolder_uid. "
     "Please update your playbook."),
    ("blank_renamed_create_option", "keeper_create", dict(RECORD_ARGS, folder_uid=""),
     "The folder_uid parameter for keeper_create has been renamed to subfolder_uid. "
     "Please update your playbook."),
    ("missing_create_root", "keeper_create", {"record_type": "login", "title": "Synthetic record"},
     "The shared_folder_uid is blank. keeper_create requires this value to be set."),
    ("missing_folder_name", "keeper_create_folder", {"shared_folder_uid": "{{ shared_uid }}"},
     "missing required arguments: folder_name"),
    ("blank_creation_name", "keeper_create_folder", {"shared_folder_uid": "{{ shared_uid }}", "folder_name": ""},
     "The folder_name is blank. keeper_create_folder requires this value to be set."),
    ("missing_lookup_selector", "keeper_get_folder", {},
     "Could not look up folder: There is nothing to look up. "
     "Set shared_folder_uid, subfolder_uid, folder_name, or folder_path."),
    ("exclusive_lookup_selectors", "keeper_get_folder",
     {"shared_folder_uid": "{{ shared_uid }}", "folder_name": "{{ folder_name }}",
      "folder_path": ["{{ folder_name }}"]},
     "parameters are mutually exclusive: folder_name|folder_path"),
    ("invalid_path_container", "keeper_get_folder",
     {"shared_folder_uid": "{{ shared_uid }}", "folder_path": {"name": "{{ folder_name }}"}},
     "Could not look up folder: The folder_path must be a string or a list of folder names."),
    ("missing_rename_name", "keeper_update_folder", {"folder_uid": "{{ folder_uid }}"},
     "missing required arguments: new_folder_name"),
    ("blank_rename_name", "keeper_update_folder", {"folder_uid": "{{ folder_uid }}", "new_folder_name": ""},
     "Could not update folder: The new_folder_name is blank."),
    ("missing_delete_uid", "keeper_delete_folder", {},
     "missing required arguments: folder_uid"),
    ("blank_delete_uid", "keeper_delete_folder", {"folder_uid": ""},
     "Could not delete folder: The folder_uid is blank."),
]
RUNTIME_CASES = [
    ("failed_record_read", "keeper_create", RECORD_ARGS),
    ("failed_creation_read", "keeper_create_folder",
     {"shared_folder_uid": "{{ shared_uid }}", "folder_name": "Synthetic folder"}),
    ("failed_lookup_read", "keeper_get_folder", {"shared_folder_uid": "{{ shared_uid }}"}),
    ("failed_rename_read", "keeper_update_folder",
     {"folder_uid": "{{ folder_uid }}", "new_folder_name": "Synthetic rename"}),
    ("failed_delete_read", "keeper_delete_folder", {"folder_uid": "{{ folder_uid }}"}),
]


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("ANSIBLE_LOCAL_TEMP", str(tmp_path / "ansible-tmp"))
    for name in ("KSM_TOKEN", "KSM_CONFIG", "KSM_CONFIG_FILE", "ANSIBLE_VAULT_PASSWORD_FILE",
                 "ANSIBLE_VAULT_IDENTITY_LIST", "ANSIBLE_ASK_VAULT_PASS"):
        monkeypatch.delenv(name, raising=False)


def write_playbook(tmp_path, tasks):
    # Keep synthetic private values out of Ansible's task-source snippets.
    variables = tmp_path / "folder_diagnostics_vars.yml"
    variables.write_text(yaml.safe_dump({
        "keeper_config": mock.MockConfig.make_base64(),
        "keeper_config_file": str(tmp_path / "unused-config.json"),
        "shared_uid": SHARED_UID,
        "folder_uid": FOLDER_UID,
        "folder_name": FOLDER_NAME,
    }, sort_keys=False), encoding="utf-8")
    path = tmp_path / "folder_diagnostics.yml"
    path.write_text(yaml.safe_dump([{
        "hosts": "my_systems",
        "gather_facts": False,
        "vars_files": [str(variables)],
        "tasks": tasks,
    }], sort_keys=False), encoding="utf-8")
    return path


def failure_task(name, module, args, no_log, check_mode):
    return {
        "name": name.replace("_", " "),
        module: dict(args),
        "register": name,
        "ignore_errors": True,
        "no_log": no_log,
        "check_mode": check_mode,
    }


def result_checks(name, expected):
    # Registered messages remain testable even when an engine censors all task output.
    return [
        "{} is failed".format(name),
        "{} is not changed".format(name),
        "{} in {}.msg".format(repr(expected), name),
    ]


@contextmanager
def playbook_output(server, playbook, callback, verbosity, sdk_output):
    logger = logging.getLogger(logger_name)
    saved = (logger.level, logger.disabled, logger.propagate, logger.handlers, logger.filters)
    handler = logging.FileHandler(sdk_output, encoding="utf-8")
    logger.handlers = [handler]
    logger.filters = []
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    logger.disabled = False
    original_init = SecretsManager.__init__
    observed_callbacks = []

    def logged_init(client, *args, **kwargs):
        kwargs["log_level"] = "DEBUG"
        original_init(client, *args, **kwargs)

    def load_cli(name):
        module = importlib.import_module(name)
        if name != "ansible.cli.playbook":
            return module

        def main():
            from ansible import constants
            observed_callbacks.append(constants.DEFAULT_STDOUT_CALLBACK)
            args = [arg for arg in sys.argv if arg != "-vvvvvv"]
            if verbosity:
                args.insert(1, "-" + "v" * verbosity)
            with patch.object(sys, "argv", args):
                module.main()

        return SimpleNamespace(main=main)

    callback_dir = Path(__file__).resolve().parents[1] / "keeper_secrets_manager_ansible/plugins/callback"
    environment = {
        "ANSIBLE_STDOUT_CALLBACK": callback,
        "ANSIBLE_CALLBACK_PLUGINS": str(callback_dir),
        "ANSIBLE_DISPLAY_TRACEBACK": "always",
    }
    framework_module = sys.modules[AnsibleTestFramework.__module__]
    try:
        with patch.dict(os.environ, environment), patch.object(SecretsManager, "__init__", logged_init), \
                patch.object(framework_module, "import_module", side_effect=load_cli):
            with run_target(server, str(playbook), {}) as result:
                assert observed_callbacks == [callback]
                yield result
    finally:
        handler.close()
        logger.setLevel(saved[0])
        logger.disabled, logger.propagate, logger.handlers, logger.filters = saved[1:]


def assert_private_output(output):
    for marker in (SHARED_UID, FOLDER_UID, SHARED_NAME, FOLDER_NAME, RUNTIME_DETAIL):
        assert marker not in output, output


@pytest.mark.parametrize("callback", ["default", "keeper_redact"])
@pytest.mark.parametrize("no_log", [False, True], ids=["public", "private"])
@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("verbosity", [0, 3], ids=["ordinary", "verbose"])
def test_safe_folder_guidance_survives_in_registered_failures(callback, no_log, check_mode, verbosity, tmp_path):
    server = FakeKeeperServer(folders=FOLDERS)
    tasks = []
    checks = []
    for name, module, args, expected in SAFE_CASES:
        tasks.append(failure_task(name, module, args, no_log, check_mode))
        checks.extend(result_checks(name, expected))
    tasks.append({"name": "Check safe failure guidance", "assert": {"that": checks}, "no_log": True})
    playbook = write_playbook(tmp_path, tasks)
    sdk_output = tmp_path / "sdk.log"

    with playbook_output(server, playbook, callback, verbosity, sdk_output) as (recap, out, err):
        output = out + err
        assert {key: recap.get(key) for key in ("ok", "changed", "failed", "ignored")} == {
            "ok": len(tasks), "changed": 0, "failed": 0, "ignored": len(SAFE_CASES),
        }, output
        assert server.calls() == []
        assert server.folders() == FOLDERS
        if no_log:
            assert_private_output(output)
            assert_private_output(sdk_output.read_text(encoding="utf-8"))
        else:
            visible = " ".join(output.split())
            for _, _, _, expected in SAFE_CASES:
                assert expected in visible, output


class _LoggedReadFailureServer(FakeKeeperServer):
    def handle(self, client, path, payload):
        logging.getLogger(logger_name).error("Folder request failed: %s", RUNTIME_DETAIL)
        return super().handle(client, path, payload)


@pytest.mark.parametrize("callback", ["default", "keeper_redact"])
@pytest.mark.parametrize("no_log", [False, True], ids=["public", "private"])
@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("verbosity", [0, 3], ids=["ordinary", "verbose"])
def test_runtime_folder_failures_keep_private_diagnostics_hidden(callback, no_log, check_mode, verbosity, tmp_path):
    server = _LoggedReadFailureServer(folders=FOLDERS, fail={"get_folders": RUNTIME_DETAIL})
    tasks = []
    checks = []
    for name, module, args in RUNTIME_CASES:
        tasks.append(failure_task(name, module, args, no_log, check_mode))
        checks.extend(result_checks(name, PRIVATE_MESSAGE if no_log else RUNTIME_DETAIL))
        if no_log:
            checks.append("{} not in {}.msg".format(repr(RUNTIME_DETAIL), name))
    tasks.append({"name": "Check runtime failure status", "assert": {"that": checks}, "no_log": True})
    playbook = write_playbook(tmp_path, tasks)
    sdk_output = tmp_path / "sdk.log"

    with playbook_output(server, playbook, callback, verbosity, sdk_output) as (recap, out, err):
        output = out + err
        assert {key: recap.get(key) for key in ("ok", "changed", "failed", "ignored")} == {
            "ok": len(tasks), "changed": 0, "failed": 0, "ignored": len(RUNTIME_CASES),
        }, output
        assert [call["path"] for call in server.calls()] == ["get_folders"] * len(RUNTIME_CASES)
        assert server.folders() == FOLDERS
        logged = sdk_output.read_text(encoding="utf-8")
        if no_log:
            assert_private_output(output)
            assert_private_output(logged)
        else:
            assert RUNTIME_DETAIL in output
            assert RUNTIME_DETAIL in logged
