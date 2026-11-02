import importlib
import io
import logging
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFolderError, _UnreadableFolderLog

from .ansible_test_framework import AnsibleTestFramework
from .folder_fake_server import FakeKeeperServer
from .integration._helpers import run_target, unload_ansible
from .keeper_folder_unreadable_test import keeper_with, readable_folders, skipping_get_folders


# A password for these tests only. The inline !vault values in keeper_folder_vault.yml are encrypted with it.
VAULT_PASSWORD = "keeper-folder-vault-test-only"

SHARED_FOLDER_UID = "SHARED_FOLDER_UID"
FOLDER_UID = "FOLDER_UID"
SIBLING_UID = "SIBLING_UID"


class _CreationRecordingServer(FakeKeeperServer):
    def handle(self, client, path, payload):
        if path != "create_secret":
            return super().handle(client, path, payload)
        state = self._load()
        state["calls"].append({"path": path, "record_uid": payload.recordUid})
        self._save(state)
        return self._json({})


class KeeperFolderVaultTest(unittest.TestCase):
    """
    Inline !vault values in the task args of keeper_get_folder, keeper_update_folder, and keeper_delete_folder.

    Before ansible-core 2.19, such a value reaches the action plugin as an AnsibleVaultEncryptedUnicode, which is not
    a str. The option check must accept it as a string, and the value must be used decrypted: the right folder must
    be found, renamed, and deleted.
    """

    @classmethod
    def setUpClass(cls):
        # A test module that imported a plugin class earlier left ansible's plugin loader with the default paths.
        for module in list(sys.modules):
            if module.startswith("ansible"):
                sys.modules.pop(module, None)

    def test_inline_vault_values_find_rename_and_delete_the_right_folder(self):
        server = FakeKeeperServer(folders=[
            {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
            {"uid": FOLDER_UID, "name": "Staging", "parent": SHARED_FOLDER_UID},
            {"uid": SIBLING_UID, "name": "Databases", "parent": SHARED_FOLDER_UID},
        ])
        # mkstemp makes the file with mode 0600. It must not be executable: Ansible runs an executable password file.
        fd, password_file = tempfile.mkstemp(prefix="ksm_vault_password_", suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write(VAULT_PASSWORD + "\n")
        saved = os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE")
        # The framework imports ansible again for each run, so the password file takes effect.
        os.environ["ANSIBLE_VAULT_PASSWORD_FILE"] = password_file
        try:
            framework = AnsibleTestFramework(playbook="keeper_folder_vault.yml", vars={
                "shared_folder_uid": SHARED_FOLDER_UID,
                "folder_uid": FOLDER_UID,
            })
            with server.patch():
                result, out, err = framework.run()

            # 2 lookups, a rename, a delete, and the assert.
            self.assertEqual({k: result.get(k) for k in ("ok", "changed", "failed", "skipped", "unreachable")},
                             {"ok": 5, "changed": 2, "failed": 0, "skipped": 0, "unreachable": 0}, out + err)
            self.assertEqual(server.calls("update_folder"),
                             [{"path": "update_folder", "folder_uid": FOLDER_UID, "folder_name": "Production"}],
                             "the rename must use the decrypted UID and the decrypted new name")
            self.assertEqual(server.calls("delete_folder"),
                             [{"path": "delete_folder", "folder_uids": [FOLDER_UID], "force": False}],
                             "the delete must use the decrypted UID")
            self.assertEqual(server.folders(), [
                {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
                {"uid": SIBLING_UID, "name": "Databases", "parent": SHARED_FOLDER_UID},
            ], "only the vaulted folder may be renamed and deleted")
        finally:
            if saved is None:
                os.environ.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
            else:
                os.environ["ANSIBLE_VAULT_PASSWORD_FILE"] = saved
            os.remove(password_file)
            server.cleanup()


@pytest.mark.parametrize("callback,verbosity,check_mode,private", [
    ("default", 0, False, True), ("keeper_redact", 0, False, True),
    ("default", 3, True, True), ("keeper_redact", 3, True, True),
    ("default", 0, False, False),
], ids=["default-normal", "redacted-normal", "default-check", "redacted-check", "public-diagnostics"])
def test_no_log_folder_diagnostics_do_not_disclose_vaulted_metadata(callback, verbosity, check_mode, private, tmp_path):
    """Real Vault decryption and SDK folder encryption, with a simulated partial-read diagnostic."""
    unload_ansible()
    from ansible.parsing.vault import VaultLib, VaultSecret

    private_name = "VAULTED_PRIVATE_NAME_4821"
    private_parent = "PRIVATE_PARENT_4821"
    private_old = "PRIVATE_OLD_NAME_4821"
    private_uids = ["PRIVATE_SHARED_UID_4821", "PRIVATE_FOLDER_UID_4821", "PRIVATE_SIBLING_UID_4821",
                    "PRIVATE_SKIPPED_UID_4821"]
    encrypted = VaultLib([("default", VaultSecret(VAULT_PASSWORD.encode()))]).encrypt(private_name.encode()).decode()
    shared, target, sibling, skipped = private_uids
    server = _CreationRecordingServer(folders=[
        {"uid": shared, "name": private_parent, "parent": None},
        {"uid": target, "name": private_old, "parent": shared},
        {"uid": sibling, "name": private_name, "parent": shared},
    ])
    tasks = [
        {"name": "Rename private folder", "keeper_update_folder": {
            "folder_uid": target, "new_folder_name": "{{ private_name }}"}, "register": "renamed"},
        {"name": "Keep private folder name", "keeper_update_folder": {
            "folder_uid": sibling if check_mode else target, "new_folder_name": "{{ private_name }}"},
         "register": "unchanged"},
        {"name": "List private folder", "keeper_get_folder": {
            "shared_folder_uid": shared, "include_subfolders": True}, "register": "listed"},
        {"name": "Delete private folder", "keeper_delete_folder": {"folder_uid": target}, "register": "deleted"},
        {"name": "Find the existing creation target", "keeper_create_folder": {
            "shared_folder_uid": shared, "folder_name": "{{ private_name }}"}, "register": "existing"},
        {"name": "Create a synthetic record", "keeper_create": {
            "shared_folder_uid": shared, "record_type": "login", "title": "Synthetic record",
            "fields": [{"type": "login", "value": "synthetic-user"}]}, "register": "created"},
        {"name": "Reject a child as creation root", "keeper_create_folder": {
            "shared_folder_uid": sibling, "folder_name": "{{ private_name }}"}, "register": "bad_root",
         "ignore_errors": True},
        {"name": "Reject padded creation name", "keeper_create_folder": {
            "shared_folder_uid": shared, "folder_name": " {{ private_name }}"}, "register": "bad_name",
         "ignore_errors": True},
        {"name": "Reject invalid lookup option", "keeper_get_folder": {
            "shared_folder_uid": shared, "include_subfolders": "{{ private_name }}"}, "register": "bad_lookup",
         "ignore_errors": True},
        {"name": "Reject invalid delete option", "keeper_delete_folder": {
            "folder_uid": sibling, "force_deletion": "{{ private_name }}"}, "register": "bad_delete",
         "ignore_errors": True},
        {"name": "Reject invalid record type", "keeper_create": {
            "shared_folder_uid": shared, "record_type": "{{ private_name }}", "title": "Synthetic record"},
         "register": "bad_record", "ignore_errors": True},
    ]
    for task in tasks:
        task.update(no_log=private, check_mode=check_mode)
    tasks.append({"name": "Check predictions and idempotence", "assert": {"that": [
        "renamed is changed", "unchanged is not changed", "listed is not changed", "deleted is changed",
        "existing is not changed", "created is changed",
        "bad_root is failed", "bad_root is not changed", "bad_name is failed", "bad_name is not changed",
        "bad_lookup is failed", "bad_lookup is not changed", "bad_delete is failed", "bad_delete is not changed",
        "bad_record is failed", "bad_record is not changed",
    ]}, "no_log": True})
    playbook = tmp_path / "private_folder.yml"
    text = yaml.safe_dump([{"hosts": "my_systems", "gather_facts": False,
                           "vars": {"private_name": "VAULT_PLACEHOLDER"}, "tasks": tasks}], sort_keys=False)
    text = text.replace("private_name: VAULT_PLACEHOLDER",
                        "private_name: !vault |\n" + "\n".join("      " + line for line in encrypted.splitlines()))
    playbook.write_text(text, encoding="utf-8")

    original_get, original_init = SecretsManager.get_folders, SecretsManager.__init__

    def partial_read(sm):
        folders = original_get(sm)
        logging.getLogger(logger_name).warning("Folder %s skipped due to error: %s", skipped,
                                               "PRIVATE_SDK_DETAIL_4821")
        return folders

    def logged_init(sm, *args, **kwargs):
        # Exercise actual SDK output instead of the framework's usual disabled SDK logger.
        kwargs["log_level"] = "DEBUG"
        original_init(sm, *args, **kwargs)

    # The framework normally fixes verbosity at six. Override only the CLI arguments, not Display or its renderer.
    observed_callbacks = []

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
    environment = {"ANSIBLE_STDOUT_CALLBACK": callback, "ANSIBLE_CALLBACK_PLUGINS": str(callback_dir)}
    framework_module = sys.modules[AnsibleTestFramework.__module__]
    with patch.dict(os.environ, environment), patch.object(framework_module, "import_module", side_effect=load_cli), \
            patch.object(SecretsManager, "__init__", logged_init), \
            patch.object(SecretsManager, "get_folders", autospec=True, side_effect=partial_read):
        with run_target(server, str(playbook), {}, vault_password=VAULT_PASSWORD) as (recap, out, err):
            output = out + err
            assert {k: recap.get(k) for k in ("ok", "changed", "failed", "ignored")} == {
                "ok": len(tasks), "changed": 3, "failed": 0, "ignored": 5,
            }, output
            assert observed_callbacks == [callback]
            if private and verbosity:
                assert "censored" in output or "no_log" in output, output
            elif private:
                # Ordinary callbacks print only task status for censored successes, not a result dictionary.
                assert '"folder_uid":' not in output and '"folder_name":' not in output, output
            if private:
                for value in [private_name, private_parent, private_old, "PRIVATE_SDK_DETAIL_4821"] + private_uids:
                    assert value not in output, output
            else:
                assert private_name in output, output
                assert "A sibling folder already has the requested name." in " ".join(output.split()), output
            assert len(server.calls("update_folder")) == (0 if check_mode else 1)
            assert len(server.calls("delete_folder")) == (0 if check_mode else 1)
            assert server.calls("create_folder") == []
            assert len(server.calls("create_secret")) == (0 if check_mode else 1)
            if check_mode:
                assert server.folder(target)["name"] == private_old
            else:
                assert server.folder(target) is None


@pytest.fixture
def sdk_output():
    """An active SDK sink, with all caller logging configuration restored after each test."""
    logger = logging.getLogger(logger_name)
    saved = (logger.level, logger.disabled, logger.propagate, logger.handlers, logger.filters)
    output = io.StringIO()
    logger.handlers = [logging.StreamHandler(output)]
    logger.filters = []
    logger.setLevel(logging.DEBUG)
    logger.disabled, logger.propagate = False, False
    try:
        yield logger, output
    finally:
        logger.setLevel(saved[0])
        logger.disabled, logger.propagate, logger.handlers, logger.filters = saved[1:]


def logger_state(logger):
    return logger.level, logger.disabled, logger.propagate, tuple(logger.handlers), tuple(logger.filters)


def folder_task(keeper, no_log):
    keeper.action_module = SimpleNamespace(_task=SimpleNamespace(no_log=no_log, check_mode=False, args={}))
    return keeper


@pytest.mark.parametrize("no_log", [False, True])
def test_private_folder_read_preserves_skips_before_suppressing_sdk_output(no_log, sdk_output):
    logger, output = sdk_output
    before = logger_state(logger)
    keeper = folder_task(keeper_with(skipping_get_folders), no_log)
    folders, unreadable = keeper._read_folders()
    assert [folder.folder_uid for folder in folders] == ["SF", "EMPTY"]
    assert unreadable == {"UNREADABLE_UID": "Invalid padding bytes."}
    assert ("UNREADABLE_UID" in output.getvalue()) is (not no_log)
    assert logger_state(logger) == before


@pytest.mark.parametrize("operation", ["read", "rename", "delete_force", "delete_nonforce",
                                       "create_folder", "create_record"])
@pytest.mark.parametrize("no_log", [False, True])
def test_private_folder_sdk_boundaries_hide_arbitrary_new_sdk_messages(operation, no_log, sdk_output):
    logger, output = sdk_output
    before = logger_state(logger)
    keeper = folder_task(keeper_with(lambda: readable_folders()), no_log)
    detail = "PRIVATE_FUTURE_SDK_DETAIL_5934"

    def log_result(result):
        def call(*args, **kwargs):
            logger.error("Future SDK diagnostic contains %s", detail)
            return result
        return call

    keeper.client.get_folders.side_effect = log_result(readable_folders())
    keeper.client.update_folder.side_effect = log_result(None)
    keeper.client.get_secrets.side_effect = log_result([])
    keeper.client.delete_folder.side_effect = log_result([{
        "folderUid": "EMPTY", "responseCode": "access_denied", "errorMessage": detail,
    }])
    keeper.client.create_folder.side_effect = log_result("CREATED_FOLDER")
    keeper.client.create_secret_with_options.side_effect = log_result("CREATED_RECORD")
    if operation == "read":
        assert keeper.get_folder(shared_folder_uid="SF")["folder_uid"] == "SF"
    elif operation == "rename":
        assert keeper.update_folder("EMPTY", "Renamed")["changed"] is True
    elif operation == "create_folder":
        assert keeper.create_folder("Synthetic folder", "SF") == ("CREATED_FOLDER", True)
    elif operation == "create_record":
        assert keeper.create_record(object(), "SF") == "CREATED_RECORD"
    else:
        with pytest.raises(KeeperFolderError, match="Diagnostic details are hidden" if no_log else detail):
            keeper.delete_folder("EMPTY", force=operation == "delete_force")
    assert (detail in output.getvalue()) is (not no_log)
    assert logger_state(logger) == before


@pytest.mark.parametrize("interruption", [ConnectionError("PRIVATE_FAILURE"), KeyboardInterrupt(), SystemExit(7)])
@pytest.mark.parametrize("disabled", [False, True])
def test_private_folder_logger_restores_state_after_errors_and_interrupts(interruption, disabled, sdk_output):
    logger, output = sdk_output
    logger.setLevel(logging.ERROR)
    logger.disabled = disabled
    before = logger_state(logger)

    def interrupted():
        skipping_get_folders()
        raise interruption

    keeper = folder_task(keeper_with(interrupted), True)
    expected = KeeperFolderError if isinstance(interruption, Exception) else type(interruption)
    with pytest.raises(expected):
        keeper._read_folders()
    assert output.getvalue() == ""
    assert logger_state(logger) == before


@pytest.mark.parametrize("operation", ["rename", "delete_force", "delete_nonforce"])
@pytest.mark.parametrize("interruption", [RuntimeError("PRIVATE_FAILURE"), KeyboardInterrupt()])
def test_private_mutation_sdk_boundaries_restore_filters_after_failure(operation, interruption, sdk_output):
    logger, output = sdk_output
    before = logger_state(logger)
    keeper = folder_task(keeper_with(lambda: readable_folders()), True)

    def interrupted(*args, **kwargs):
        logger.error("Future SDK private failure: %s", "PRIVATE_FAILURE")
        raise interruption

    if operation == "rename":
        keeper.client.update_folder.side_effect = interrupted
        call = lambda: keeper.update_folder("EMPTY", "Renamed")
    elif operation == "delete_force":
        keeper.client.delete_folder.side_effect = interrupted
        call = lambda: keeper.delete_folder("EMPTY", force=True)
    else:
        keeper.client.get_secrets.side_effect = interrupted
        call = lambda: keeper.delete_folder("EMPTY")
    expected = KeeperFolderError if isinstance(interruption, Exception) else type(interruption)
    with pytest.raises(expected):
        call()
    assert output.getvalue() == ""
    assert logger_state(logger) == before


@pytest.mark.parametrize("no_log", [False, True])
def test_skip_capture_precedes_existing_sdk_filters(no_log, sdk_output):
    logger, output = sdk_output
    inspected = []

    class Reject(logging.Filter):
        def filter(self, record):
            inspected.append(record)
            return False

    logger.addFilter(Reject())
    before = logger_state(logger)
    _, unreadable = folder_task(keeper_with(skipping_get_folders), no_log)._read_folders()
    assert unreadable == {"UNREADABLE_UID": "Invalid padding bytes."}
    assert bool(inspected) is (not no_log)
    assert output.getvalue() == ""
    assert logger_state(logger) == before


def test_private_sdk_filter_is_thread_scoped_and_preserves_nested_read_capture(sdk_output):
    logger, output = sdk_output
    before = logger_state(logger)
    keeper = folder_task(keeper_with(skipping_get_folders), True)
    outer, inner = _UnreadableFolderLog(), _UnreadableFolderLog()
    with keeper._folder_sdk_logging(outer):
        with keeper._folder_sdk_logging(inner):
            skipping_get_folders()
            worker = threading.Thread(target=lambda: logger.warning(
                "Folder %s skipped due to error: %s", "UNRELATED_THREAD_UID", "unrelated diagnostic"))
            worker.start()
            worker.join(timeout=5)
            assert not worker.is_alive()
        assert outer.folders == inner.folders == {"UNREADABLE_UID": "Invalid padding bytes."}
        assert "UNREADABLE_UID" not in output.getvalue()
        assert "UNRELATED_THREAD_UID" in output.getvalue()
    assert logger_state(logger) == before


@pytest.mark.parametrize("task_flag, ambient_flag, variable_flag, expected", [
    (True, False, False, True), (False, True, True, False),
    (None, True, False, True), (None, False, True, True), (None, False, False, False),
])
def test_folder_no_log_uses_resolved_task_or_lookup_context(task_flag, ambient_flag, variable_flag, expected):
    keeper = keeper_with(skipping_get_folders)
    if task_flag is not None:
        folder_task(keeper, task_flag)
    keeper.task_vars = {"ansible_no_log": variable_flag}
    context = SimpleNamespace(TaskContext=SimpleNamespace(current=lambda: SimpleNamespace(
        task=SimpleNamespace(no_log=ambient_flag))))
    with patch.dict(sys.modules, {"ansible._internal._task": context}):
        assert keeper._folder_no_log() is expected


class PrivateUnreadableServer(FakeKeeperServer):
    def _folder_list(self, state, app_key):
        folders = super()._folder_list(state, app_key)
        for folder in folders:
            if folder["folderUid"] == "PRIVATE_UNREADABLE_UID_5934":
                folder["data"] = "invalid-ciphertext"
        return folders


@pytest.mark.parametrize("no_log", [False, True])
@pytest.mark.parametrize("globally_disabled", [False, True], ids=["warnings-enabled", "warnings-disabled"])
def test_real_sdk_unreadable_diagnostics_preserve_evidence_without_private_output(
        no_log, globally_disabled, sdk_output):
    """Public SDK 17.3 fails decoding; skip behavior is exercised only by qualified local-source SDK runs."""
    logger, output = sdk_output
    server = PrivateUnreadableServer(folders=[
        {"uid": "SHARED", "name": "Synthetic shared", "parent": None},
        {"uid": "PRIVATE_UNREADABLE_UID_5934", "name": "Synthetic target", "parent": "SHARED"},
    ])
    keeper = folder_task(object.__new__(KeeperAnsible), no_log)
    keeper.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()), log_level="DEBUG")
    old_disable = logger.manager.disable
    logging.disable(logging.CRITICAL if globally_disabled else logging.NOTSET)
    before = logger_state(logger)
    try:
        with server.patch(), patch.object(keeper.client, "get_folders", wraps=keeper.client.get_folders) as read:
            try:
                folders, unreadable = keeper._read_folders()
            except KeeperFolderError:
                assert "PRIVATE_UNREADABLE_UID_5934" not in output.getvalue()
            else:
                assert [folder.folder_uid for folder in folders] == ["SHARED"]
                assert "PRIVATE_UNREADABLE_UID_5934" in unreadable
                assert ("PRIVATE_UNREADABLE_UID_5934" in output.getvalue()) is (not no_log)
            assert read.call_count == int(not globally_disabled)
        assert logger_state(logger) == before
        assert logger.manager.disable == (logging.CRITICAL if globally_disabled else logging.NOTSET)
    finally:
        logging.disable(old_disable)
        server.cleanup()


@pytest.mark.parametrize("no_log", [False, True])
def test_real_sdk_refusal_keeps_failure_without_private_sdk_logging(no_log, sdk_output):
    """Real SDK refusal logging is present in local-source SDK 17.4 and 18, not in the public 17.3 control."""
    logger, output = sdk_output
    uid, detail = "PRIVATE_REFUSED_UID_5934", "PRIVATE_REFUSAL_DETAIL_5934"
    server = FakeKeeperServer(folders=[
        {"uid": "SHARED", "name": "Synthetic shared", "parent": None},
        {"uid": uid, "name": "Synthetic target", "parent": "SHARED"},
    ], delete_status={uid: ["access_denied", detail]})
    keeper = folder_task(object.__new__(KeeperAnsible), no_log)
    keeper.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()), log_level="DEBUG")
    before = logger_state(logger)
    try:
        with server.patch(), pytest.raises(KeeperFolderError, match="Diagnostic details are hidden" if no_log else detail):
            keeper.delete_folder(uid)
        if no_log:
            assert uid not in output.getvalue() and detail not in output.getvalue()
        assert server.folder(uid) is not None
        assert logger_state(logger) == before
    finally:
        server.cleanup()


@pytest.mark.parametrize("callback", ["default", "keeper_redact"])
def test_no_log_real_sdk_skip_and_refusal_are_censored_by_both_callbacks(callback, tmp_path):
    """Exercise real local-source skip/refusal logging, retaining the public SDK 17.3 early-failure control."""
    skipped, refused = "PRIVATE_UNREADABLE_UID_5934", "PRIVATE_REFUSED_UID_5934"
    detail = "PRIVATE_REFUSAL_DETAIL_5934"
    server = PrivateUnreadableServer(folders=[
        {"uid": "SHARED", "name": "Synthetic shared", "parent": None},
        {"uid": skipped, "name": "PRIVATE_UNREADABLE_NAME_5934", "parent": "SHARED"},
        {"uid": refused, "name": "PRIVATE_REFUSED_NAME_5934", "parent": "SHARED"},
    ], delete_status={refused: ["access_denied", detail]})
    original_init = SecretsManager.__init__

    def logged_init(sm, *args, **kwargs):
        kwargs["log_level"] = "DEBUG"
        original_init(sm, *args, **kwargs)

    playbook = tmp_path / "private_sdk_logging.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "my_systems", "gather_facts": False, "tasks": [
            {"name": "Read private SDK metadata", "keeper_get_folder": {
                "shared_folder_uid": "SHARED", "include_subfolders": True,
            }, "register": "looked_up", "no_log": True, "ignore_errors": True},
            {"name": "Attempt refused private operation", "keeper_delete_folder": {
                "folder_uid": refused,
            }, "register": "deleted", "no_log": True, "ignore_errors": True},
            {"name": "Keep the failure visible only as status", "assert": {"that": [
                "deleted is failed", "deleted is not changed",
            ]}, "no_log": True},
        ],
    }], sort_keys=False), encoding="utf-8")
    callback_dir = Path(__file__).resolve().parents[1] / "keeper_secrets_manager_ansible/plugins/callback"
    environment = {"ANSIBLE_STDOUT_CALLBACK": callback, "ANSIBLE_CALLBACK_PLUGINS": str(callback_dir)}
    with patch.dict(os.environ, environment), patch.object(SecretsManager, "__init__", logged_init):
        with run_target(server, str(playbook), {}) as (recap, out, err):
            assert recap.get("failed") == 0 and recap.get("ignored") in (1, 2), out + err
            assert "censored" in out + err or "no_log" in out + err
            for value in (skipped, refused, detail, "PRIVATE_UNREADABLE_NAME_5934", "PRIVATE_REFUSED_NAME_5934"):
                assert value not in out + err, out + err
            assert server.folder(skipped) is not None and server.folder(refused) is not None
            if server.calls("delete_folder"):
                assert server.calls("delete_folder") == [
                    {"path": "delete_folder", "folder_uids": [refused], "force": False},
                ]
