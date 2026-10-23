from contextlib import contextmanager
import logging
from unittest.mock import patch

import pytest
import yaml
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFolderError
from ._helpers import run_target
from ..folder_fake_server import FakeKeeperServer, NOT_EMPTY_CODE

UID = "EMPTY_UID"
FOLDERS = [
    {"uid": "SHARED_UID", "name": "Infrastructure", "parent": None},
    {"uid": UID, "name": "Staging", "parent": "SHARED_UID"},
]
HIDDEN_RECORD = {"uid": "HIDDEN_UID", "title": "Hidden", "folder": "NOT_SHARED_TO_APP", "inner": UID}
DELETE_REQUEST = [{"path": "delete_folder", "folder_uids": [UID], "force": False}]


@contextmanager
def real_keeper(server):
    try:
        keeper = object.__new__(KeeperAnsible)
        keeper.client = SecretsManager(config=InMemoryKeyValueStorage(config=mock.MockConfig.make_base64()))
        with server.patch():
            yield keeper
    finally:
        server.cleanup()


@pytest.mark.parametrize("options, code", [
    pytest.param({"delete_status": {UID: ["access_denied", "No permission"]}}, "access_denied", id="access_denied"),
    pytest.param({"records": [HIDDEN_RECORD]}, NOT_EMPTY_CODE, id="record_hidden_from_the_application"),
])
def test_a_real_sdk_refusal_never_reports_a_delete(options, code):
    server = FakeKeeperServer(folders=FOLDERS, **options)
    with real_keeper(server) as keeper:
        with pytest.raises(KeeperFolderError) as error:
            keeper.delete_folder(UID)
        assert "returned {}:".format(code) in str(error.value)
        assert server.folders() == FOLDERS
        assert server.records() == options.get("records", [])
        assert server.calls("delete_folder") == DELETE_REQUEST
        assert len(server.calls("get_folders")) == 1


class DeleteResponseServer(FakeKeeperServer):
    def __init__(self, body, **kwargs):
        self.body = body
        super().__init__(**kwargs)

    def handle(self, sm, path, payload):
        response = super().handle(sm, path, payload)
        return self._json(self.body) if path == "delete_folder" else response


@pytest.mark.parametrize("gone", [False, True], ids=["folder_exists", "folder_gone"])
@pytest.mark.parametrize("body", [{}, {"folders": None}, {"folders": []}],
                         ids=["missing_status_key", "null_status", "empty_status"])
def test_a_missing_real_sdk_status_is_verified_with_a_second_read(body, gone):
    # SDK 17.3 returns {}, None, or []; newer SDKs normalize missing and null statuses to [].
    server = DeleteResponseServer(body=body, folders=FOLDERS, omit_delete_status=not gone)
    with real_keeper(server) as keeper:
        if gone:
            assert keeper.delete_folder(UID) == {"changed": True, "folder_uid": UID, "folder_name": "Staging"}
            assert server.folder(UID) is None
        else:
            with pytest.raises(KeeperFolderError, match="and the folder still exists"):
                keeper.delete_folder(UID)
            assert server.folders() == FOLDERS
        assert server.calls("delete_folder") == DELETE_REQUEST
        assert len(server.calls("get_folders")) == 2


@pytest.mark.parametrize("force", [False, True], ids=["nonforce", "force"])
@pytest.mark.parametrize("response, skipped_uid", [
    pytest.param([], UID, id="empty_status"), pytest.param({}, UID, id="missing_status"),
    pytest.param(None, UID, id="null_status"), pytest.param("garbage", UID, id="non_list_status"),
    pytest.param({"folders": None}, UID, id="null_folder_status"),
    pytest.param({"folders": "garbage"}, UID, id="malformed_folder_status"),
    pytest.param([{"folderUid": UID + "_2", "responseCode": "ok"}], UID, id="another_uid_status"),
    pytest.param([{"responseCode": "ok"}], UID, id="status_without_uid"),
    pytest.param([], None, id="unidentified_none_uid"), pytest.param([], "", id="unidentified_empty_uid"),
    pytest.param([], " ", id="unidentified_blank_uid"),
])
def test_simulated_partial_read_never_confirms_an_unreadable_delete(response, skipped_uid, force):
    """Simulate SDK partial-read compatibility; do not describe this as public SDK 17.3 behavior."""
    server = FakeKeeperServer(folders=FOLDERS, omit_delete_status=True)
    with real_keeper(server) as keeper:
        original_get, original_delete = keeper.client.get_folders, keeper.client.delete_folder
        reads = []

        def partial_read():
            folders = original_get()
            reads.append(folders)
            if len(reads) == 2:
                logging.getLogger(logger_name).warning("Folder %s skipped due to error: %s", skipped_uid,
                                                       "simulated unreadable metadata")
                return [folder for folder in folders if folder.folder_uid != UID]
            return folders

        def missing_status(*args, **kwargs):
            original_delete(*args, **kwargs)
            return response

        with patch.object(keeper.client, "get_folders", side_effect=partial_read), \
                patch.object(keeper.client, "delete_folder", side_effect=missing_status), \
                pytest.raises(KeeperFolderError, match="so it can still exist"):
            keeper.delete_folder(UID, force=force)
        assert server.folder(UID) is not None
        assert server.calls("delete_folder") == [{"path": "delete_folder", "folder_uids": [UID], "force": force}]
        assert len(reads) == len(server.calls("get_folders")) == 2


@pytest.mark.parametrize("force", [False, True], ids=["nonforce", "force"])
def test_partial_read_of_a_different_exact_uid_does_not_block_confirmed_absence(force):
    other_uid = UID + "_2"
    folders = FOLDERS + [{"uid": other_uid, "name": "Unrelated", "parent": "SHARED_UID"}]
    server = DeleteResponseServer(body={"folders": []}, folders=folders)
    with real_keeper(server) as keeper:
        original_get = keeper.client.get_folders
        read_count = 0

        def partial_read():
            nonlocal read_count
            read_count += 1
            readable = original_get()
            if read_count == 2:
                logging.getLogger(logger_name).warning("Folder %s skipped due to error: %s", other_uid,
                                                       "simulated unreadable metadata")
                return [folder for folder in readable if folder.folder_uid != other_uid]
            return readable

        with patch.object(keeper.client, "get_folders", side_effect=partial_read):
            assert keeper.delete_folder(UID, force=force) == {
                "changed": True, "folder_uid": UID, "folder_name": "Staging",
            }
        assert server.folder(UID) is None
        assert server.folder(other_uid) is not None
        assert read_count == 2


class UnreadableDeleteReadbackServer(DeleteResponseServer):
    """Keep the target in fake state, corrupting only its encrypted name after the unconfirmed request."""

    def _folder_list(self, state, app_key):
        folders = super()._folder_list(state, app_key)
        if any(call["path"] == "delete_folder" for call in state["calls"]):
            for folder in folders:
                if folder["folderUid"] == UID:
                    folder["data"] = "invalid-ciphertext"
        return folders


@pytest.mark.parametrize("force", [False, True], ids=["nonforce", "force"])
@pytest.mark.parametrize("body", [{}, {"folders": None}, {"folders": []}],
                         ids=["missing_status_key", "null_status", "empty_status"])
def test_real_sdk_unreadable_readback_never_reports_a_confirmed_delete(body, force):
    """Public SDK 17.3 fails decoding; skip-and-continue coverage uses qualified local-source SDK installations."""
    server = UnreadableDeleteReadbackServer(body=body, folders=FOLDERS, omit_delete_status=True)
    with real_keeper(server) as keeper:
        with pytest.raises(KeeperFolderError) as error:
            keeper.delete_folder(UID, force=force)
        message = str(error.value)
        assert "folder is unreadable, so it can still exist" in message or \
            "the check of the folder list after it failed, so the folder can still exist" in message, message
        assert server.folder(UID) is not None
        assert server.calls("delete_folder") == [{"path": "delete_folder", "folder_uids": [UID], "force": force}]
        assert len(server.calls("get_folders")) == 2


@pytest.mark.parametrize("force", [False, True], ids=["nonforce", "force"])
def test_unconfirmed_delete_check_mode_does_not_send_a_request_or_readback(force):
    server = UnreadableDeleteReadbackServer(body={"folders": []}, folders=FOLDERS, omit_delete_status=True)
    with real_keeper(server) as keeper:
        assert keeper.delete_folder(UID, force=force, check_mode=True) == {
            "changed": True, "folder_uid": UID, "folder_name": "Staging",
        }
        assert server.folders() == FOLDERS
        assert not server.calls("delete_folder")
        assert len(server.calls("get_folders")) == 1


@pytest.mark.parametrize("force", [False, True], ids=["nonforce", "force"])
def test_action_does_not_report_a_confirmed_unreadable_delete(force, tmp_path):
    server = UnreadableDeleteReadbackServer(body={"folders": []}, folders=FOLDERS, omit_delete_status=True)
    playbook = tmp_path / "unconfirmed_delete.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "my_systems", "gather_facts": False, "tasks": [
            {"name": "Attempt unconfirmed deletion", "keeper_delete_folder": {
                "folder_uid": UID, "force_deletion": force,
            }, "register": "deleted", "ignore_errors": True},
            {"name": "Require a failed result", "assert": {"that": [
                "deleted is failed", "deleted is not changed", "'folder_uid' not in deleted",
                "'did not confirm' in deleted.msg or 'sent no result' in deleted.msg",
            ]}},
        ],
    }], sort_keys=False), encoding="utf-8")
    with run_target(server, str(playbook), {}) as (recap, out, err):
        assert recap.get("failed") == 0 and recap.get("ignored") == 1, out + err
        assert server.folder(UID) is not None
        assert server.calls("delete_folder") == [{"path": "delete_folder", "folder_uids": [UID], "force": force}]
        assert len(server.calls("get_folders")) == 2
