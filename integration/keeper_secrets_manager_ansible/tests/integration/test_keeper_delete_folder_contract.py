from contextlib import contextmanager

import pytest
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFolderError
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
