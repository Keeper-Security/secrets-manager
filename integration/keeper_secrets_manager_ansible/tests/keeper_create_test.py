import base64
import json
import tempfile
import unittest
from unittest.mock import patch

import pytest
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.dtos import KeeperFolder, RecordCreate
from keeper_secrets_manager_core.mock import Record, Response
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from keeper_secrets_manager_ansible import KeeperAnsible

from .ansible_test_framework import AnsibleTestFramework
from .folder_fake_server import FakeKeeperServer


mock_response = Response()
mock_record = Record(title="Record 1", record_type="login")
mock_record.field("password", "MYPASSWORD")
mock_response.add_record(record=mock_record)


# This is tied to the test. If additional tests are added, they will need their own create_secret mock method.
def mocked_create_secret(*args, **kwargs):

    # args[0] is a CreateOptions object (folder_uid, subfolder_uid)
    _ = args[0]
    record_create = args[1]

    if len(record_create.fields) < 1:
        raise AssertionError("Record create doesn't have enough fields.")
    if len(record_create.fields[1].value) != 1:
        raise AssertionError("Record create doesn't have one password.")

    password_value = None
    for field in record_create.fields:
        if field.type == "password":
            password_value = field.value
            break
    if password_value is None:
        raise AssertionError("Could not find password field in record")
    if len(password_value) == 0:
        raise AssertionError("Found password field, but the value is blank.")

    password = password_value[0]
    if len(password) != 128:
        raise AssertionError("Record create password is not 128 chars long, only {}.".format(len(password)))

    # Make sure the lowercase letter are not in the password. We are filtering them out.
    for index in range(0, 25):
        char = "abcdefghijklmnopqrstuvwxyz"[index]
        if char in password:
            raise AssertionError("Found a lowercase letter in the password. Not allowed in this test.")

    return "NEW_UID"


class KeeperCreateTest(unittest.TestCase):

    @patch.object(SecretsManager, "get_folders", return_value=[KeeperFolder(b"k" * 32, "XXXXX", "", "Shared")])
    @patch("keeper_secrets_manager_core.core.SecretsManager.create_secret_with_options", side_effect=mocked_create_secret)
    def test_keeper_create(self, mock_create, mock_folders):
        with tempfile.TemporaryDirectory() as _:
            a = AnsibleTestFramework(
                playbook="keeper_create.yml",
                vars={
                    "shared_folder_uid": "XXXXX"
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 2, "2 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 1, "the record creation should report changed")


CREATE_FOLDERS = [
    {"uid": "SHARED_A", "name": "Shared A", "parent": None},
    {"uid": "SHARED_B", "name": "Shared B", "parent": None},
    {"uid": "PARENT_A", "name": "Parent A", "parent": "SHARED_A"},
    {"uid": "PARENT_B", "name": "Parent B", "parent": "SHARED_B"},
    {"uid": "DEEP_A", "name": "Deep A", "parent": "PARENT_A"},
]
INVALID_CREATE_TARGETS = [
    pytest.param("SHARED_A", "PARENT_B", "is not inside the shared folder", id="different_shared_root"),
    pytest.param("PARENT_A", None, "is a subfolder, not a shared folder", id="subfolder_as_shared_root"),
    pytest.param("MISSING", None, "folder key for MISSING not found", id="missing_shared_root"),
    pytest.param("SHARED_A", "MISSING", "The subfolder MISSING was not found", id="missing_subfolder"),
    pytest.param("SHARED_A", "SHARED_A", "is not inside the shared folder", id="root_as_subfolder"),
]


class RecordCreateServer(FakeKeeperServer):
    """Reuse the encrypted folder fixture, recording and decrypting synthetic record creation payloads."""

    def handle(self, sm, path, payload):
        if path != "create_secret":
            return super().handle(sm, path, payload)
        state = self._load()
        shared = self._find(state, payload.folderUid)
        record_key = CryptoUtils.decrypt_aes(base64.b64decode(payload.folderKey), base64.b64decode(shared["key"]))
        record = json.loads(CryptoUtils.decrypt_aes(base64.b64decode(payload.data), record_key).decode())
        state["calls"].append({
            "path": path, "shared_folder_uid": payload.folderUid, "subfolder_uid": payload.subFolderUid,
            "record_uid": payload.recordUid, "record": record,
        })
        self._save(state)
        return self._json({})


@pytest.fixture
def record_hierarchy():
    server = RecordCreateServer(folders=CREATE_FOLDERS)
    keeper = object.__new__(KeeperAnsible)
    keeper.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()), log_level="ERROR")
    record = RecordCreate("login", "Synthetic hierarchy record")
    record.fields = []
    reads = []
    original_get = keeper.client.get_folders

    def get_folders():
        folders = original_get()
        reads.append(folders)
        return folders

    try:
        with server.patch(), patch.object(keeper.client, "get_folders", side_effect=get_folders), \
                patch.object(SecretsManager, "prepare_create_payload",
                             wraps=SecretsManager.prepare_create_payload) as prepare, \
                patch.object(keeper.client, "create_secret_with_options",
                             wraps=keeper.client.create_secret_with_options) as create:
            yield server, keeper, record, reads, prepare, create
    finally:
        server.cleanup()


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("shared, subfolder, message", INVALID_CREATE_TARGETS)
def test_record_creation_rejects_invalid_hierarchy_before_payload_preparation(record_hierarchy, check_mode,
                                                                            shared, subfolder, message):
    server, keeper, record, reads, prepare, create = record_hierarchy
    with patch.object(record, "to_json", wraps=record.to_json) as serialize:
        with pytest.raises(Exception, match=message):
            keeper.create_record(record, shared, subfolder_uid=subfolder, check_mode=check_mode)
        serialize.assert_not_called()
    prepare.assert_not_called()
    create.assert_not_called()
    assert len(reads) == 1
    assert [call["path"] for call in server.calls()] == ["get_folders"]
    assert server.folders() == CREATE_FOLDERS


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("subfolder, expected", [
    pytest.param(None, None, id="null_subfolder"), pytest.param("", None, id="empty_subfolder"),
    pytest.param("PARENT_A", "PARENT_A", id="direct_child"), pytest.param("DEEP_A", "DEEP_A", id="deep_child"),
])
def test_record_creation_uses_one_validated_folder_read_and_the_shared_root_key(record_hierarchy, check_mode,
                                                                               subfolder, expected):
    server, keeper, record, reads, prepare, create = record_hierarchy
    result = keeper.create_record(record, "SHARED_A", subfolder_uid=subfolder, check_mode=check_mode)
    assert len(reads) == 1
    shared_key = next(f.folder_key for f in reads[0] if f.folder_uid == "SHARED_A")
    prepare.assert_called_once()
    assert prepare.call_args.args[3] == shared_key
    options = prepare.call_args.args[1]
    assert (options.folder_uid, options.subfolder_uid) == ("SHARED_A", expected)
    if check_mode:
        assert result is None
        create.assert_not_called()
        assert not server.calls("create_secret")
    else:
        create.assert_called_once()
        assert create.call_args.kwargs["folders"] is reads[0]
        call, = server.calls("create_secret")
        assert result == call["record_uid"]
        assert (call["shared_folder_uid"], call["subfolder_uid"]) == ("SHARED_A", expected)
        assert call["record"]["title"] == record.title


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("folders", [
    pytest.param([KeeperFolder(b"k" * 32, "SHARED_A", "", "A"),
                  KeeperFolder(b"s" * 32, "ORPHAN", "MISSING", "Orphan")], id="missing_ancestor"),
    pytest.param([KeeperFolder(b"k" * 32, "SHARED_A", "", "A"),
                  KeeperFolder(b"s" * 32, "ORPHAN", "CYCLE", "Child"),
                  KeeperFolder(b"c" * 32, "CYCLE", "ORPHAN", "Parent")], id="cycle"),
    pytest.param([KeeperFolder(None, "SHARED_A", "", "A")], id="missing_root_key"),
])
def test_record_creation_rejects_incomplete_or_cyclic_hierarchy(record_hierarchy, check_mode, folders):
    server, keeper, record, _, prepare, create = record_hierarchy
    with patch.object(keeper.client, "get_folders", return_value=folders):
        with pytest.raises(Exception, match="not inside the shared folder|folder key for SHARED_A not found"):
            keeper.create_record(record, "SHARED_A", subfolder_uid="ORPHAN", check_mode=check_mode)
    prepare.assert_not_called()
    create.assert_not_called()
    assert not server.calls()
