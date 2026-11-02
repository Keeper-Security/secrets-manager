import pytest
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from keeper_secrets_manager_ansible import KeeperAnsible
from .folder_fake_server import FakeKeeperServer

FOLDERS = [
    {"uid": "SF_A", "name": "Shared A", "parent": None},
    {"uid": "SF_B", "name": "Shared B", "parent": None},
    {"uid": "PARENT_A", "name": "Parent A", "parent": "SF_A"},
    {"uid": "DEEP_A", "name": "Deep A", "parent": "PARENT_A"},
    {"uid": "PARENT_B", "name": "Parent B", "parent": "SF_B"},
    {"uid": "DEEP_B", "name": "Deep B", "parent": "PARENT_B"},
] + [
    {"uid": "CHILD_" + parent, "name": "Existing", "parent": parent}
    for parent in ("SF_A", "PARENT_A", "DEEP_A", "DEEP_B")
]


@pytest.fixture
def vault():
    server = FakeKeeperServer(folders=FOLDERS)
    keeper = object.__new__(KeeperAnsible)
    keeper.client = SecretsManager(config=InMemoryKeyValueStorage(config=mock.MockConfig.make_base64()),
                                   log_level="ERROR")
    try:
        with server.patch():
            yield keeper, server
    finally:
        server.cleanup()


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("name", ["Existing", "New"])
@pytest.mark.parametrize("shared, parent, message", [
    ("SF_A", "DEEP_B", "not inside the shared folder"),
    ("MISSING", "DEEP_B", "folder key for MISSING not found"),
    ("PARENT_B", "DEEP_B", "is a subfolder, not a shared folder"),
    ("SF_A", "MISSING", "The subfolder MISSING was not found"),
], ids=["wrong-root", "missing-root", "nested-root", "missing-parent"])
def test_invalid_target_fails_before_existing_or_new_child(vault, shared, parent, message, name, check_mode):
    keeper, server = vault
    with pytest.raises(Exception, match=message):
        keeper.create_folder(name, shared, subfolder_uid=parent, check_mode=check_mode)
    assert server.calls("create_folder") == []
    assert server.folders() == FOLDERS


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("parent", [None, "PARENT_A", "DEEP_A"], ids=["shared", "nested", "deep"])
@pytest.mark.parametrize("name", ["Existing", "New"])
def test_valid_target_preserves_idempotency_and_correct_parent(vault, parent, name, check_mode):
    keeper, server = vault
    uid, changed = keeper.create_folder(name, "SF_A", subfolder_uid=parent, check_mode=check_mode)
    existing = name == "Existing"
    assert changed == (not existing)
    assert len(server.calls("create_folder")) == int(not existing and not check_mode)
    if existing:
        assert uid == "CHILD_" + (parent or "SF_A")
    elif check_mode:
        assert uid is None
        assert server.folders() == FOLDERS
    else:
        created = server.calls("create_folder")[0]
        assert (created["shared_folder_uid"], created["parent_uid"], created["folder_name"]) == ("SF_A", parent, name)
        assert server.folder(uid) == {"uid": uid, "name": name, "parent": parent or "SF_A"}
        assert keeper.create_folder(name, "SF_A", subfolder_uid=parent) == (uid, False)
        assert len(server.calls("create_folder")) == 1
