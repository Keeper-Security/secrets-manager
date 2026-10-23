import base64
import copy
import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.dtos import KeeperFile, SecretsManagerResponse
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFieldType
from .ansible_test_framework import AnsibleTestFramework
from .folder_fake_server import FakeKeeperServer, _b64
from .unreadable_record_server import FAULTS, SECRET, TITLE, UnreadableRecordServer

UID = "STALE_CACHE_RECORD_UID"
SHARED_UID = "SHARED_FOLDER_UID"


def _wrapped_selector(selected, wrapper):
    return selected if wrapper is None else {key: wrapper([value]) for key, value in selected.items()}


class _NotesServer(FakeKeeperServer):
    """A fake server that keeps the notes of each record and applies update_secret to them."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        state = self._load()
        for record in state["records"]:
            record["key"] = _b64(os.urandom(32))
        self._save(state)

    @staticmethod
    def _secrets(state, app_key):
        folders = {folder["uid"]: {
            "folderUid": folder["uid"],
            "folderKey": _b64(CryptoUtils.encrypt_aes(base64.b64decode(folder["key"]), app_key)),
            "records": [],
        } for folder in state["folders"]}
        for record in state["records"]:
            record_key = base64.b64decode(record["key"])
            folder_key = base64.b64decode(FakeKeeperServer._find(state, record["folder"])["key"])
            data = {"type": "login", "title": record["title"], "fields": [], "custom": [],
                    "notes": record.get("notes", "")}
            folders[record["folder"]]["records"].append({
                "recordUid": record["uid"],
                "recordKey": _b64(CryptoUtils.encrypt_aes(record_key, folder_key)),
                "data": _b64(CryptoUtils.encrypt_aes(json.dumps(data).encode(), record_key)),
                "isEditable": True, "files": None,
            })
        return {"folders": list(folders.values()), "records": []}

    def handle(self, sm, path, payload):
        if path != "update_secret":
            return super().handle(sm, path, payload)
        state = self._load()
        target = next(record for record in state["records"] if record["uid"] == payload.recordUid)
        record_key = base64.b64decode(target["key"])
        data = json.loads(CryptoUtils.decrypt_aes(base64.b64decode(payload.data), record_key).decode())
        state["calls"].append({"path": path, "record_uid": payload.recordUid, "notes": data.get("notes")})
        for record in state["records"]:
            if record["uid"] == payload.recordUid:
                record["notes"] = data.get("notes")
        self._save(state)
        return b""


class KeeperSetCacheTest(unittest.TestCase):
    """keeper_set must decide and save from the vault, not from a registered cache that can be outdated."""

    def test_an_outdated_cache_cannot_hide_a_needed_save(self):
        for name in list(sys.modules):
            if name.startswith("ansible"):
                sys.modules.pop(name, None)
        server = _NotesServer(folders=[{"uid": SHARED_UID, "name": "Shared", "parent": None}],
                              records=[{"uid": UID, "title": "Stale Cache Record", "folder": SHARED_UID,
                                        "notes": "target"}])
        self.addCleanup(server.cleanup)
        from ansible.errors import AnsibleError
        with server.patch(), patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError):
            recap, out, err = AnsibleTestFramework(
                playbook="keeper_set_stale_cache.yml",
                vars={"uid": UID, "keeper_record_cache_secret": "outdated-cache-test-only"},
            ).run()
        self.assertEqual(recap.get("failed"), 0, out + err)
        self.assertEqual(recap.get("changed"), 2, out + err)
        self.assertEqual([call["notes"] for call in server.calls("update_secret")], ["drifted", "target"])
        self.assertEqual(server.records()[0]["notes"], "target")

    def test_set_value_does_not_read_the_registered_cache(self):
        keeper = object.__new__(KeeperAnsible)
        keeper.client = SimpleNamespace(save=lambda record: None)
        record = SimpleNamespace(uid=UID, title="Record", dict={"notes": "old"}, _update=lambda: None)
        with patch.object(keeper, "get_records_from_cache") as from_cache, \
                patch.object(keeper, "get_records_from_vault", return_value=[record]) as from_vault:
            self.assertTrue(keeper.set_value(KeeperFieldType.NOTES, None, "new", uid=UID, cache="REGISTERED_CACHE"))
        from_cache.assert_not_called()
        from_vault.assert_called_once()


class _UnreadableNotesServer(UnreadableRecordServer, _NotesServer):
    """Reuse the unreadable response faults with independent folder and record encryption keys."""

    def _secrets(self, state, app_key):
        response = super()._secrets(state, app_key)
        if self.fault in ("attachment", "record_data"):
            record_key = base64.b64decode(state["records"][0]["key"])
            record = response["records"][0]
            record["recordKey"] = _b64(CryptoUtils.encrypt_aes(record_key, app_key))
            if self.fault == "record_data":
                invalid_json = b'{"password": "' + SECRET.encode() + b'"'
                record["data"] = _b64(CryptoUtils.encrypt_aes(invalid_json, record_key))
        return response


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("fault", FAULTS)
@pytest.mark.parametrize("selector", ["title", "readable_uid", "unreadable_uid"])
@pytest.mark.parametrize("wrapper", [None, list, tuple], ids=["scalar", "list", "tuple"])
def test_unreadable_live_targets_cannot_redirect_a_save(fault, selector, check_mode, wrapper):
    server = _UnreadableNotesServer(fault, shared_title=True)
    keeper = object.__new__(KeeperAnsible)
    keeper.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()))
    selected = {"title": {"title": TITLE}, "readable_uid": {"uid": "OTHER_UID"},
                "unreadable_uid": {"uid": "RECORD_UID"}}[selector]
    arguments = _wrapped_selector(selected, wrapper)
    acquisitions = []
    real_read = keeper.client.get_secrets

    def acquire(*args, **kwargs):
        response = real_read(*args, **kwargs)
        acquisitions.append(response)
        return response

    file_init = KeeperFile.__init__
    try:
        with server.patch(), patch.object(keeper.client, "get_secrets", side_effect=acquire) as read, \
                patch.object(keeper.client, "save", wraps=keeper.client.save) as save, \
                patch.object(KeeperFile, "__init__", autospec=True, side_effect=file_init) as file_constructor:
            if selector == "readable_uid":
                assert keeper.set_value(KeeperFieldType.NOTES, None, SECRET, check_mode=check_mode, **arguments)
            else:
                with pytest.raises(ValueError, match="uniqueness|unreadable") as error:
                    keeper.set_value(KeeperFieldType.NOTES, None, SECRET, check_mode=check_mode, **arguments)
                assert SECRET not in str(error.value)
            read.assert_called_once_with(*(() if selector == "title" else ([selected["uid"]],)),
                                         full_response=True)
            assert save.call_count == int(selector == "readable_uid" and not check_mode)
            if selector == "title" and not check_mode:
                if fault == "attachment":
                    file_constructor.assert_called_once()
                elif fault == "record_data":
                    file_constructor.assert_not_called()
                    damaged = acquisitions[0].bad_records[0]["r"]
                    app_key = base64.b64decode(keeper.client.config.get(ConfigKeys.KEY_APP_KEY))
                    record_key = CryptoUtils.decrypt_aes(base64.b64decode(damaged["recordKey"]), app_key)
                    with pytest.raises(json.JSONDecodeError):
                        json.loads(CryptoUtils.decrypt_aes(base64.b64decode(damaged["data"]), record_key))
        writes = server.calls("update_secret")
        assert [(call["record_uid"], call["notes"]) for call in writes] == (
            [("OTHER_UID", SECRET)] if selector == "readable_uid" and not check_mode else [])
        assert KeeperAnsible._dr_cache_allowed
    finally:
        server.cleanup()


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("kind,outcome", [
    ("bad_record", "uniqueness"), ("bad_folder", "uniqueness"), ("unknown_folder", "uniqueness"),
    ("duplicate", "multiple"), ("missing", "Could not find"), ("unique", None), ("unrelated_duplicates", None),
])
def test_title_selection_is_confirmed_before_any_local_or_remote_mutation(kind, outcome, check_mode):
    from ansible.errors import AnsibleError
    record = SimpleNamespace(uid=UID, title=TITLE, dict={"notes": "old"}, _update=Mock())
    response = SecretsManagerResponse()
    response.records = [] if kind == "missing" else [record]
    if kind == "bad_record":
        response.bad_records = [{"r": {"recordUid": "UNREADABLE_UID"}, "err": SECRET}]
    if kind in ("bad_folder", "unknown_folder"):
        response.bad_folders = [{"f": {"records": [] if kind == "unknown_folder" else
                                     [{"recordUid": "UNREADABLE_UID"}]}, "err": SECRET}]
        if kind == "unknown_folder":
            response.bad_folders[0]["f"].pop("records")
    if kind == "duplicate":
        response.records.append(SimpleNamespace(uid="SECOND_UID", title=TITLE))
    elif kind == "unrelated_duplicates":
        response.records.extend([SimpleNamespace(uid="UNRELATED_UID", title="Unrelated") for _ in range(2)])
    keeper = object.__new__(KeeperAnsible)
    keeper.client = SimpleNamespace(get_secrets=Mock(return_value=response), save=Mock())
    before = copy.deepcopy(record.dict)
    with patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError):
        if outcome:
            with pytest.raises((ValueError, AnsibleError), match=outcome) as error:
                keeper.set_value(KeeperFieldType.NOTES, None, SECRET, title=TITLE, check_mode=check_mode)
            assert SECRET not in str(error.value)
            assert record.dict == before
            record._update.assert_not_called()
        else:
            assert keeper.set_value(KeeperFieldType.NOTES, None, SECRET, title=TITLE, check_mode=check_mode)
    keeper.client.get_secrets.assert_called_once_with(full_response=True)
    assert keeper.client.save.call_count == int(outcome is None and not check_mode)


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("selector,returned", [
    ({"uid": UID}, []),
    ({"uid": [UID, "SECOND_UID"]}, [UID, "SECOND_UID"]),
    ({"title": TITLE}, [UID, "SECOND_UID"]),
])
def test_singular_updates_never_mutate_missing_or_ambiguous_acquisitions(selector, returned, check_mode):
    from ansible.errors import AnsibleError
    keeper = object.__new__(KeeperAnsible)
    keeper.client = SimpleNamespace(save=Mock())
    records = [SimpleNamespace(uid=uid, title=TITLE, dict={"notes": "old"}, _update=Mock()) for uid in returned]
    with patch.object(keeper, "get_records_from_vault", return_value=records) as read, \
            patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError):
        with pytest.raises((ValueError, AnsibleError), match="single|multiple|Could not find"):
            keeper.set_value(KeeperFieldType.NOTES, None, SECRET, check_mode=check_mode, **selector)
    if any(isinstance(value, list) for value in selector.values()):
        read.assert_not_called()
    else:
        read.assert_called_once_with(uids=selector.get("uid"), titles=selector.get("title"), allow_missing=True,
                                     require_unique_uids=True)
    keeper.client.save.assert_not_called()
    for record in records:
        assert record.dict == {"notes": "old"}
        record._update.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("selector", ["uid", "title"])
@pytest.mark.parametrize("wrapper", [list, tuple], ids=["list", "tuple"])
@pytest.mark.parametrize("kind", ["unique", "unchanged", "missing", "duplicate"])
def test_singleton_selectors_preserve_live_selection_behavior(kind, wrapper, selector, check_mode):
    from ansible.errors import AnsibleError

    record = SimpleNamespace(uid=UID, title=TITLE, dict={"notes": "old"}, _update=Mock())
    response = SecretsManagerResponse()
    response.records = [] if kind == "missing" else [record]
    if kind == "duplicate":
        response.records.append(SimpleNamespace(
            uid=UID if selector == "uid" else "SECOND_UID", title=TITLE, dict={"notes": "other"}, _update=Mock()))
    keeper = object.__new__(KeeperAnsible)
    keeper.client = SimpleNamespace(get_secrets=Mock(return_value=response), save=Mock())
    selected = _wrapped_selector({selector: UID if selector == "uid" else TITLE}, wrapper)
    originals = [copy.deepcopy(item.dict) for item in response.records]
    value = "old" if kind == "unchanged" else SECRET
    with patch.object(keeper, "get_records_from_cache") as from_cache, \
            patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError):
        if kind in ("missing", "duplicate"):
            with pytest.raises((ValueError, AnsibleError), match="Could not find|multiple") as error:
                keeper.set_value(KeeperFieldType.NOTES, None, value, cache="REGISTERED_CACHE",
                                 check_mode=check_mode, **selected)
            assert SECRET not in str(error.value)
            assert [item.dict for item in response.records] == originals
            record._update.assert_not_called()
            for item in response.records:
                item._update.assert_not_called()
        else:
            assert keeper.set_value(KeeperFieldType.NOTES, None, value, cache="REGISTERED_CACHE",
                                    check_mode=check_mode, **selected) == (kind == "unique")
            assert record.dict == {"notes": value}
            record._update.assert_called_once()
    from_cache.assert_not_called()
    keeper.client.get_secrets.assert_called_once_with(*(([UID],) if selector == "uid" else ()), full_response=True)
    assert keeper.client.save.call_count == int(kind == "unique" and not check_mode)
    assert KeeperAnsible._dr_cache_allowed


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("selector", ["uid", "title"])
@pytest.mark.parametrize("container", [
    lambda value: [],
    lambda value: (),
    lambda value: [value, "MISSING_SELECTION"],
    lambda value: (value, "MISSING_SELECTION"),
    lambda value: {value},
    lambda value: {"value": value},
    lambda value: [[value]],
    lambda value: ([value],),
    lambda value: [(value,)],
    lambda value: ((value,),),
    lambda value: [{value}],
    lambda value: ({value},),
    lambda value: [{"value": value}],
    lambda value: ({"value": value},),
], ids=[
    "empty-list", "empty-tuple", "multiple-list", "multiple-tuple", "set", "dict",
    "list-list", "tuple-list", "list-tuple", "tuple-tuple", "list-set", "tuple-set", "list-dict", "tuple-dict",
])
def test_non_singular_selectors_fail_before_vault_lookup(container, selector, check_mode):
    record = SimpleNamespace(uid=UID, title=TITLE, dict={"notes": "old"}, _update=Mock())
    keeper = object.__new__(KeeperAnsible)
    keeper.client = SimpleNamespace(save=Mock())
    selected = {selector: container(UID if selector == "uid" else TITLE)}
    with patch.object(keeper, "get_records_from_vault", return_value=[record]) as read, \
            patch.object(keeper, "get_records_from_cache") as from_cache:
        with pytest.raises(ValueError, match="single UID or title") as error:
            keeper.set_value(KeeperFieldType.NOTES, None, SECRET, cache="REGISTERED_CACHE",
                             check_mode=check_mode, **selected)
        assert SECRET not in str(error.value)
    read.assert_not_called()
    from_cache.assert_not_called()
    keeper.client.save.assert_not_called()
    assert record.dict == {"notes": "old"}
    record._update.assert_not_called()
    assert KeeperAnsible._dr_cache_allowed


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("selector", ["uid", "title"])
@pytest.mark.parametrize("multiple", [False, True], ids=["singleton", "multiple"])
def test_native_templated_selectors_preserve_update_behavior(tmp_path, multiple, selector, check_mode):
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)
    from ansible.errors import AnsibleError

    server = _NotesServer(
        folders=[{"uid": SHARED_UID, "name": "Shared"}],
        records=[{"uid": UID, "title": TITLE, "folder": SHARED_UID, "notes": "old"}])
    selected = [UID if selector == "uid" else TITLE]
    if multiple:
        selected.append("MISSING_SELECTION")
    playbook = tmp_path / "keeper_set_selector.yml"
    playbook.write_text(
        "- hosts: my_systems\n"
        "  gather_facts: false\n"
        "  tasks:\n"
        "    - name: Update selected notes\n"
        "      keeper_set:\n"
        f"        {selector}: \"{{{{ selected_target }}}}\"\n"
        "        notes: true\n"
        "        value: \"{{ new_value }}\"\n"
        "      ignore_errors: true\n",
        encoding="utf-8")
    try:
        with server.patch(), patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError):
            status, out, err = AnsibleTestFramework(
                playbook=str(playbook), check_mode=check_mode,
                vars={"selected_target": selected, "new_value": SECRET,
                      "keeper_config": mock.MockConfig.make_base64(), "ansible_python_interpreter": sys.executable},
            ).run()
        assert status.get("failed") == 0, out + err
        assert status.get("ignored") == int(multiple), out + err
        assert status.get("changed") == int(not multiple), out + err
        assert [(call["record_uid"], call["notes"]) for call in server.calls("update_secret")] == (
            [(UID, SECRET)] if not multiple and not check_mode else [])
        assert server.records()[0]["notes"] == (SECRET if not multiple and not check_mode else "old")
        if multiple:
            assert "single UID or title" in out + err
            assert server.calls("get_secret") == []
    finally:
        server.cleanup()


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("selector", ["uid", "title"])
@pytest.mark.parametrize("wrapper", [None, list, tuple], ids=["scalar", "list", "tuple"])
def test_duplicate_full_response_uids_are_rejected_before_local_or_remote_mutation(selector, check_mode, wrapper):
    from ansible.errors import AnsibleError
    records = [SimpleNamespace(uid=UID, title=title, dict={"notes": "old"}, _update=Mock())
               for title in (TITLE, "Other record")]
    response = SecretsManagerResponse()
    response.records = records
    keeper = object.__new__(KeeperAnsible)
    keeper.client = SimpleNamespace(get_secrets=Mock(return_value=response), save=Mock())
    originals = [copy.deepcopy(record.dict) for record in records]
    selected = _wrapped_selector({selector: UID if selector == "uid" else TITLE}, wrapper)
    with patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError):
        with pytest.raises(AnsibleError, match="multiple live records"):
            keeper.set_value(KeeperFieldType.NOTES, None, SECRET, check_mode=check_mode, **selected)
    keeper.client.get_secrets.assert_called_once_with(*(([UID],) if selector == "uid" else ()), full_response=True)
    keeper.client.save.assert_not_called()
    assert [record.dict for record in records] == originals
    for record in records:
        record._update.assert_not_called()
    assert KeeperAnsible._dr_cache_allowed


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("selector", ["uid", "title"])
def test_duplicate_live_uids_are_rejected_before_acquisition_can_collapse_them(selector, check_mode):
    from ansible.errors import AnsibleError

    server = _NotesServer(
        folders=[{"uid": SHARED_UID, "name": "Shared"}],
        records=[{"uid": UID, "title": TITLE, "folder": SHARED_UID, "notes": "old-0"},
                 {"uid": UID, "title": TITLE, "folder": SHARED_UID, "notes": "old-1"}])
    keeper = object.__new__(KeeperAnsible)
    keeper.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()))
    acquired = []
    originals = []
    real_read = keeper.client.get_secrets

    def acquire(*args, **kwargs):
        response = real_read(*args, **kwargs)
        if len(response.records) == 1 and response.records[0].uid == UID:
            raw = [record for folder in response.folders for record in folder.records]
            assert len(raw) == 2 and all(record.uid == UID for record in raw)
            assert raw[0].record_key_bytes != raw[1].record_key_bytes
            assert not response.bad_records and not response.bad_folders
            assert len({record["key"] for record in server.records()}) == 2
            read.assert_called_once_with(*(([UID],) if selector == "uid" else ()), full_response=True)
            save.assert_not_called()
            assert not acquired and not originals and server.calls("update_secret") == []
            pytest.skip("The SDK exposes one record for two independent fixture entries with the same UID.")
        for record in response.records:
            acquired.append(record)
            originals.append(copy.deepcopy(record.dict))
            record._update = Mock(wraps=record._update)
        return response

    selected = {selector: UID if selector == "uid" else TITLE}
    try:
        with server.patch(), patch.object(keeper.client, "get_secrets", side_effect=acquire) as read, \
                patch.object(keeper.client, "save") as save, \
                patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError):
            with pytest.raises(AnsibleError, match="multiple live records"):
                keeper.set_value(KeeperFieldType.NOTES, None, SECRET, check_mode=check_mode, **selected)
            read.assert_called_once_with(*(([UID],) if selector == "uid" else ()), full_response=True)
            save.assert_not_called()
        assert len(acquired) == 2 and acquired[0].record_key_bytes != acquired[1].record_key_bytes
        assert [record.dict for record in acquired] == originals
        for record in acquired:
            record._update.assert_not_called()
        assert server.calls("update_secret") == []
        assert KeeperAnsible._dr_cache_allowed
    finally:
        server.cleanup()
