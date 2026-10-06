import base64
import json
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFieldType
from .ansible_test_framework import AnsibleTestFramework
from .folder_fake_server import FakeKeeperServer, _b64

UID = "STALE_CACHE_RECORD_UID"
SHARED_UID = "SHARED_FOLDER_UID"


class _NotesServer(FakeKeeperServer):
    """A fake server that keeps the notes of each record and applies update_secret to them."""

    @staticmethod
    def _secrets(state, app_key):
        records = []
        for record in state["records"]:
            data = {"type": "login", "title": record["title"], "fields": [], "custom": [],
                    "notes": record.get("notes", "")}
            records.append({
                "recordUid": record["uid"],
                "recordKey": _b64(CryptoUtils.encrypt_aes(app_key, app_key)),
                "data": _b64(CryptoUtils.encrypt_aes(json.dumps(data).encode(), app_key)),
                "isEditable": True, "files": None,
            })
        return {"folders": [{"folderUid": SHARED_UID, "folderKey": _b64(CryptoUtils.encrypt_aes(app_key, app_key)),
                             "records": records}], "records": []}

    def handle(self, sm, path, payload):
        if path != "update_secret":
            return super().handle(sm, path, payload)
        state = self._load()
        app_key = base64.b64decode(sm.config.get(ConfigKeys.KEY_APP_KEY))
        data = json.loads(CryptoUtils.decrypt_aes(base64.b64decode(payload.data), app_key).decode())
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
