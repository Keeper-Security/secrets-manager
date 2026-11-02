"""
A small stand-in for the Keeper Secrets Manager server, for the folder module tests.

It replaces only SecretsManager._post_query, the method that sends a request and returns the decrypted response.
So the real SDK code still runs on both sides of it: get_folders() decrypts real encrypted folder keys and names,
create_folder() and update_folder() build real encrypted payloads, and delete_folder() parses a real per-folder
response.

Ansible runs each task in a forked worker process, so an in-memory mock cannot report back to the test, and a
change made by one task would not be seen by the next task. This server keeps the folder tree, the records, and
a log of every call in a JSON file. A rename or a delete in one task is seen by the next task, and the test can
read the call log after the playbook ends.

Folders are dictionaries: {"uid": ..., "name": ..., "parent": ...}. The parent is None for a shared folder.
A subfolder can also have "gcm": True. Older SDKs encrypt a subfolder key and name with AES-CBC; SDK 18.0.0 and
later create new subfolders with AES-GCM, and read either format. The server stores each folder in the format
that created it, so this fake server does the same.
Records are dictionaries: {"uid": ..., "title": ..., "folder": <shared folder UID>, "inner": <subfolder UID>}.
"inner" is None for a record at the top of its shared folder.
"""

import base64
import json
import os
import tempfile
from unittest.mock import patch

from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.exceptions import KeeperError

# The response code that this fake server returns for a non-empty folder when force is not set. The real
# server's code for this case is not documented in the SDKs; the modules must not depend on its exact value.
NOT_EMPTY_CODE = "folder_not_empty"


def _b64(data):
    return base64.b64encode(data).decode()


class FakeKeeperServer:

    def __init__(self, folders, records=None, delete_status=None, omit_delete_status=False,
                 missing_delete_status=None, fail=None):
        """
        folders: the folder tree. List shared folders before their subfolders, as the real server does.
        records: the records, each in a shared folder, and optionally in a subfolder of it.
        delete_status: {folder_uid: [responseCode, errorMessage]}. A delete of one of these folders returns this
            status and deletes nothing, for example ["access_denied", "User does not have permission"].
        omit_delete_status: if True, a delete returns {"folders": []} and deletes nothing.
        missing_delete_status: [responseCode, errorMessage] to return for a folder UID that does not exist. By
            default the server leaves that UID out of the response, as the SDK documents.
        fail: {path: message}. A call to this path raises KeeperError(message), for example
            {"update_folder": "access denied"}.
        """
        fd, self.path = tempfile.mkstemp(prefix="ksm_fake_server_", suffix=".json")
        os.close(fd)

        state_folders = []
        for folder in folders:
            state_folders.append({
                "uid": folder["uid"],
                "name": folder["name"],
                "parent": folder.get("parent") or None,
                "key": _b64(os.urandom(32)),
                "gcm": folder.get("gcm", False) is True and bool(folder.get("parent")),
            })
        self._save({
            "folders": state_folders,
            "records": [dict(r) for r in (records or [])],
            "delete_status": delete_status or {},
            "omit_delete_status": omit_delete_status,
            "missing_delete_status": missing_delete_status,
            "fail": fail or {},
            "calls": [],
        })

    # ---- Use in a test ----

    def patch(self):
        """A context manager that sends every SDK request to this server."""
        server = self

        def post_query(sm, path, payload):
            return server.handle(sm, path, payload)

        return patch.object(SecretsManager, "_post_query", autospec=True, side_effect=post_query)

    def calls(self, path=None):
        """The calls that the server received, in order. With a path, only the calls to that path."""
        calls = self._load()["calls"]
        if path is not None:
            calls = [c for c in calls if c["path"] == path]
        return calls

    def folders(self):
        """The folder tree as it is now: [{"uid", "name", "parent"}]."""
        return [{"uid": f["uid"], "name": f["name"], "parent": f["parent"]} for f in self._load()["folders"]]

    def folder(self, uid):
        return next((f for f in self.folders() if f["uid"] == uid), None)

    def records(self):
        return self._load()["records"]

    def cleanup(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    # ---- The server ----

    def handle(self, sm, path, payload):
        state = self._load()
        call = {"path": path}
        state["calls"].append(call)

        try:
            if path in state["fail"]:
                # Record what the request was about, so a test can check a request that the server refused.
                for attr, key in (("folderUid", "folder_uid"), ("sharedFolderUid", "shared_folder_uid"),
                                  ("folderUids", "folder_uids"), ("forceDeletion", "force")):
                    value = getattr(payload, attr, None)
                    if value is not None:
                        call[key] = list(value) if isinstance(value, (list, tuple)) else value
                raise KeeperError(state["fail"][path])

            app_key = base64.b64decode(sm.config.get(ConfigKeys.KEY_APP_KEY))

            if path == "get_folders":
                return self._json({"folders": self._folder_list(state, app_key)})

            if path == "get_secret":
                return self._json(self._secrets(state, app_key))

            if path == "create_folder":
                shared = self._find(state, payload.sharedFolderUid)
                if shared is None:
                    raise KeeperError("shared folder not found")
                # An AES-GCM wrapped 32-byte key is 60 bytes (12 nonce + 32 + 16 tag). AES-CBC makes 64.
                wrapped_key = CryptoUtils.url_safe_str_to_bytes(payload.sharedFolderKey)
                gcm = len(wrapped_key) == 60
                if gcm:
                    folder_key = CryptoUtils.decrypt_aes(wrapped_key, base64.b64decode(shared["key"]))
                else:
                    folder_key = CryptoUtils.decrypt_aes_cbc(wrapped_key, base64.b64decode(shared["key"]))
                name = self._decrypt_name(payload.data, folder_key, gcm)
                call.update(folder_uid=payload.folderUid, shared_folder_uid=payload.sharedFolderUid,
                            parent_uid=payload.parentUid, folder_name=name, gcm=gcm)
                state["folders"].append({
                    "uid": payload.folderUid,
                    "name": name,
                    "parent": payload.parentUid or payload.sharedFolderUid,
                    "key": _b64(folder_key),
                    "gcm": gcm,
                })
                return self._json({})

            if path == "update_folder":
                folder = self._find(state, payload.folderUid)
                if folder is None:
                    raise KeeperError("folder not found")
                # The SDK must encrypt the new name in the format of the folder. If it does not, this raises,
                # and the test fails, as it would against the real vault.
                name = self._decrypt_name(payload.data, base64.b64decode(folder["key"]), folder.get("gcm", False))
                call.update(folder_uid=payload.folderUid, folder_name=name)
                folder["name"] = name
                return self._json({})

            if path == "delete_folder":
                call.update(folder_uids=list(payload.folderUids), force=payload.forceDeletion)
                return self._json({"folders": self._delete(state, list(payload.folderUids), payload.forceDeletion)})

            raise AssertionError("The fake Keeper server does not handle the path {}".format(path))
        finally:
            self._save(state)

    def _delete(self, state, folder_uids, force):
        if state["omit_delete_status"] is True:
            return []

        statuses = []
        for uid in folder_uids:
            if uid in state["delete_status"]:
                code, message = state["delete_status"][uid]
                statuses.append({"folderUid": uid, "responseCode": code, "errorMessage": message})
                continue

            folder = self._find(state, uid)
            if folder is None:
                if state["missing_delete_status"] is not None:
                    code, message = state["missing_delete_status"]
                    statuses.append({"folderUid": uid, "responseCode": code, "errorMessage": message})
                continue

            subtree = self._subtree(state, uid)
            has_records = any(r.get("inner") in subtree or (not r.get("inner") and r["folder"] in subtree)
                              for r in state["records"])
            if force is not True and (len(subtree) > 1 or has_records):
                statuses.append({"folderUid": uid, "responseCode": NOT_EMPTY_CODE,
                                 "errorMessage": "The folder is not empty"})
                continue

            state["folders"] = [f for f in state["folders"] if f["uid"] not in subtree]
            state["records"] = [r for r in state["records"]
                                if r.get("inner") not in subtree and r["folder"] not in subtree]
            statuses.append({"folderUid": uid, "responseCode": "ok"})
        return statuses

    # ---- Encoding ----

    @staticmethod
    def _json(data):
        return json.dumps(data).encode()

    @staticmethod
    def _decrypt_name(data, key, gcm=False):
        data = CryptoUtils.url_safe_str_to_bytes(data)
        plain = CryptoUtils.decrypt_aes(data, key) if gcm else CryptoUtils.decrypt_aes_cbc(data, key)
        return json.loads(plain.decode())["name"]

    @staticmethod
    def _find(state, uid):
        return next((f for f in state["folders"] if f["uid"] == uid), None)

    @staticmethod
    def _subtree(state, uid):
        subtree = {uid}
        grew = True
        while grew:
            grew = False
            for f in state["folders"]:
                if f["parent"] in subtree and f["uid"] not in subtree:
                    subtree.add(f["uid"])
                    grew = True
        return subtree

    def _shared_folder_of(self, state, folder):
        seen = set()
        while folder is not None and folder["parent"] and folder["uid"] not in seen:
            seen.add(folder["uid"])
            folder = self._find(state, folder["parent"])
        return folder

    def _folder_list(self, state, app_key):
        # The format of the get_folders response. A shared folder key is encrypted with the application key
        # (AES-GCM), and its name with its own key (AES-CBC). Every subfolder key, at any depth, is encrypted with
        # the key of its shared folder, and the subfolder name with its own key: AES-CBC for both, or AES-GCM for
        # both if the subfolder was created in the GCM format.
        result = []
        for folder in state["folders"]:
            key = base64.b64decode(folder["key"])
            name = json.dumps({"name": folder["name"]}).encode()
            if not folder["parent"]:
                result.append({"folderUid": folder["uid"], "folderKey": _b64(CryptoUtils.encrypt_aes(key, app_key)),
                               "data": _b64(CryptoUtils.encrypt_aes_cbc(name, key))})
                continue

            shared_key = base64.b64decode(self._shared_folder_of(state, folder)["key"])
            if folder.get("gcm", False):
                wrapped_key, data = CryptoUtils.encrypt_aes(key, shared_key), CryptoUtils.encrypt_aes(name, key)
            else:
                wrapped_key, data = CryptoUtils.encrypt_aes_cbc(key, shared_key), CryptoUtils.encrypt_aes_cbc(name, key)
            result.append({"folderUid": folder["uid"], "parent": folder["parent"], "folderKey": _b64(wrapped_key),
                           "data": _b64(data)})
        return result

    @staticmethod
    def _secrets(state, app_key):
        # The format of the get_secret response, with each record in its shared folder. As in the SDK's own mock,
        # the application key is also used as the folder key and the record key.
        shared_folders = {}
        for folder in state["folders"]:
            if not folder["parent"]:
                shared_folders[folder["uid"]] = {
                    "folderUid": folder["uid"],
                    "folderKey": _b64(CryptoUtils.encrypt_aes(app_key, app_key)),
                    "records": [],
                }
        for record in state["records"]:
            data = {"type": "login", "title": record["title"], "fields": [], "custom": [], "notes": ""}
            item = {
                "recordUid": record["uid"],
                "recordKey": _b64(CryptoUtils.encrypt_aes(app_key, app_key)),
                "data": _b64(CryptoUtils.encrypt_aes(json.dumps(data).encode(), app_key)),
                "isEditable": True,
                "files": None,
            }
            if record.get("inner"):
                item["innerFolderUid"] = record["inner"]
            if record["folder"] in shared_folders:
                shared_folders[record["folder"]]["records"].append(item)
        return {"folders": list(shared_folders.values()), "records": []}

    # ---- State file ----

    def _load(self):
        with open(self.path) as fh:
            return json.load(fh)

    def _save(self, state):
        with open(self.path, "w") as fh:
            json.dump(state, fh)
