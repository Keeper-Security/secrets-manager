import base64
import json
import logging
import os
import re
import unittest
from unittest import mock

from cryptography.exceptions import InvalidTag
from requests import Response as RequestResponse

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.dtos import KeeperFileUpload, KeeperFolder, RecordCreate
from keeper_secrets_manager_core.dto.payload import CreateOptions, KSMHttpResponse
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.helpers import get_drive_folder_name
from keeper_secrets_manager_core.keeper_globals import keeper_public_keys, logger_name
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.utils import base64_to_bytes, pad_aes_gcm, url_safe_str_to_bytes

DRIVE_HINT = "shared directly to the application and hold at least one record"
CREATE_REFUSED_IN_DRIVE = r"cannot create a folder in an NSF \(Keeper Drive\) folder"
UPDATE_REFUSED_IN_DRIVE = r"cannot update an NSF \(Keeper Drive\) folder"


def listed_subfolders(*folder_uids, parent="sharedFolderUid______"):
    """A get_folders response that lists each folder as a subfolder of a shared folder.

    delete_folder() reads only the UID and the parent of each entry.
    """
    return {"folders": [{"folderUid": x, "parent": parent} for x in folder_uids]}


def b64(data):
    return base64.b64encode(data).decode()


def new_uid():
    return CryptoUtils.bytes_to_url_safe_str(os.urandom(16))


def encrypted_name(name, folder_key, use_gcm=True):
    data = json.dumps({"name": name}).encode()
    if use_gcm:
        return b64(CryptoUtils.encrypt_aes(data, folder_key))
    return b64(CryptoUtils.encrypt_aes_cbc(data, folder_key))


def padded_drive_name(name, folder_key, size=255):
    """An NSF (Keeper Drive) folder name as the server sends it: AES-GCM, zero-padded to its column size."""
    blob = CryptoUtils.encrypt_aes(json.dumps({"name": name}).encode(), folder_key)
    return b64(blob + b'\x00' * (size - len(blob)))


class FakeServer:
    """Answers /sm/v1 calls with fixed responses and keeps each decrypted request payload.

    errors maps a path to (HTTP status, JSON body) for an error response, which the server sends unencrypted.
    get_secret applies requestedFolders as the server does: it always lists a legacy shared folder (an entry
    without data), it lists an NSF folder only when the filter names it, and it fails on an empty UID.
    """

    def __init__(self, responses, errors=None):
        self.responses = responses
        self.errors = errors or {}
        self.requests = []

    @staticmethod
    def error_response(status, body):
        res = RequestResponse()
        res._content = json.dumps(body).encode()
        res.encoding = "utf-8"
        res.status_code = status
        res.reason = "Error"
        return KSMHttpResponse(res.status_code, res.content, res)

    def respond(self, path, payload):
        """Return the response body for a request, or an error response."""
        if path in self.errors:
            return self.error_response(*self.errors[path])

        body = self.responses.get(path, {})
        requested = payload.get("requestedFolders")
        if path == "get_secret" and requested is not None:
            if not all(requested):
                return self.error_response(500, {"error": "unknown", "message": "An empty folder UID failed"})
            if isinstance(body, dict):
                body = dict(body, folders=[f for f in body.get("folders") or []
                                           if not f.get("data") or f.get("folderUid") in requested])
        return body

    def post_function(self, url, transmission_key, encrypted_payload, verify_ssl_certs=True, proxy_url=None):
        path = url.rsplit('/', 1)[-1]
        payload = json.loads(CryptoUtils.decrypt_aes(encrypted_payload.encrypted_payload, transmission_key.key))
        self.requests.append((path, payload))

        body = self.respond(path, payload)
        if isinstance(body, KSMHttpResponse):
            return body

        content = CryptoUtils.encrypt_aes(json.dumps(body).encode(), transmission_key.key)
        res = RequestResponse()
        res._content = content
        res.status_code = 200
        res.reason = "OK"
        return KSMHttpResponse(res.status_code, res.content, res)

    def paths(self):
        return [path for path, _ in self.requests]

    def payload(self, path):
        return next(payload for (x, payload) in reversed(self.requests) if x == path)


class BindingFakeServer(FakeServer):
    """FakeServer with the bind gate of the server, for a client with a new one-time token.

    The server answers the first request, which sends the public key, with the application key. It finishes
    the binding only on a later read without the public key, and it refuses each write until then.
    """

    def __init__(self, responses, encrypted_app_key, owner_public_key):
        super().__init__(responses)
        self.binding = {"encryptedAppKey": encrypted_app_key, "appOwnerPublicKey": owner_public_key}
        self.bound = False

    def respond(self, path, payload):
        if not self.bound:
            if payload.get("publicKey"):
                body = super().respond(path, payload)
                return dict(body, **self.binding) if isinstance(body, dict) else body
            if path not in ("get_folders", "get_secret"):
                return self.error_response(403, {"error": "access_denied",
                                                 "message": "Unable to validate Keeper application access"})
            self.bound = True
        return super().respond(path, payload)


class KeeperDriveTest(unittest.TestCase):
    """NSF folders shared directly to the application, next to legacy shared folders.

    The server sends an NSF folder with its folder key wrapped by the application key and
    its name encrypted with the folder key in AES-GCM. get_folders() does not list NSF folders,
    and get_secrets() lists each one that holds at least one record.
    """

    def setUp(self):
        self.secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))
        self.app_key = base64_to_bytes(self.secrets_manager.config.get(ConfigKeys.KEY_APP_KEY))

        self.drive_uid, self.drive_key = new_uid(), os.urandom(32)
        self.legacy_uid, self.legacy_key = new_uid(), os.urandom(32)

    def serve(self, responses, errors=None):
        server = FakeServer(responses, errors)
        self.secrets_manager.post_function = server.post_function
        return server

    def drive_secret_response(self):
        """A get_secret response with one NSF folder that holds one record."""
        return {"get_secret": {"folders": [self.secret_folder(self.drive_uid, self.drive_key, name="Drive")]}}

    def enable_sdk_log(self):
        """The SDK turns off its logger when no log_level is set; turn it on for this test only."""
        logger = logging.getLogger(logger_name)
        self.addCleanup(setattr, logger, "disabled", logger.disabled)
        logger.disabled = False

    def get_drive_record(self):
        """Return a record from an NSF folder, and its record key as the server stores it."""
        folder = self.secret_folder(self.drive_uid, self.drive_key, name="Drive")
        self.serve({"get_secret": {"folders": [folder]}})
        record = self.secrets_manager.get_secrets()[0]
        record_key = CryptoUtils.decrypt_aes(base64.b64decode(folder["records"][0]["recordKey"]), self.drive_key)
        return record, record_key

    def secret_folder(self, folder_uid, folder_key, name=None):
        """A folder with one record as get_secret returns it. Only an NSF folder has a name."""
        record_key = os.urandom(32)
        record_data = json.dumps({"title": "Existing", "type": "login", "fields": [], "custom": []}).encode()
        folder = {
            "folderUid": folder_uid,
            "folderKey": b64(CryptoUtils.encrypt_aes(folder_key, self.app_key)),
            "isEditable": True,
            "records": [{
                "recordUid": new_uid(),
                "recordKey": b64(CryptoUtils.encrypt_aes(record_key, folder_key)),
                "data": b64(CryptoUtils.encrypt_aes(record_data, record_key)),
                "revision": 1,
                "isEditable": True,
            }],
        }
        if name is not None:
            folder["data"] = encrypted_name(name, folder_key)
        return folder

    def top_folder(self, folder_uid, folder_key, name, use_gcm=True):
        """A top-level folder as get_folders returns it."""
        return {
            "folderUid": folder_uid,
            "folderKey": b64(CryptoUtils.encrypt_aes(folder_key, self.app_key)),
            "data": encrypted_name(name, folder_key, use_gcm=use_gcm),
            "isEditable": True,
        }

    def legacy_top_folder(self):
        """A legacy shared folder as get_folders returns it, with its name in AES-CBC."""
        return self.top_folder(self.legacy_uid, self.legacy_key, "Legacy", use_gcm=False)

    def assert_drive_record_payload(self, payload, folder_key, record_create):
        record_key_encrypted = base64.b64decode(payload["recordKey"])
        self.assertEqual(60, len(record_key_encrypted),
                         "recordKey must be the record key wrapped with the folder key (AES-GCM)")
        record_key = CryptoUtils.decrypt_aes(record_key_encrypted, folder_key)

        data = base64.b64decode(payload["data"])
        self.assertGreaterEqual(len(data), 412, "the server rejects NSF record data under 412 bytes")
        record_json = CryptoUtils.decrypt_aes(data, record_key)
        self.assertEqual(json.loads(record_create.to_json()), json.loads(record_json))
        self.assertIsNone(payload["folderKey"], "folderKey is a legacy field")

    def assert_legacy_folder_payload(self, payload, shared_folder_key, name):
        """A subfolder of a legacy shared folder has an AES-CBC key and AES-CBC folder data, as in SDK 17.3.0.

        Commander and SDK 17.3.0 unwrap the key of such a subfolder with AES-CBC.
        """
        wrapped_key = url_safe_str_to_bytes(payload["sharedFolderKey"])
        self.assertEqual(64, len(wrapped_key), "an AES-CBC key is an IV (16 bytes) and the padded key (48 bytes)")
        with self.assertRaises(InvalidTag):
            CryptoUtils.decrypt_aes(wrapped_key, shared_folder_key)
        folder_key = CryptoUtils.decrypt_aes_cbc(wrapped_key, shared_folder_key)
        self.assertEqual(32, len(folder_key))

        folder_data = url_safe_str_to_bytes(payload["data"])
        with self.assertRaises(InvalidTag):
            CryptoUtils.decrypt_aes(folder_data, folder_key)
        self.assertEqual(name, json.loads(CryptoUtils.decrypt_aes_cbc(folder_data, folder_key))["name"])

    def legacy_subfolder(self, folder_uid, folder_key, name, use_gcm=False):
        """A subfolder of the legacy shared folder as get_folders returns it.

        Its key is wrapped with the shared folder key.
        """
        wrap = CryptoUtils.encrypt_aes if use_gcm else CryptoUtils.encrypt_aes_cbc
        return {
            "folderUid": folder_uid,
            "parent": self.legacy_uid,
            "folderKey": b64(wrap(folder_key, self.legacy_key)),
            "data": encrypted_name(name, folder_key, use_gcm=use_gcm),
        }

    def test_get_folders_reads_top_level_aes_gcm_folder_name(self):
        """get_folders() reads a top-level AES-GCM folder name and sets use_gcm.

        get_folders() cannot tell an NSF folder from a legacy one, so is_drive stays False.
        """
        self.serve({"get_folders": {"folders": [
            self.legacy_top_folder(),
            self.top_folder(self.drive_uid, self.drive_key, "Drive"),
        ]}})

        folders = {f.folder_uid: f for f in self.secrets_manager.get_folders()}

        drive = folders[self.drive_uid]
        self.assertEqual(("Drive", True, False), (drive.name, drive.use_gcm, drive.is_drive))
        self.assertEqual(self.drive_key, drive.folder_key)
        legacy = folders[self.legacy_uid]
        self.assertEqual(("Legacy", False, False), (legacy.name, legacy.use_gcm, legacy.is_drive))

    def test_get_folders_subfolders_are_not_drive_folders(self):
        """Legacy subfolders keep the key-size dispatch and are never NSF folders."""
        cbc_uid, cbc_key = new_uid(), os.urandom(32)
        gcm_uid, gcm_key = new_uid(), os.urandom(32)
        self.serve({"get_folders": {"folders": [
            self.legacy_top_folder(),
            {
                "folderUid": cbc_uid,
                "parent": self.legacy_uid,
                "folderKey": b64(CryptoUtils.encrypt_aes_cbc(cbc_key, self.legacy_key)),
                "data": encrypted_name("CBC sub", cbc_key, use_gcm=False),
            },
            {
                "folderUid": gcm_uid,
                "parent": self.legacy_uid,
                "folderKey": b64(CryptoUtils.encrypt_aes(gcm_key, self.legacy_key)),
                "data": encrypted_name("GCM sub", gcm_key),
            },
        ]}})

        folders = {f.folder_uid: f for f in self.secrets_manager.get_folders()}

        cbc, gcm = folders[cbc_uid], folders[gcm_uid]
        self.assertEqual(("CBC sub", False, False), (cbc.name, cbc.use_gcm, cbc.is_drive))
        self.assertEqual(("GCM sub", True, False), (gcm.name, gcm.use_gcm, gcm.is_drive))

    def test_get_secrets_marks_drive_folders(self):
        """A get_secrets() folder entry with data is an NSF folder; a legacy entry has data null."""
        drive = self.secret_folder(self.drive_uid, self.drive_key, name="Drive")
        legacy = self.secret_folder(self.legacy_uid, self.legacy_key)
        legacy["data"] = None
        self.serve({"get_secret": {"folders": [drive, legacy]}})

        response = self.secrets_manager.get_secrets(full_response=True)

        folders = {f.uid: f for f in response.folders}
        self.assertEqual((True, "Drive"), (folders[self.drive_uid].is_drive, folders[self.drive_uid].name))
        self.assertEqual((False, ""), (folders[self.legacy_uid].is_drive, folders[self.legacy_uid].name))
        self.assertEqual({self.drive_uid}, response.drive_folder_uids)
        records = {r.uid: r for r in response.records}
        self.assertTrue(records[drive["records"][0]["recordUid"]].is_drive)
        self.assertFalse(records[legacy["records"][0]["recordUid"]].is_drive)
        self.assertTrue(folders[self.drive_uid].records[0].is_drive)

    def test_get_secrets_folder_with_unreadable_name_is_drive_folder(self):
        """A folder entry with data is an NSF folder also when its name does not decrypt."""
        folder = self.secret_folder(self.drive_uid, self.drive_key)
        folder["data"] = encrypted_name("Other key", os.urandom(32))
        self.serve({"get_secret": {"folders": [folder]}})

        response = self.secrets_manager.get_secrets(full_response=True)

        self.assertEqual((True, ""), (response.folders[0].is_drive, response.folders[0].name))
        self.assertEqual({self.drive_uid}, response.drive_folder_uids)
        self.assertEqual(1, len(response.records))
        self.assertTrue(response.records[0].is_drive)
        self.assertEqual(0, len(response.bad_folders))

    def test_get_secrets_direct_record_share_is_not_drive(self):
        """A record that is shared directly to the application, not through an NSF folder, is not an NSF record."""
        record_key = os.urandom(32)
        direct = {
            "recordUid": new_uid(),
            "recordKey": b64(CryptoUtils.encrypt_aes(record_key, self.app_key)),
            "data": b64(CryptoUtils.encrypt_aes(json.dumps({"title": "Direct", "type": "login", "fields": []}).encode(),
                                                record_key)),
            "revision": 1,
        }
        self.serve({"get_secret": {"records": [direct],
                                   "folders": [self.secret_folder(self.drive_uid, self.drive_key, name="Drive")]}})

        response = self.secrets_manager.get_secrets(full_response=True)

        records = {r.uid: r for r in response.records}
        self.assertEqual(2, len(records))
        self.assertFalse(records[direct["recordUid"]].is_drive)
        self.assertEqual({self.drive_uid}, response.drive_folder_uids)

    def test_get_secrets_reads_zero_padded_drive_folder_name(self):
        """The server can send an NSF folder name zero-padded to 255 bytes; the name is still read."""
        folder = self.secret_folder(self.drive_uid, self.drive_key)
        folder["data"] = padded_drive_name("Padded", self.drive_key)
        self.serve({"get_secret": {"folders": [folder]}})

        response = self.secrets_manager.get_secrets(full_response=True)

        self.assertEqual((True, "Padded"), (response.folders[0].is_drive, response.folders[0].name))

    def test_get_folders_reads_zero_padded_drive_folder_name(self):
        self.serve({"get_folders": {"folders": [{
            "folderUid": self.drive_uid,
            "folderKey": b64(CryptoUtils.encrypt_aes(self.drive_key, self.app_key)),
            "data": padded_drive_name("Padded", self.drive_key),
            "isEditable": True,
        }]}})

        folders = self.secrets_manager.get_folders()

        self.assertEqual(1, len(folders), "a zero-padded NSF folder name must not make get_folders skip the folder")
        self.assertEqual(("Padded", True, False), (folders[0].name, folders[0].use_gcm, folders[0].is_drive))

    def test_create_folder_in_top_level_aes_gcm_folder_sends_the_17_3_0_requests(self):
        """create_folder() reads only get_folders(), as in 17.3.0, also for a top-level AES-GCM folder."""
        server = self.serve({
            "get_folders": {"folders": [self.top_folder(self.drive_uid, self.drive_key, "Drive")]},
            "get_secret": {"folders": [self.secret_folder(self.drive_uid, self.drive_key, name="Drive")]},
        })

        self.secrets_manager.create_folder(CreateOptions(self.drive_uid, None), "Child")

        self.assertEqual(["get_folders", "create_folder"], server.paths())
        self.assert_legacy_folder_payload(server.payload("create_folder"), self.drive_key, "Child")

    def test_write_to_top_level_aes_gcm_legacy_folder_stays_legacy(self):
        """A legacy shared folder with an AES-GCM name gets the legacy payload without a get_secrets() call."""
        legacy = self.secret_folder(self.legacy_uid, self.legacy_key)
        server = self.serve({
            "get_folders": {"folders": [self.top_folder(self.legacy_uid, self.legacy_key, "Legacy GCM")]},
            "get_secret": {"folders": [legacy]},
        })

        self.secrets_manager.create_folder(CreateOptions(self.legacy_uid, None), "Child")

        self.assertEqual(["get_folders", "create_folder"], server.paths())
        payload = server.payload("create_folder")
        self.assertEqual(self.legacy_uid, payload["sharedFolderUid"])
        self.assertIsNone(payload["parentUid"])
        # The AES-GCM name of the parent must not make the new subfolder an AES-GCM subfolder
        self.assert_legacy_folder_payload(payload, self.legacy_key, "Child")

    def test_create_secret_in_drive_folder(self):
        server = self.serve({"get_secret": {"folders": [
            self.secret_folder(self.drive_uid, self.drive_key, name="Drive"),
        ]}})
        record = RecordCreate('login', 'New Drive record')

        self.secrets_manager.create_secret(self.drive_uid, record)

        self.assertEqual(["get_secret", "create_secret"], server.paths())
        self.assertEqual([self.drive_uid], server.payload("get_secret")["requestedFolders"])
        self.assertIsNone(server.payload("get_secret")["requestedRecords"])
        payload = server.payload("create_secret")
        self.assertEqual(self.drive_uid, payload["folderUid"])
        self.assertIsNone(payload["subFolderUid"])
        self.assert_drive_record_payload(payload, self.drive_key, record)

    def test_create_secret_unknown_folder_raises_with_drive_hint(self):
        self.serve({"get_secret": {"folders": []}})

        with self.assertRaisesRegex(KeeperError, DRIVE_HINT):
            self.secrets_manager.create_secret(new_uid(), RecordCreate('login', 'x'))

    def test_create_secret_in_legacy_folder_is_unchanged(self):
        server = self.serve({"get_secret": {"folders": [self.secret_folder(self.legacy_uid, self.legacy_key)]}})
        record = RecordCreate('login', 'New legacy record')

        self.secrets_manager.create_secret(self.legacy_uid, record)

        payload = server.payload("create_secret")
        self.assertEqual(125, len(base64.b64decode(payload["recordKey"])),
                         "a legacy recordKey is wrapped with the owner public key")
        record_key = CryptoUtils.decrypt_aes(base64.b64decode(payload["folderKey"]), self.legacy_key)
        record_json = CryptoUtils.decrypt_aes(base64.b64decode(payload["data"]), record_key)
        self.assertEqual(record.to_json().encode(), record_json, "legacy record data is not padded")

    def test_create_secret_with_options_finds_drive_folder_in_get_secrets(self):
        server = self.serve({
            "get_folders": {"folders": [self.legacy_top_folder()]},
            "get_secret": {"folders": [self.secret_folder(self.drive_uid, self.drive_key, name="Drive")]},
        })
        record = RecordCreate('login', 'New Drive record')

        self.secrets_manager.create_secret_with_options(CreateOptions(self.drive_uid, None), record)

        self.assertEqual(["get_folders", "get_secret", "create_secret"], server.paths())
        self.assertEqual([self.drive_uid], server.payload("get_secret")["requestedFolders"],
                         "the lookup asks only for the target folder, with no empty UID")
        self.assertIsNone(server.payload("get_secret")["requestedRecords"])
        self.assert_drive_record_payload(server.payload("create_secret"), self.drive_key, record)

    def test_write_lookup_with_custom_post_function_is_not_filtered(self):
        """A custom post function such as KSMCache keeps each get_secret response, so it gets the full response."""
        server = self.serve(self.drive_secret_response())
        self.secrets_manager.custom_post_function = server.post_function

        self.secrets_manager.create_secret_with_options(CreateOptions(self.drive_uid, None), RecordCreate('login', 'x'))

        self.assertIsNone(server.payload("get_secret")["requestedFolders"])

    def test_write_lookup_filter_has_no_repeated_uid(self):
        server = self.serve(self.drive_secret_response())

        self.secrets_manager.create_secret_with_options(CreateOptions(self.drive_uid, self.drive_uid),
                                                        RecordCreate('login', 'x'))

        self.assertEqual([self.drive_uid], server.payload("get_secret")["requestedFolders"])

    def test_create_secret_with_options_in_legacy_folder_skips_get_secrets(self):
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder()]}})

        self.secrets_manager.create_secret_with_options(CreateOptions(self.legacy_uid, None),
                                                        RecordCreate('login', 'New legacy record'))

        self.assertEqual(["get_folders", "create_secret"], server.paths())
        self.assertEqual(125, len(base64.b64decode(server.payload("create_secret")["recordKey"])))

    def test_create_secret_with_options_uses_key_of_target_drive_folder(self):
        """With subfolder_uid, the record key is wrapped with the key of that NSF folder."""
        target_uid, target_key = new_uid(), os.urandom(32)
        server = self.serve({"get_secret": {"folders": [
            self.secret_folder(self.drive_uid, self.drive_key, name="Drive"),
            self.secret_folder(target_uid, target_key, name="Target"),
        ]}})
        record = RecordCreate('login', 'In target')

        self.secrets_manager.create_secret_with_options(CreateOptions(self.drive_uid, target_uid), record)

        self.assertEqual([self.drive_uid, target_uid], server.payload("get_secret")["requestedFolders"])
        payload = server.payload("create_secret")
        self.assertEqual(target_uid, payload["subFolderUid"])
        self.assert_drive_record_payload(payload, target_key, record)

    def test_create_secret_with_options_takes_the_kind_from_the_target_folder(self):
        """The target NSF folder decides the payload, also when get_secrets() does not list folder_uid."""
        target_uid, target_key = new_uid(), os.urandom(32)
        server = self.serve({"get_secret": {"folders": [self.secret_folder(target_uid, target_key, name="Target")]}})
        record = RecordCreate('login', 'In target')

        self.secrets_manager.create_secret_with_options(CreateOptions(self.drive_uid, target_uid), record)

        payload = server.payload("create_secret")
        self.assertEqual((self.drive_uid, target_uid), (payload["folderUid"], payload["subFolderUid"]))
        self.assert_drive_record_payload(payload, target_key, record)

    def test_create_secret_with_options_in_legacy_subfolder_is_unchanged(self):
        sub_uid, sub_key = new_uid(), os.urandom(32)
        server = self.serve({"get_folders": {"folders": [
            self.legacy_top_folder(),
            {
                "folderUid": sub_uid,
                "parent": self.legacy_uid,
                "folderKey": b64(CryptoUtils.encrypt_aes(sub_key, self.legacy_key)),
                "data": encrypted_name("Sub", sub_key),
            },
        ]}})

        self.secrets_manager.create_secret_with_options(CreateOptions(self.legacy_uid, sub_uid),
                                                        RecordCreate('login', 'In legacy subfolder'))

        self.assertEqual(["get_folders", "create_secret"], server.paths())
        payload = server.payload("create_secret")
        self.assertEqual((self.legacy_uid, sub_uid), (payload["folderUid"], payload["subFolderUid"]))
        record_key = CryptoUtils.decrypt_aes(base64.b64decode(payload["folderKey"]), self.legacy_key)
        self.assertEqual(32, len(record_key), "a legacy record key is wrapped with the shared folder key")

    def test_create_secret_with_options_unknown_drive_target_raises(self):
        server = self.serve({"get_secret": {"folders": [
            self.secret_folder(self.drive_uid, self.drive_key, name="Drive"),
        ]}})

        with self.assertRaisesRegex(KeeperError, DRIVE_HINT):
            self.secrets_manager.create_secret_with_options(CreateOptions(self.drive_uid, new_uid()),
                                                            RecordCreate('login', 'x'))
        self.assertNotIn("create_secret", server.paths())

    def serve_fresh_client(self, responses):
        """Give the test a client with a new one-time token (a clientKey and no app key) and a binding server."""
        config = MockConfig.make_config(skip_list=[ConfigKeys.KEY_APP_KEY.value, ConfigKeys.KEY_OWNER_PUBLIC_KEY.value])
        self.secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(config))
        # The SDK removes clientKey from a config that has a clientId, so set it after the constructor
        client_key = os.urandom(32)
        self.secrets_manager.config.set(ConfigKeys.KEY_CLIENT_KEY, CryptoUtils.bytes_to_url_safe_str(client_key))
        self.app_key = os.urandom(32)
        server = BindingFakeServer(responses(),
                                   CryptoUtils.bytes_to_url_safe_str(CryptoUtils.encrypt_aes(self.app_key, client_key)),
                                   keeper_public_keys["7"])
        self.secrets_manager.post_function = server.post_function
        return server

    def assert_bound(self, server):
        payloads = [payload for _, payload in server.requests]
        self.assertIsNotNone(payloads[0]["publicKey"], "the first request sends the public key")
        self.assertTrue(all(payload.get("publicKey") is None for payload in payloads[1:]))
        self.assertTrue(server.bound, "a read without the public key finishes the binding")
        self.assertEqual(self.app_key, base64_to_bytes(self.secrets_manager.config.get(ConfigKeys.KEY_APP_KEY)))
        self.assertIsNone(self.secrets_manager.config.get(ConfigKeys.KEY_CLIENT_KEY))

    def test_fresh_client_first_call_creates_secret_in_drive_folder(self):
        """A client with a new one-time token binds in get_folders(), then finds the NSF folder in get_secrets()."""
        server = self.serve_fresh_client(lambda: {
            "get_folders": {"folders": []},
            "get_secret": {"folders": [self.secret_folder(self.drive_uid, self.drive_key, name="Drive")]},
        })
        record = RecordCreate('login', 'First call')

        self.secrets_manager.create_secret_with_options(CreateOptions(self.drive_uid, None), record)

        self.assertEqual(["get_folders", "get_folders", "get_secret", "create_secret"], server.paths())
        self.assert_bound(server)
        self.assertEqual([self.drive_uid], server.payload("get_secret")["requestedFolders"])
        self.assert_drive_record_payload(server.payload("create_secret"), self.drive_key, record)

    def test_fresh_client_first_call_creates_secret_in_legacy_folder(self):
        """get_folders() finishes the binding of a new client, so the next write passes the bind gate of the server."""
        server = self.serve_fresh_client(lambda: {"get_folders": {"folders": [self.legacy_top_folder()]}})

        self.secrets_manager.create_secret_with_options(CreateOptions(self.legacy_uid, None),
                                                        RecordCreate('login', 'First call'))

        self.assertEqual(["get_folders", "get_folders", "create_secret"], server.paths())
        self.assert_bound(server)

    def test_create_folder_in_drive_folder_that_only_get_secrets_lists_is_refused(self):
        server = self.serve({
            "get_folders": {"folders": [self.legacy_top_folder()]},
            "get_secret": {"folders": [self.secret_folder(self.drive_uid, self.drive_key, name="Drive")]},
        })

        with self.assertRaisesRegex(KeeperError, f"folder key for {self.drive_uid} not found$"):
            self.secrets_manager.create_folder(CreateOptions(self.drive_uid, None), "New Drive folder")
        self.assertEqual(["get_folders"], server.paths())

    def test_create_folder_under_drive_subfolder_is_refused(self):
        parent_uid, parent_key = new_uid(), os.urandom(32)
        server = self.serve({"get_secret": {"folders": [
            self.secret_folder(self.drive_uid, self.drive_key, name="Drive"),
            self.secret_folder(parent_uid, parent_key, name="Parent"),
        ]}})

        with self.assertRaisesRegex(KeeperError, f"folder key for {self.drive_uid} not found$"):
            self.secrets_manager.create_folder(CreateOptions(self.drive_uid, parent_uid), "Child")
        self.assertEqual(["get_folders"], server.paths())

    def test_create_folder_in_legacy_folder_is_unchanged(self):
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder()]}})

        self.secrets_manager.create_folder(CreateOptions(self.legacy_uid, None), "Legacy child")

        self.assertEqual(["get_folders", "create_folder"], server.paths())
        payload = server.payload("create_folder")
        self.assertEqual(self.legacy_uid, payload["sharedFolderUid"])
        self.assertIsNone(payload["parentUid"])
        self.assert_legacy_folder_payload(payload, self.legacy_key, "Legacy child")

    def test_create_folder_in_legacy_subfolder_wraps_the_key_with_the_shared_folder_key_in_aes_cbc(self):
        sub_uid, sub_key = new_uid(), os.urandom(32)
        server = self.serve({"get_folders": {"folders": [
            self.legacy_top_folder(),
            self.legacy_subfolder(sub_uid, sub_key, "Sub"),
        ]}})

        self.secrets_manager.create_folder(CreateOptions(self.legacy_uid, sub_uid), "Child")

        self.assertEqual(["get_folders", "create_folder"], server.paths())
        payload = server.payload("create_folder")
        self.assertEqual((self.legacy_uid, sub_uid), (payload["sharedFolderUid"], payload["parentUid"]))
        self.assert_legacy_folder_payload(payload, self.legacy_key, "Child")

    def test_create_folder_in_legacy_subfolder_with_an_aes_gcm_key_still_uses_aes_cbc(self):
        """A subfolder with a 60-byte AES-GCM key does not change the format of its children."""
        sub_uid, sub_key = new_uid(), os.urandom(32)
        server = self.serve({"get_folders": {"folders": [
            self.legacy_top_folder(),
            self.legacy_subfolder(sub_uid, sub_key, "Sub", use_gcm=True),
        ]}})

        self.secrets_manager.create_folder(CreateOptions(self.legacy_uid, sub_uid), "Child")

        self.assertEqual(["get_folders", "create_folder"], server.paths())
        self.assert_legacy_folder_payload(server.payload("create_folder"), self.legacy_key, "Child")

    def test_new_legacy_subfolder_is_read_back_and_renamed_in_aes_cbc(self):
        """create_folder(), get_folders() and update_folder() agree on the AES-CBC format for a legacy subfolder."""
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder()]}})
        sub_uid = self.secrets_manager.create_folder(CreateOptions(self.legacy_uid, None), "Created")
        payload = server.payload("create_folder")
        self.assertEqual(sub_uid, payload["folderUid"])

        # The server returns the new subfolder with the key and the name that create_folder() sent
        listed = {"get_folders": {"folders": [
            self.legacy_top_folder(),
            {"folderUid": sub_uid, "parent": self.legacy_uid,
             "folderKey": b64(url_safe_str_to_bytes(payload["sharedFolderKey"])),
             "data": b64(url_safe_str_to_bytes(payload["data"]))},
        ]}}
        self.serve(listed)
        created = next(x for x in self.secrets_manager.get_folders() if x.folder_uid == sub_uid)
        self.assertEqual(("Created", False, False), (created.name, created.use_gcm, created.is_drive))

        server = self.serve(listed)
        self.secrets_manager.update_folder(sub_uid, "Renamed")

        update = server.payload("update_folder")
        renamed = CryptoUtils.decrypt_aes_cbc(url_safe_str_to_bytes(update["data"]), created.folder_key)
        self.assertEqual("Renamed", json.loads(renamed)["name"])

    def test_create_folder_unknown_folder_raises(self):
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder()]}})
        missing_uid = new_uid()

        with self.assertRaises(KeeperError) as context:
            self.secrets_manager.create_folder(CreateOptions(missing_uid, None), "x")
        self.assertEqual(f"Unable to create folder - folder key for {missing_uid} not found",
                         context.exception.message, "the same text as in 17.3.0")
        self.assertEqual(["get_folders"], server.paths())

    def test_update_folder_unknown_folder_raises_the_17_3_0_text(self):
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder()]}})
        missing_uid = new_uid()

        with self.assertRaises(KeeperError) as context:
            self.secrets_manager.update_folder(missing_uid, "x")
        self.assertEqual(f"Unable to update folder - folder key for {missing_uid} not found",
                         context.exception.message, "the same text as in 17.3.0, with no NSF hint")
        self.assertEqual(["get_folders"], server.paths())

    def test_create_folder_under_caller_drive_subfolder_is_refused(self):
        """An NSF target folder in the folders of the caller is refused before any request."""
        parent_uid, parent_key = new_uid(), os.urandom(32)
        server = self.serve({})
        folders = [KeeperFolder(self.legacy_key, self.drive_uid, '', 'Shared'),
                   KeeperFolder(parent_key, parent_uid, '', 'Parent', use_gcm=True, is_drive=True)]

        with self.assertRaisesRegex(KeeperError, CREATE_REFUSED_IN_DRIVE):
            self.secrets_manager.create_folder(CreateOptions(self.drive_uid, parent_uid), "Child", folders=folders)
        self.assertEqual([], server.paths())

    def test_create_folder_under_unlisted_subfolder_of_caller_drive_folder_is_refused(self):
        """An NSF shared folder is refused also when the target subfolder is not in the folders of the caller."""
        server = self.serve({})
        folder = KeeperFolder(self.drive_key, self.drive_uid, '', 'Drive', use_gcm=True, is_drive=True)

        with self.assertRaisesRegex(KeeperError, CREATE_REFUSED_IN_DRIVE):
            self.secrets_manager.create_folder(CreateOptions(self.drive_uid, new_uid()), "Child", folders=[folder])
        self.assertEqual([], server.paths())

    def test_create_folder_in_caller_drive_folder_is_refused(self):
        server = self.serve({})
        folder = KeeperFolder(self.drive_key, self.drive_uid, '', 'Drive', use_gcm=True, is_drive=True)

        with self.assertRaisesRegex(KeeperError, CREATE_REFUSED_IN_DRIVE):
            self.secrets_manager.create_folder(CreateOptions(self.drive_uid, None), "Child", folders=[folder])
        self.assertEqual([], server.paths())

    def test_create_folder_with_empty_shared_folder_uid_sends_no_request(self):
        """A caller folder without a UID cannot give an empty sharedFolderUid, which the server sends to the NSF path."""
        server = self.serve({})
        folder = KeeperFolder(self.legacy_key, '', '', 'No UID')

        with self.assertRaisesRegex(KeeperError, "the shared folder UID is missing"):
            self.secrets_manager.create_folder(CreateOptions('', self.drive_uid), "Child", folders=[folder])
        self.assertEqual([], server.paths())

    def test_create_folder_under_unlisted_drive_subfolder_raises(self):
        server = self.serve({"get_secret": {"folders": [
            self.secret_folder(self.drive_uid, self.drive_key, name="Drive"),
        ]}})
        missing_uid = new_uid()

        with self.assertRaisesRegex(KeeperError, self.drive_uid):
            self.secrets_manager.create_folder(CreateOptions(self.drive_uid, missing_uid), "x")
        self.assertEqual(["get_folders"], server.paths())

    def test_update_folder_on_drive_folder_is_refused_without_get_secret(self):
        """An NSF folder that only get_secrets() lists gets the 17.3.0 text; the SDK sends no get_secret."""
        server = self.serve({
            "get_folders": {"folders": [self.legacy_top_folder()]},
            "get_secret": {"folders": [self.secret_folder(self.drive_uid, self.drive_key, name="Drive")]},
        })

        with self.assertRaises(KeeperError) as context:
            self.secrets_manager.update_folder(self.drive_uid, "Renamed")
        self.assertEqual(f"Unable to update folder - folder key for {self.drive_uid} not found",
                         context.exception.message)
        self.assertEqual(["get_folders"], server.paths())

    def test_update_folder_refuses_caller_drive_folder_object(self):
        server = self.serve({})
        folder = KeeperFolder(self.drive_key, self.drive_uid, '', 'Drive', use_gcm=False, is_drive=True)

        with self.assertRaisesRegex(KeeperError, UPDATE_REFUSED_IN_DRIVE):
            self.secrets_manager.update_folder(self.drive_uid, "Renamed", folders=[folder])
        self.assertEqual([], server.paths())

    def test_update_folder_on_legacy_subfolder_is_unchanged(self):
        sub_uid, sub_key = new_uid(), os.urandom(32)
        server = self.serve({"get_folders": {"folders": [
            self.legacy_top_folder(),
            {
                "folderUid": sub_uid,
                "parent": self.legacy_uid,
                "folderKey": b64(CryptoUtils.encrypt_aes_cbc(sub_key, self.legacy_key)),
                "data": encrypted_name("Sub", sub_key, use_gcm=False),
            },
        ]}})

        self.secrets_manager.update_folder(sub_uid, "Renamed")

        self.assertEqual(["get_folders", "update_folder"], server.paths())
        data = url_safe_str_to_bytes(server.payload("update_folder")["data"])
        self.assertEqual("Renamed", json.loads(CryptoUtils.decrypt_aes_cbc(data, sub_key))["name"])

    def test_update_folder_on_legacy_subfolder_with_an_aes_gcm_key_keeps_aes_gcm(self):
        """A subfolder with a 60-byte AES-GCM key keeps an AES-GCM name.

        get_folders() reads the name of a folder with a 60-byte key as AES-GCM,
        so an AES-CBC name would hide the folder.
        """
        sub_uid, sub_key = new_uid(), os.urandom(32)
        subfolder = self.legacy_subfolder(sub_uid, sub_key, "Sub", use_gcm=True)
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder(), subfolder]}})

        self.secrets_manager.update_folder(sub_uid, "Renamed")

        self.assertEqual(["get_folders", "update_folder"], server.paths())
        data = url_safe_str_to_bytes(server.payload("update_folder")["data"])
        self.assertEqual("Renamed", json.loads(CryptoUtils.decrypt_aes(data, sub_key))["name"])

        # get_folders() still lists the renamed folder
        self.serve({"get_folders": {"folders": [self.legacy_top_folder(), dict(subfolder, data=b64(data))]}})
        names = {x.folder_uid: x.name for x in self.secrets_manager.get_folders()}
        self.assertEqual("Renamed", names.get(sub_uid))

    def test_update_folder_on_top_level_aes_gcm_legacy_folder_gives_the_17_3_0_server_error(self):
        """The server refuses to rename a shared folder, so the SDK gives that error with no write request."""
        server = self.serve({
            "get_folders": {"folders": [self.top_folder(self.legacy_uid, self.legacy_key, "Legacy GCM")]},
            "get_secret": {"folders": [self.secret_folder(self.legacy_uid, self.legacy_key)]},
        })

        with self.assertRaises(KeeperError) as context:
            self.secrets_manager.update_folder(self.legacy_uid, "Renamed")

        error = context.exception
        self.assertEqual(f"Error: access_denied, message=Folder {self.legacy_uid} is not editable", error.message)
        self.assertEqual(("access_denied", None, None), (error.result_code, error.status_code, error.additional_info))
        self.assertEqual(["get_folders"], server.paths())

    def test_save_drive_record(self):
        """An update of an NSF record uses the same payload as a legacy record."""
        record, record_key = self.get_drive_record()
        self.assertTrue(record.is_drive)
        server = self.serve({})

        self.secrets_manager.save(record)

        payload = server.payload("update_secret")
        self.assertEqual((record.uid, 1), (payload["recordUid"], payload["revision"]))
        record_json = CryptoUtils.decrypt_aes(base64.b64decode(payload["data"]), record_key)
        self.assertEqual(json.loads(record.raw_json), json.loads(record_json))

    def test_upload_file_to_drive_record(self):
        """A file upload to an NSF record uses the same add_file payload as a legacy record."""
        record, record_key = self.get_drive_record()
        server = self.serve({"add_file": {"url": "https://upload.example.invalid/", "parameters": "{}",
                                          "successStatusCode": 204}})
        uploads = []

        def upload(url, parameters, encrypted_file_data, verify_ssl_certs=True, proxy_url=None):
            uploads.append(encrypted_file_data)
            return {"isOk": True, "statusCode": 204, "data": ""}

        with mock.patch.object(SecretsManager, "_SecretsManager__upload_file_function", staticmethod(upload)):
            file_uid = self.secrets_manager.upload_file(record, KeeperFileUpload("a.txt", "A", "text/plain", b"hello"))

        payload = server.payload("add_file")
        self.assertEqual((record.uid, file_uid), (payload["ownerRecordUid"], payload["fileRecordUid"]))
        file_key = CryptoUtils.decrypt_aes(base64.b64decode(payload["linkKey"]), record_key)
        self.assertEqual(b"hello", CryptoUtils.decrypt_aes(uploads[0], file_key))
        owner_json = json.loads(CryptoUtils.decrypt_aes(url_safe_str_to_bytes(payload["ownerRecordData"]), record_key))
        self.assertIn({"type": "fileRef", "value": [file_uid]}, owner_json["fields"])

    def test_upload_file_refused_by_an_older_server(self):
        """A server before NSF file support refuses the upload with a clear error."""
        record, _ = self.get_drive_record()
        message = "unable to add file: Keeper Drive records are not supported in add_file"
        self.serve({}, errors={"add_file": (400, {"error": "bad_request", "message": message, "additional_info": ""})})
        uploads = []

        with mock.patch.object(SecretsManager, "_SecretsManager__upload_file_function",
                               staticmethod(lambda *args, **kwargs: uploads.append(args))):
            with self.assertRaisesRegex(KeeperError, message):
                self.secrets_manager.upload_file(record, KeeperFileUpload("a.txt", "A", "text/plain", b"hello"))
        self.assertEqual([], uploads)

    def test_delete_secret_logs_each_refused_record(self):
        refused = {"recordUid": "rec2", "folderUid": self.drive_uid, "responseCode": "access_denied",
                   "errorMessage": "Record rec2 cannot be removed from a shared folder: restricted by enforcement"}
        response = {"records": [{"recordUid": "rec1", "folderUid": self.drive_uid, "responseCode": "ok",
                                 "errorMessage": None}, refused], "folders": []}
        self.serve({"delete_secret": response})
        self.enable_sdk_log()

        with self.assertLogs(logger_name, level="ERROR") as logs:
            result = self.secrets_manager.delete_secret(["rec1", "rec2"])

        self.assertEqual(response["records"], result, "the results are returned unchanged")
        self.assertEqual(1, len(logs.records))
        self.assertIn("rec2", logs.output[0])
        self.assertIn("restricted by enforcement", logs.output[0])

    def test_delete_secret_without_results_returns_an_empty_list(self):
        self.serve({"delete_secret": {}})

        self.assertEqual([], self.secrets_manager.delete_secret("rec1"))

    def test_delete_folder_logs_each_refused_folder(self):
        response = {"records": [], "folders": [
            {"folderUid": "folder1", "responseCode": "ok", "errorMessage": None},
            {"folderUid": "folder2", "responseCode": "access_denied",
             "errorMessage": "Folder or folders are not empty, use forceDeletion to delete with the content"},
        ]}
        server = self.serve({"get_folders": listed_subfolders("folder1", "folder2"), "delete_folder": response})
        self.enable_sdk_log()

        with self.assertLogs(logger_name, level="ERROR") as logs:
            result = self.secrets_manager.delete_folder(["folder1", "folder2"])

        self.assertEqual(response["folders"], result)
        self.assertEqual(["get_folders", "delete_folder"], server.paths())
        self.assertEqual(1, len(logs.records))
        self.assertIn("folder2", logs.output[0])
        self.assertIn("not empty", logs.output[0])

    def test_delete_folder_without_results_returns_an_empty_list(self):
        self.serve({"get_folders": listed_subfolders("folder1"), "delete_folder": {"records": []}})

        self.assertEqual([], self.secrets_manager.delete_folder("folder1"))

    def test_server_error_keeps_its_details(self):
        """A server refusal keeps its error code, HTTP status, and additional_info on the KeeperError."""
        message = "This feature has been disabled by your Keeper administrator."
        self.serve(self.drive_secret_response(),
                   errors={"create_secret": (403, {"error": "access_denied", "message": message,
                                                   "additional_info": "disallowed"})})

        with self.assertRaises(KeeperError) as context:
            self.secrets_manager.create_secret(self.drive_uid, RecordCreate('login', 'x'))

        error = context.exception
        self.assertEqual(f"Error: access_denied, message={message}", str(error), "the error text does not change")
        self.assertEqual(("access_denied", 403, "disallowed"),
                         (error.result_code, error.status_code, error.additional_info))

    def test_client_side_error_has_no_server_details(self):
        self.serve({"get_folders": {"folders": [self.legacy_top_folder()]}})

        with self.assertRaises(KeeperError) as context:
            self.secrets_manager.create_folder(CreateOptions(new_uid(), None), "x")

        error = context.exception
        self.assertEqual((None, None, None), (error.result_code, error.status_code, error.additional_info))

    def test_create_secret_with_empty_folder_uid_sends_no_folder_filter(self):
        for folder_uid in ("", None):
            with self.subTest(folder_uid=folder_uid):
                server = self.serve({"get_secret": {"folders": []}})
                with self.assertRaisesRegex(KeeperError, DRIVE_HINT):
                    self.secrets_manager.create_secret(folder_uid, RecordCreate('login', 'x'))
                self.assertIsNone(server.payload("get_secret")["requestedFolders"])

    def test_create_secret_with_custom_post_function_is_not_filtered(self):
        server = self.serve(self.drive_secret_response())
        self.secrets_manager.custom_post_function = server.post_function

        self.secrets_manager.create_secret(self.drive_uid, RecordCreate('login', 'x'))

        self.assertIsNone(server.payload("get_secret")["requestedFolders"])

    def test_update_folder_with_caller_drive_folder_sends_no_request(self):
        server = self.serve({})
        folder = KeeperFolder(self.drive_key, self.drive_uid, '', 'Drive', use_gcm=True, is_drive=True)

        with self.assertRaisesRegex(KeeperError, UPDATE_REFUSED_IN_DRIVE):
            self.secrets_manager.update_folder(self.drive_uid, "Renamed", folders=[folder])
        self.assertEqual([], server.paths())

    def test_create_folder_with_caller_folder_without_key_raises_without_requests(self):
        server = self.serve(self.drive_secret_response())

        with self.assertRaisesRegex(KeeperError, f"folder key for {self.drive_uid} not found"):
            self.secrets_manager.create_folder(CreateOptions(self.drive_uid, None), "Child",
                                               folders=[KeeperFolder(None, self.drive_uid, '', 'Drive')])
        self.assertEqual([], server.paths())

    def test_create_folder_with_caller_legacy_folders_sends_no_read_request(self):
        server = self.serve({})
        folders = [KeeperFolder(self.legacy_key, self.legacy_uid, '', 'Legacy')]

        self.secrets_manager.create_folder(CreateOptions(self.legacy_uid, None), "Child", folders=folders)

        self.assertEqual(["create_folder"], server.paths())
        self.assert_legacy_folder_payload(server.payload("create_folder"), self.legacy_key, "Child")

    def test_create_folder_in_legacy_subfolder_sends_the_17_3_0_payload(self):
        sub_uid, sub_key = new_uid(), os.urandom(32)
        server = self.serve({"get_folders": {"folders": [
            self.legacy_top_folder(),
            self.legacy_subfolder(sub_uid, sub_key, "Sub"),
        ]}})

        self.secrets_manager.create_folder(CreateOptions(self.legacy_uid, sub_uid), "Child")

        self.assertEqual(["get_folders", "create_folder"], server.paths())
        payload = server.payload("create_folder")
        self.assertEqual((self.legacy_uid, sub_uid), (payload["sharedFolderUid"], payload["parentUid"]))
        encrypted_key = url_safe_str_to_bytes(payload["sharedFolderKey"])
        self.assertEqual(64, len(encrypted_key), "AES-CBC: IV (16) and padded key (48)")
        folder_key = CryptoUtils.decrypt_aes_cbc(encrypted_key, self.legacy_key)
        data = CryptoUtils.decrypt_aes_cbc(url_safe_str_to_bytes(payload["data"]), folder_key)
        self.assertEqual({"name": "Child"}, json.loads(data))

    def test_create_secret_with_options_asks_for_a_drive_target_under_a_listed_folder(self):
        """A settled folder_uid does not skip the lookup of subfolder_uid."""
        target_uid, target_key = new_uid(), os.urandom(32)
        server = self.serve({
            "get_folders": {"folders": [self.legacy_top_folder(), self.top_folder(target_uid, target_key, "Target")]},
            "get_secret": {"folders": [self.secret_folder(target_uid, target_key, name="Target")]},
        })
        record = RecordCreate('login', 'In target')

        self.secrets_manager.create_secret_with_options(CreateOptions(self.legacy_uid, target_uid), record)

        self.assertEqual(["get_folders", "get_secret", "create_secret"], server.paths())
        self.assert_drive_record_payload(server.payload("create_secret"), target_key, record)

    def test_create_folder_with_caller_drive_folder_without_key_raises(self):
        server = self.serve({})
        folder = KeeperFolder(None, self.drive_uid, '', 'Drive', use_gcm=True, is_drive=True)

        with self.assertRaisesRegex(KeeperError, CREATE_REFUSED_IN_DRIVE):
            self.secrets_manager.create_folder(CreateOptions(self.drive_uid, None), "x", folders=[folder])
        self.assertNotIn("create_folder", server.paths())

    def test_create_secret_with_options_unknown_shared_folder_is_named(self):
        self.serve({"get_folders": {"folders": [self.legacy_top_folder()]}})
        missing_uid = new_uid()

        with self.assertRaisesRegex(KeeperError, re.escape(f"folder key for {missing_uid} not found")):
            self.secrets_manager.create_secret_with_options(CreateOptions(missing_uid, new_uid()),
                                                            RecordCreate('login', 'x'))

    def test_drive_record_payload_without_folder_key_names_the_target(self):
        with self.assertRaisesRegex(KeeperError, "folder key for SUB is missing"):
            SecretsManager.prepare_create_payload(self.secrets_manager.config, CreateOptions("DRIVE", "SUB"), "{}",
                                                  None, is_drive=True)

    def test_create_folder_in_top_level_aes_gcm_folder_without_records_sends_the_17_3_0_requests(self):
        """get_folders() cannot tell an NSF folder from a legacy folder; create_folder() sends the 17.3.0
        requests and the server decides."""
        legacy = self.secret_folder(self.legacy_uid, self.legacy_key)
        server = self.serve({
            "get_folders": {"folders": [self.legacy_top_folder(),
                                        self.top_folder(self.drive_uid, self.drive_key, "Drive")]},
            "get_secret": {"folders": [legacy]},
        })

        self.secrets_manager.create_folder(CreateOptions(self.drive_uid, None), "Child")

        self.assertEqual(["get_folders", "create_folder"], server.paths())
        self.assertEqual(self.drive_uid, server.payload("create_folder")["sharedFolderUid"])

    def test_get_secrets_drive_folder_uids_skip_entry_without_uid(self):
        no_uid = self.secret_folder(new_uid(), os.urandom(32), name="No UID")
        no_uid.pop("folderUid")
        self.serve({"get_secret": {"folders": [self.secret_folder(self.drive_uid, self.drive_key, name="Drive"),
                                               no_uid]}})

        response = self.secrets_manager.get_secrets(full_response=True)

        self.assertEqual({self.drive_uid}, response.drive_folder_uids)
        self.assertEqual(1, len(response.bad_folders))

    def test_get_secrets_folder_with_empty_data_is_not_drive(self):
        legacy = self.secret_folder(self.legacy_uid, self.legacy_key)
        legacy["data"] = ""
        self.serve({"get_secret": {"folders": [legacy]}})

        response = self.secrets_manager.get_secrets(full_response=True)

        self.assertFalse(response.folders[0].is_drive)
        self.assertEqual(set(), response.drive_folder_uids)

    def test_get_secrets_marks_each_copy_of_a_drive_record(self):
        """A record that is shared directly and also held by an NSF folder is an NSF record in both lists."""
        drive = self.secret_folder(self.drive_uid, self.drive_key, name="Drive")
        held = drive["records"][0]
        record_key = CryptoUtils.decrypt_aes(base64.b64decode(held["recordKey"]), self.drive_key)
        direct = {"recordUid": held["recordUid"], "recordKey": b64(CryptoUtils.encrypt_aes(record_key, self.app_key)),
                  "data": held["data"], "revision": 1}
        self.serve({"get_secret": {"records": [direct], "folders": [drive]}})

        response = self.secrets_manager.get_secrets(full_response=True)

        self.assertEqual(1, len(response.records))
        self.assertTrue(response.records[0].is_drive)
        self.assertTrue(response.folders[0].records[0].is_drive)

    def test_get_secrets_malformed_record_in_drive_folder_does_not_fail_the_call(self):
        drive = self.secret_folder(self.drive_uid, self.drive_key, name="Drive")
        drive["records"].append("unexpected")
        self.serve({"get_secret": {"folders": [drive]}})

        response = self.secrets_manager.get_secrets(full_response=True)

        self.assertEqual(1, len(response.bad_folders))
        self.assertEqual({self.drive_uid}, response.drive_folder_uids)

    def test_get_folders_keeps_padded_gcm_folder_with_empty_name(self):
        self.serve({"get_folders": {"folders": [{
            "folderUid": self.drive_uid,
            "folderKey": b64(CryptoUtils.encrypt_aes(self.drive_key, self.app_key)),
            "data": padded_drive_name("", self.drive_key),
        }]}})

        folders = self.secrets_manager.get_folders()

        self.assertEqual([(self.drive_uid, "", True)], [(f.folder_uid, f.name, f.use_gcm) for f in folders])

    def test_delete_secret_keeps_unexpected_result_items(self):
        response = {"records": ["unexpected", {"recordUid": "rec1", "responseCode": "ok"}]}
        self.serve({"delete_secret": response})

        self.assertEqual(response["records"], self.secrets_manager.delete_secret("rec1"))

    def test_delete_with_null_body_returns_an_empty_list(self):
        self.serve({"delete_secret": None, "delete_folder": None, "get_folders": listed_subfolders("folder1")})

        self.assertEqual([], self.secrets_manager.delete_secret("rec1"))
        self.assertEqual([], self.secrets_manager.delete_folder("folder1"))

    def test_delete_log_names_the_code_once(self):
        """The server can send the code itself as errorMessage, for example "access_denied "."""
        self.serve({"delete_secret": {"records": [
            {"recordUid": "rec1", "folderUid": None, "responseCode": "access_denied", "errorMessage": "access_denied "},
        ]}})
        self.enable_sdk_log()

        with self.assertLogs(logger_name, level="ERROR") as logs:
            self.secrets_manager.delete_secret("rec1")

        self.assertEqual(["Failed to delete record rec1: access_denied"], [r.getMessage() for r in logs.records])

    def nsf_secret_response(self):
        """get_secret: a legacy shared folder and an NSF folder with a zero-padded name, each with one record."""
        drive_folder = self.secret_folder(self.drive_uid, self.drive_key, name="Drive")
        drive_folder["data"] = padded_drive_name("Drive", self.drive_key)
        return {"folders": [self.secret_folder(self.legacy_uid, self.legacy_key), drive_folder]}

    def test_get_folders_default_sends_only_get_folders_and_lists_no_nsf_folder(self):
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder()]},
                             "get_secret": self.nsf_secret_response()})

        folders = self.secrets_manager.get_folders()

        self.assertEqual(["get_folders"], server.paths())
        self.assertEqual([(self.legacy_uid, False)], [(x.folder_uid, x.is_drive) for x in folders])

    def test_get_folders_include_nsf_adds_each_nsf_folder_that_get_secrets_lists(self):
        sub_uid, sub_key = new_uid(), os.urandom(32)
        server = self.serve({
            "get_folders": {"folders": [self.legacy_top_folder(), self.legacy_subfolder(sub_uid, sub_key, "Sub")]},
            "get_secret": self.nsf_secret_response(),
        })

        folders = self.secrets_manager.get_folders(include_nsf=True)

        self.assertEqual(["get_folders", "get_secret"], server.paths())
        self.assertEqual([self.legacy_uid, sub_uid, self.drive_uid], [x.folder_uid for x in folders])
        self.assertEqual([False, False, True], [x.is_drive for x in folders])
        drive = folders[-1]
        self.assertEqual(("Drive", "", True, self.drive_key),
                         (drive.name, drive.parent_uid, drive.use_gcm, drive.folder_key))
        payload = server.payload("get_secret")
        self.assertEqual((None, None), (payload["requestedRecords"], payload["requestedFolders"]),
                         "a folder filter drops each NSF folder that it does not name")

    def test_get_folders_include_nsf_keeps_one_nsf_copy_when_get_folders_also_lists_it(self):
        """If the server also lists the NSF folder in get_folders, the result keeps the copy with is_drive=True."""
        self.serve({
            "get_folders": {"folders": [self.legacy_top_folder(),
                                        self.top_folder(self.drive_uid, self.drive_key, "Drive")]},
            "get_secret": self.nsf_secret_response(),
        })

        folders = self.secrets_manager.get_folders(include_nsf=True)

        self.assertEqual([(self.legacy_uid, False), (self.drive_uid, True)],
                         [(x.folder_uid, x.is_drive) for x in folders])

    def test_get_folders_include_nsf_skips_an_nsf_folder_that_it_cannot_decrypt(self):
        bad = self.secret_folder(self.drive_uid, self.drive_key, name="Drive")
        bad["folderKey"] = b64(CryptoUtils.encrypt_aes(self.drive_key, os.urandom(32)))
        self.serve({"get_folders": {"folders": [self.legacy_top_folder()]},
                    "get_secret": {"folders": [self.secret_folder(self.legacy_uid, self.legacy_key), bad]}})

        folders = self.secrets_manager.get_folders(include_nsf=True)

        self.assertEqual([self.legacy_uid], [x.folder_uid for x in folders])

    def test_get_folders_include_nsf_raises_when_get_secret_fails(self):
        message = "The number of records from Shared Folders exceeds the maximum limit of 30000"
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder()]}},
                            errors={"get_secret": (403, {"error": "access_denied", "message": message})})

        with self.assertRaisesRegex(KeeperError, "maximum limit of 30000"):
            self.secrets_manager.get_folders(include_nsf=True)
        self.assertEqual(["get_folders", "get_secret"], server.paths())

    def test_get_folders_include_nsf_binds_a_new_client_first(self):
        server = self.serve_fresh_client(lambda: {"get_folders": {"folders": []},
                                                  "get_secret": self.nsf_secret_response()})

        folders = self.secrets_manager.get_folders(include_nsf=True)

        self.assertEqual(["get_folders", "get_folders", "get_secret"], server.paths())
        self.assert_bound(server)
        self.assertEqual([self.drive_uid], [x.folder_uid for x in folders if x.is_drive])

    def test_get_folders_include_nsf_sends_only_get_secret_through_custom_post_function(self):
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder()]},
                             "get_secret": self.nsf_secret_response()})
        custom_paths = []

        def custom_post_function(url, transmission_key, encrypted_payload, verify_ssl_certs=True, proxy_url=None):
            custom_paths.append(url.rsplit('/', 1)[-1])
            return server.post_function(url, transmission_key, encrypted_payload, verify_ssl_certs, proxy_url)

        self.secrets_manager.custom_post_function = custom_post_function
        folders = self.secrets_manager.get_folders(include_nsf=True)

        self.assertEqual(["get_secret"], custom_paths,
                         "as for get_secrets(), only get_secret uses custom_post_function")
        self.assertIn(self.drive_uid, [x.folder_uid for x in folders])

    def test_get_folders_include_nsf_result_feeds_the_folder_write_checks(self):
        self.serve({"get_folders": {"folders": [self.legacy_top_folder()]},
                    "get_secret": self.nsf_secret_response()})
        folders = self.secrets_manager.get_folders(include_nsf=True)
        server = self.serve({})

        with self.assertRaisesRegex(KeeperError, UPDATE_REFUSED_IN_DRIVE):
            self.secrets_manager.update_folder(self.drive_uid, "Renamed", folders=folders)
        with self.assertRaisesRegex(KeeperError, CREATE_REFUSED_IN_DRIVE):
            self.secrets_manager.create_folder(CreateOptions(self.drive_uid, None), "Child", folders=folders)
        self.assertEqual([], server.paths())

        record = RecordCreate('login', 'In NSF')
        self.secrets_manager.create_secret_with_options(CreateOptions(self.drive_uid, None), record, folders=folders)
        self.assertEqual(["create_secret"], server.paths(), "the NSF folder in the list needs no lookup")
        self.assert_drive_record_payload(server.payload("create_secret"), self.drive_key, record)

    def test_get_folders_include_nsf_is_a_keyword_argument(self):
        self.serve({"get_folders": {"folders": []}})

        with self.assertRaises(TypeError):
            self.secrets_manager.get_folders(True)


class CreateFolderPayloadTest(unittest.TestCase):
    """prepare_create_folder_payload() for a legacy shared folder; an NSF folder is refused."""

    def setUp(self):
        self.config = InMemoryKeyValueStorage(MockConfig.make_config())
        self.parent_key = os.urandom(32)

    def legacy_folder_name(self, payload):
        folder_key = CryptoUtils.decrypt_aes_cbc(url_safe_str_to_bytes(payload.sharedFolderKey), self.parent_key)
        return json.loads(CryptoUtils.decrypt_aes_cbc(url_safe_str_to_bytes(payload.data), folder_key))["name"]

    def test_legacy_shared_folder(self):
        payload = SecretsManager.prepare_create_folder_payload(self.config, CreateOptions("SF", None), "New",
                                                               self.parent_key)
        self.assertEqual(("SF", None), (payload.sharedFolderUid, payload.parentUid))
        self.assertEqual(64, len(url_safe_str_to_bytes(payload.sharedFolderKey)),
                         "AES-CBC: IV (16) and padded key (48)")
        self.assertEqual("New", self.legacy_folder_name(payload))

    def test_legacy_subfolder(self):
        payload = SecretsManager.prepare_create_folder_payload(self.config, CreateOptions("SF", "SUB"), "New",
                                                               self.parent_key)
        self.assertEqual(("SF", "SUB"), (payload.sharedFolderUid, payload.parentUid))
        self.assertEqual(64, len(url_safe_str_to_bytes(payload.sharedFolderKey)),
                         "AES-CBC: IV (16) and padded key (48)")
        self.assertEqual("New", self.legacy_folder_name(payload))

    def test_drive_folder_is_refused(self):
        with self.assertRaisesRegex(KeeperError, CREATE_REFUSED_IN_DRIVE):
            SecretsManager.prepare_create_folder_payload(self.config, CreateOptions("DRIVE", None), "New",
                                                         self.parent_key, is_drive=True)

    def test_drive_subfolder_is_refused(self):
        with self.assertRaisesRegex(KeeperError, CREATE_REFUSED_IN_DRIVE):
            SecretsManager.prepare_create_folder_payload(self.config, CreateOptions("DRIVE", "SUB"), "New",
                                                         self.parent_key, is_drive=True)

    def test_drive_folder_needs_a_parent(self):
        with self.assertRaises(KeeperError):
            SecretsManager.prepare_create_folder_payload(self.config, CreateOptions(None, None), "New",
                                                         self.parent_key, is_drive=True)

    def test_empty_shared_folder_uid_is_refused(self):
        """The server sends a create_folder request with an empty sharedFolderUid to the NSF path."""
        for folder_uid, subfolder_uid in (("", "NSF"), (None, "NSF"), ("", None), (None, None)):
            with self.subTest(folder_uid=folder_uid, subfolder_uid=subfolder_uid):
                with self.assertRaisesRegex(KeeperError, "the shared folder UID is missing"):
                    SecretsManager.prepare_create_folder_payload(self.config,
                                                                 CreateOptions(folder_uid, subfolder_uid),
                                                                 "New", self.parent_key)


class DriveFolderNameTest(unittest.TestCase):

    def test_ciphertext_that_ends_with_a_zero_byte(self):
        """A zero byte at the end of the real ciphertext is not taken for padding."""
        folder_key = os.urandom(32)
        data = json.dumps({"name": "Edge"}).encode()
        blob = next(b for b in (CryptoUtils.encrypt_aes(data, folder_key) for _ in range(100000)) if b[-1] == 0)

        self.assertEqual("Edge", get_drive_folder_name(b64(blob + b'\x00' * 40), folder_key))

    def test_legacy_cbc_name_is_not_a_drive_name(self):
        folder_key = os.urandom(32)

        self.assertIsNone(get_drive_folder_name(encrypted_name("Legacy", folder_key, use_gcm=False), folder_key))


class PadAesGcmTest(unittest.TestCase):

    def test_pads_to_384_bytes_then_to_16_byte_blocks(self):
        for size, expected in ((0, 384), (100, 384), (384, 384), (385, 400), (400, 400), (401, 416)):
            padded = pad_aes_gcm(b'x' * size)
            self.assertEqual(expected, len(padded), f"size {size}")
            self.assertEqual(b'x' * size, padded[:size])
            self.assertEqual(b' ' * (expected - size), padded[size:])

    def test_small_record_encrypts_to_the_server_minimum(self):
        self.assertEqual(412, len(CryptoUtils.encrypt_aes(pad_aes_gcm(b'{}'), os.urandom(32))))


if __name__ == '__main__':
    unittest.main()
