import base64
import json
import os
import unittest

from requests import Response as RequestResponse

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.dtos import KeeperFolder, RecordCreate
from keeper_secrets_manager_core.dto.payload import CreateOptions, KSMHttpResponse
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.helpers import get_drive_folder_name
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.utils import base64_to_bytes, pad_aes_gcm, url_safe_str_to_bytes


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
    """A Keeper Drive folder name as the server sends it: AES-GCM, zero-padded to its column size."""
    blob = CryptoUtils.encrypt_aes(json.dumps({"name": name}).encode(), folder_key)
    return b64(blob + b'\x00' * (size - len(blob)))


class FakeServer:
    """Answers /sm/v1 calls with fixed responses and keeps each decrypted request payload."""

    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    def post_function(self, url, transmission_key, encrypted_payload, verify_ssl_certs=True, proxy_url=None):
        path = url.rsplit('/', 1)[-1]
        payload = json.loads(CryptoUtils.decrypt_aes(encrypted_payload.encrypted_payload, transmission_key.key))
        self.requests.append((path, payload))

        content = CryptoUtils.encrypt_aes(json.dumps(self.responses.get(path, {})).encode(), transmission_key.key)
        res = RequestResponse()
        res._content = content
        res.status_code = 200
        res.reason = "OK"
        return KSMHttpResponse(res.status_code, res.content, res)

    def paths(self):
        return [path for path, _ in self.requests]

    def payload(self, path):
        return next(payload for (x, payload) in reversed(self.requests) if x == path)


class KeeperDriveTest(unittest.TestCase):
    """Keeper Drive folders shared directly to the application, next to legacy shared folders.

    The server sends a Keeper Drive folder with its folder key wrapped by the application key and
    its name encrypted with the folder key in AES-GCM. get_folders() does not list Drive folders,
    and get_secrets() lists each one that holds at least one record.
    """

    def setUp(self):
        self.secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))
        self.app_key = base64_to_bytes(self.secrets_manager.config.get(ConfigKeys.KEY_APP_KEY))

        self.drive_uid, self.drive_key = new_uid(), os.urandom(32)
        self.legacy_uid, self.legacy_key = new_uid(), os.urandom(32)

    def serve(self, responses):
        server = FakeServer(responses)
        self.secrets_manager.post_function = server.post_function
        return server

    def secret_folder(self, folder_uid, folder_key, name=None):
        """A folder with one record as get_secret returns it. Only a Keeper Drive folder has a name."""
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

    def legacy_top_folder(self):
        """A legacy shared folder as get_folders returns it, with its name in AES-CBC."""
        return {
            "folderUid": self.legacy_uid,
            "folderKey": b64(CryptoUtils.encrypt_aes(self.legacy_key, self.app_key)),
            "data": encrypted_name("Legacy", self.legacy_key, use_gcm=False),
            "isEditable": True,
        }

    def assert_drive_record_payload(self, payload, folder_key, record_create):
        record_key_encrypted = base64.b64decode(payload["recordKey"])
        self.assertEqual(60, len(record_key_encrypted),
                         "recordKey must be the record key wrapped with the folder key (AES-GCM)")
        record_key = CryptoUtils.decrypt_aes(record_key_encrypted, folder_key)

        data = base64.b64decode(payload["data"])
        self.assertGreaterEqual(len(data), 412, "the server rejects Keeper Drive record data under 412 bytes")
        record_json = CryptoUtils.decrypt_aes(data, record_key)
        self.assertEqual(json.loads(record_create.to_json()), json.loads(record_json))
        self.assertIsNone(payload["folderKey"], "folderKey is a legacy field")

    def assert_drive_folder_payload(self, payload, parent_uid, parent_key, name):
        self.assertIsNone(payload["sharedFolderUid"], "a blank sharedFolderUid sends the request to the Keeper Drive path")
        self.assertEqual(parent_uid, payload["parentUid"])

        folder_key = CryptoUtils.decrypt_aes(url_safe_str_to_bytes(payload["sharedFolderKey"]), parent_key)
        folder_data = CryptoUtils.decrypt_aes(url_safe_str_to_bytes(payload["data"]), folder_key)
        self.assertEqual(name, json.loads(folder_data)["name"])

    def test_get_folders_reads_top_level_drive_folder(self):
        """A top-level folder with an AES-GCM name is returned as a Keeper Drive folder."""
        self.serve({"get_folders": {"folders": [
            self.legacy_top_folder(),
            {
                "folderUid": self.drive_uid,
                "folderKey": b64(CryptoUtils.encrypt_aes(self.drive_key, self.app_key)),
                "data": encrypted_name("Drive", self.drive_key),
                "isEditable": True,
            },
        ]}})

        folders = {f.folder_uid: f for f in self.secrets_manager.get_folders()}

        drive = folders[self.drive_uid]
        self.assertEqual(("Drive", True, True), (drive.name, drive.use_gcm, drive.is_drive))
        self.assertEqual(self.drive_key, drive.folder_key)
        legacy = folders[self.legacy_uid]
        self.assertEqual(("Legacy", False, False), (legacy.name, legacy.use_gcm, legacy.is_drive))

    def test_get_folders_subfolders_are_not_drive_folders(self):
        """Legacy subfolders keep the key-size dispatch and are never Keeper Drive folders."""
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
        """get_secrets marks a folder with an AES-GCM name as a Keeper Drive folder and reads the name."""
        self.serve({"get_secret": {"folders": [
            self.secret_folder(self.drive_uid, self.drive_key, name="Drive"),
            self.secret_folder(self.legacy_uid, self.legacy_key),
        ]}})

        response = self.secrets_manager.get_secrets(full_response=True)

        folders = {f.uid: f for f in response.folders}
        self.assertEqual((True, "Drive"), (folders[self.drive_uid].is_drive, folders[self.drive_uid].name))
        self.assertEqual((False, ""), (folders[self.legacy_uid].is_drive, folders[self.legacy_uid].name))
        self.assertEqual(2, len(response.records))

    def test_get_secrets_keeps_records_of_folder_with_unreadable_name(self):
        """A folder name that does not decrypt does not drop the folder or its records."""
        folder = self.secret_folder(self.drive_uid, self.drive_key)
        folder["data"] = encrypted_name("Other key", os.urandom(32))
        self.serve({"get_secret": {"folders": [folder]}})

        response = self.secrets_manager.get_secrets(full_response=True)

        self.assertFalse(response.folders[0].is_drive)
        self.assertEqual(1, len(response.records))
        self.assertEqual(0, len(response.bad_folders))

    def test_get_secrets_reads_zero_padded_drive_folder_name(self):
        """The server can send a Drive folder name zero-padded to 255 bytes; the name is still read."""
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

        self.assertEqual(1, len(folders), "a zero-padded Drive folder name must not make get_folders skip the folder")
        self.assertEqual(("Padded", True, True), (folders[0].name, folders[0].use_gcm, folders[0].is_drive))

    def test_create_secret_in_drive_folder(self):
        server = self.serve({"get_secret": {"folders": [
            self.secret_folder(self.drive_uid, self.drive_key, name="Drive"),
        ]}})
        record = RecordCreate('login', 'New Drive record')

        self.secrets_manager.create_secret(self.drive_uid, record)

        self.assertEqual(["get_secret", "create_secret"], server.paths())
        payload = server.payload("create_secret")
        self.assertEqual(self.drive_uid, payload["folderUid"])
        self.assertIsNone(payload["subFolderUid"])
        self.assert_drive_record_payload(payload, self.drive_key, record)

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
        self.assert_drive_record_payload(server.payload("create_secret"), self.drive_key, record)

    def test_create_secret_with_options_in_legacy_folder_skips_get_secrets(self):
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder()]}})

        self.secrets_manager.create_secret_with_options(CreateOptions(self.legacy_uid, None),
                                                        RecordCreate('login', 'New legacy record'))

        self.assertEqual(["get_folders", "create_secret"], server.paths())
        self.assertEqual(125, len(base64.b64decode(server.payload("create_secret")["recordKey"])))

    def test_create_secret_with_options_uses_key_of_target_drive_folder(self):
        """With subfolder_uid, the record key is wrapped with the key of that Keeper Drive folder."""
        target_uid, target_key = new_uid(), os.urandom(32)
        server = self.serve({"get_secret": {"folders": [
            self.secret_folder(self.drive_uid, self.drive_key, name="Drive"),
            self.secret_folder(target_uid, target_key, name="Target"),
        ]}})
        record = RecordCreate('login', 'In target')

        self.secrets_manager.create_secret_with_options(CreateOptions(self.drive_uid, target_uid), record)

        payload = server.payload("create_secret")
        self.assertEqual(target_uid, payload["subFolderUid"])
        self.assert_drive_record_payload(payload, target_key, record)

    def test_create_secret_with_options_unknown_drive_target_raises(self):
        server = self.serve({"get_secret": {"folders": [
            self.secret_folder(self.drive_uid, self.drive_key, name="Drive"),
        ]}})

        with self.assertRaises(KeeperError):
            self.secrets_manager.create_secret_with_options(CreateOptions(self.drive_uid, new_uid()),
                                                            RecordCreate('login', 'x'))
        self.assertNotIn("create_secret", server.paths())

    def test_create_folder_in_drive_folder(self):
        server = self.serve({
            "get_folders": {"folders": [self.legacy_top_folder()]},
            "get_secret": {"folders": [self.secret_folder(self.drive_uid, self.drive_key, name="Drive")]},
        })

        self.secrets_manager.create_folder(CreateOptions(self.drive_uid, None), "New Drive folder")

        self.assertEqual(["get_folders", "get_secret", "create_folder"], server.paths())
        self.assert_drive_folder_payload(server.payload("create_folder"), self.drive_uid, self.drive_key,
                                         "New Drive folder")

    def test_create_folder_under_drive_subfolder_uses_its_key(self):
        parent_uid, parent_key = new_uid(), os.urandom(32)
        server = self.serve({"get_secret": {"folders": [
            self.secret_folder(self.drive_uid, self.drive_key, name="Drive"),
            self.secret_folder(parent_uid, parent_key, name="Parent"),
        ]}})

        self.secrets_manager.create_folder(CreateOptions(self.drive_uid, parent_uid), "Child")

        self.assert_drive_folder_payload(server.payload("create_folder"), parent_uid, parent_key, "Child")

    def test_create_folder_in_legacy_folder_is_unchanged(self):
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder()]}})

        self.secrets_manager.create_folder(CreateOptions(self.legacy_uid, None), "Legacy child")

        self.assertEqual(["get_folders", "create_folder"], server.paths())
        payload = server.payload("create_folder")
        self.assertEqual(self.legacy_uid, payload["sharedFolderUid"])
        self.assertIsNone(payload["parentUid"])
        folder_key = CryptoUtils.decrypt_aes(url_safe_str_to_bytes(payload["sharedFolderKey"]), self.legacy_key)
        self.assertEqual(32, len(folder_key))

    def test_create_folder_unknown_folder_raises(self):
        server = self.serve({"get_folders": {"folders": [self.legacy_top_folder()]}})

        with self.assertRaises(KeeperError):
            self.secrets_manager.create_folder(CreateOptions(new_uid(), None), "x")
        self.assertEqual(["get_folders", "get_secret"], server.paths())

    def test_update_folder_on_drive_folder_writes_gcm_name(self):
        server = self.serve({
            "get_folders": {"folders": [self.legacy_top_folder()]},
            "get_secret": {"folders": [self.secret_folder(self.drive_uid, self.drive_key, name="Drive")]},
        })

        self.secrets_manager.update_folder(self.drive_uid, "Renamed")

        data = url_safe_str_to_bytes(server.payload("update_folder")["data"])
        self.assertEqual("Renamed", json.loads(CryptoUtils.decrypt_aes(data, self.drive_key))["name"])

    def test_update_folder_uses_gcm_for_drive_folder_object(self):
        """A Keeper Drive folder name is written in AES-GCM even when the folder object has use_gcm=False."""
        server = self.serve({})
        folder = KeeperFolder(self.drive_key, self.drive_uid, '', 'Drive', use_gcm=False, is_drive=True)

        self.secrets_manager.update_folder(self.drive_uid, "Renamed", folders=[folder])

        self.assertEqual(["update_folder"], server.paths())
        data = url_safe_str_to_bytes(server.payload("update_folder")["data"])
        self.assertEqual("Renamed", json.loads(CryptoUtils.decrypt_aes(data, self.drive_key))["name"])

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
