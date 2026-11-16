"""A classic folder rename keeps all folder data except the name."""

import copy
import json
import os
import unittest
from types import SimpleNamespace
from unittest import mock

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.dtos import KeeperFolder
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.keeper_globals import keeper_public_keys
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.utils import base64_to_bytes, url_safe_str_to_bytes

from keeper_drive_test import BindingFakeServer, FakeServer, UPDATE_REFUSED_IN_DRIVE, b64, new_uid


class FolderMetadataTest(unittest.TestCase):

    def setUp(self):
        self.secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))
        self.app_key = base64_to_bytes(self.secrets_manager.config.get(ConfigKeys.KEY_APP_KEY))
        self.shared_uid, self.shared_key = new_uid(), os.urandom(32)
        self.sub_uid, self.sub_key = new_uid(), os.urandom(32)
        self.metadata = {
            "name": "Old name",
            "color": "#1A73E8",
            "unicode": "caf\u00e9 \u65e5\u672c\u8a9e \U0001f4c2",
            "nullable": None,
            "enabled": False,
            "rank": 0,
            "futureField": {
                "list": [False, 0, None, "", {"name": "Keep this name", "color": "Keep this color"}],
                "emptyObject": {},
                "emptyList": [],
            },
        }

    def serve(self, folders, errors=None):
        server = FakeServer({"get_folders": {"folders": folders}}, errors=errors)
        self.secrets_manager.post_function = server.post_function
        return server

    def encrypted_data(self, data, key, use_gcm=False):
        encrypt = CryptoUtils.encrypt_aes if use_gcm else CryptoUtils.encrypt_aes_cbc
        return b64(encrypt(json.dumps(data).encode(), key))

    def shared_entry(self):
        return {
            "folderUid": self.shared_uid,
            "folderKey": b64(CryptoUtils.encrypt_aes(self.shared_key, self.app_key)),
            "data": self.encrypted_data({"name": "Shared", "color": "Keep shared color"}, self.shared_key),
        }

    def sub_entry(self, data=None, use_gcm=False, key=None):
        key = key or self.sub_key
        encrypt = CryptoUtils.encrypt_aes if use_gcm else CryptoUtils.encrypt_aes_cbc
        return {
            "folderUid": self.sub_uid,
            "parent": self.shared_uid,
            "folderKey": b64(encrypt(key, self.shared_key)),
            "data": self.encrypted_data(self.metadata if data is None else data, key, use_gcm),
        }

    def tree(self, sub_entry=None):
        return [self.shared_entry(), self.sub_entry() if sub_entry is None else sub_entry]

    def manual_folder(self, data=None, key=None, parent=None, is_drive=False):
        folder = KeeperFolder(key or self.sub_key, self.sub_uid,
                              self.shared_uid if parent is None else parent,
                              "Cached name", is_drive=is_drive)
        if data is not None:
            folder.data = copy.deepcopy(data)
        return folder

    def decoded_payloads(self, server, key=None, use_gcm=False):
        decrypt = CryptoUtils.decrypt_aes if use_gcm else CryptoUtils.decrypt_aes_cbc
        return [
            json.loads(decrypt(url_safe_str_to_bytes(payload["data"]), key or self.sub_key))
            for path, payload in server.requests if path == "update_folder"
        ]

    def assert_renamed_data(self, actual, name, source=None):
        expected = copy.deepcopy(self.metadata if source is None else source)
        expected["name"] = name
        self.assertEqual(expected, actual)
        if source is None:
            self.assertIsNone(actual["nullable"])
            self.assertIs(actual["enabled"], False)
            self.assertIs(type(actual["rank"]), int)

    def test_get_folders_keeps_complete_classic_data(self):
        server = self.serve(self.tree())

        folders = self.secrets_manager.get_folders()

        self.assertEqual(["get_folders"], server.paths())
        folder = next(folder for folder in folders if folder.folder_uid == self.sub_uid)
        self.assertEqual(self.metadata, folder.data)
        self.assertEqual(self.metadata["name"], folder.name)
        self.assertFalse(folder.is_drive)
        self.assertFalse(folder.use_gcm)

    def test_default_rename_keeps_color_and_unknown_fields(self):
        server = self.serve(self.tree())
        name = 'Renamed caf\u00e9 \u65e5\u672c\u8a9e \U0001f4c2 "quoted"\nname'

        self.secrets_manager.update_folder(self.sub_uid, name)

        self.assertEqual(["get_folders", "update_folder"], server.paths())
        self.assert_renamed_data(self.decoded_payloads(server)[0], name)
        self.assertEqual(self.sub_uid, server.payload("update_folder")["folderUid"])

    def test_gcm_subfolder_keeps_data_and_the_existing_cipher(self):
        server = self.serve(self.tree(self.sub_entry(use_gcm=True)))

        self.secrets_manager.update_folder(self.sub_uid, "GCM rename")

        self.assertEqual(["get_folders", "update_folder"], server.paths())
        self.assert_renamed_data(self.decoded_payloads(server, use_gcm=True)[0], "GCM rename")

    def test_nested_classic_child_keeps_complete_data_with_both_ciphers(self):
        first_uid, second_uid = new_uid(), new_uid()
        first_key, second_key = os.urandom(32), os.urandom(32)
        first = {
            "folderUid": first_uid,
            "parent": self.shared_uid,
            "folderKey": b64(CryptoUtils.encrypt_aes_cbc(first_key, self.shared_key)),
            "data": self.encrypted_data({"name": "First", "color": "First color"}, first_key),
        }
        second = {
            "folderUid": second_uid,
            "parent": first_uid,
            "folderKey": b64(CryptoUtils.encrypt_aes_cbc(second_key, self.shared_key)),
            "data": self.encrypted_data({"name": "Second", "color": "Second color"}, second_key),
        }
        for use_gcm in (False, True):
            with self.subTest(use_gcm=use_gcm):
                child = self.sub_entry(use_gcm=use_gcm)
                child["parent"] = second_uid
                child["isEditable"] = True
                child["serverOnlyField"] = "Keep this field out of the folder JSON"
                server = self.serve([self.shared_entry(), child, second, first])

                self.secrets_manager.update_folder(self.sub_uid, "Nested child")

                self.assertEqual(["get_folders", "update_folder"], server.paths())
                decoded = self.decoded_payloads(server, use_gcm=use_gcm)[0]
                self.assert_renamed_data(decoded, "Nested child")
                for field in ("folderUid", "folderKey", "parent", "isEditable", "serverOnlyField"):
                    self.assertNotIn(field, decoded)

    def test_new_client_finishes_binding_before_the_complete_update(self):
        config = MockConfig.make_config(skip_list=[ConfigKeys.KEY_APP_KEY.value, ConfigKeys.KEY_OWNER_PUBLIC_KEY.value])
        self.secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(config))
        client_key = os.urandom(32)
        self.secrets_manager.config.set(ConfigKeys.KEY_CLIENT_KEY, CryptoUtils.bytes_to_url_safe_str(client_key))
        self.app_key = os.urandom(32)
        server = BindingFakeServer(
            {"get_folders": {"folders": self.tree()}},
            CryptoUtils.bytes_to_url_safe_str(CryptoUtils.encrypt_aes(self.app_key, client_key)),
            keeper_public_keys["7"])
        self.secrets_manager.post_function = server.post_function

        self.secrets_manager.update_folder(self.sub_uid, "First rename")

        self.assertEqual(["get_folders", "get_folders", "update_folder"], server.paths())
        self.assert_renamed_data(self.decoded_payloads(server)[0], "First rename")

    def test_cached_get_folders_result_needs_no_second_read(self):
        server = self.serve(self.tree())
        folders = self.secrets_manager.get_folders()
        server.requests.clear()

        self.secrets_manager.update_folder(self.sub_uid, "Cached rename", folders=folders)

        self.assertEqual(["update_folder"], server.paths())
        self.assert_renamed_data(self.decoded_payloads(server)[0], "Cached rename")

    def test_repeated_cached_renames_do_not_change_cached_data(self):
        server = self.serve(self.tree())
        folders = self.secrets_manager.get_folders()
        folder = next(folder for folder in folders if folder.folder_uid == self.sub_uid)
        before = copy.deepcopy(folder.data)
        original_name = folder.name
        server.requests.clear()

        self.secrets_manager.update_folder(self.sub_uid, "First rename", folders=folders)
        self.secrets_manager.update_folder(self.sub_uid, "Second rename", folders=folders)

        self.assertEqual(["update_folder", "update_folder"], server.paths())
        first, second = self.decoded_payloads(server)
        self.assert_renamed_data(first, "First rename")
        self.assert_renamed_data(second, "Second rename")
        self.assertEqual(before, folder.data)
        self.assertEqual(original_name, folder.name)

    def test_payload_builder_copies_data_and_keeps_the_selected_cipher(self):
        for use_gcm in (False, True):
            with self.subTest(use_gcm=use_gcm):
                before = copy.deepcopy(self.metadata)

                payload = SecretsManager.prepare_update_folder_payload(
                    self.secrets_manager.config, self.sub_uid, "Payload rename", self.sub_key,
                    use_gcm=use_gcm, folder_data=self.metadata)

                decrypt = CryptoUtils.decrypt_aes if use_gcm else CryptoUtils.decrypt_aes_cbc
                decoded = json.loads(decrypt(url_safe_str_to_bytes(payload.data), self.sub_key))
                self.assert_renamed_data(decoded, "Payload rename")
                self.assertEqual(before, self.metadata)

    def test_payload_builder_without_data_keeps_the_existing_interface(self):
        for use_gcm in (False, True):
            with self.subTest(use_gcm=use_gcm):
                payload = SecretsManager.prepare_update_folder_payload(
                    self.secrets_manager.config, self.sub_uid, "Payload rename", self.sub_key, use_gcm)

                decrypt = CryptoUtils.decrypt_aes if use_gcm else CryptoUtils.decrypt_aes_cbc
                decoded = json.loads(decrypt(url_safe_str_to_bytes(payload.data), self.sub_key))
                self.assertEqual({"name": "Payload rename"}, decoded)

    def test_payload_builder_refuses_non_object_metadata(self):
        for source in ([], "text", 0, False):
            with self.subTest(source=source):
                with self.assertRaises(KeeperError):
                    SecretsManager.prepare_update_folder_payload(
                        self.secrets_manager.config, self.sub_uid, "Unsafe rename",
                        self.sub_key, folder_data=source)

    def test_old_constructor_has_no_complete_data(self):
        folder = KeeperFolder(self.sub_key, self.sub_uid, self.shared_uid, "Old name")

        self.assertIsNone(folder.data)

    def test_constructor_accepts_data_after_all_existing_arguments(self):
        folder = KeeperFolder(self.sub_key, self.sub_uid, self.shared_uid, "Old name",
                              False, False, self.metadata)

        self.assertEqual(self.metadata, folder.data)
        self.assertFalse(folder.use_gcm)
        self.assertFalse(folder.is_drive)

    def test_manual_folder_without_data_reads_current_data_and_key(self):
        new_key = os.urandom(32)
        current = dict(copy.deepcopy(self.metadata), color="#FFFFFF", revision=2)
        server = self.serve(self.tree(self.sub_entry(data=current, key=new_key)))
        folder = self.manual_folder()

        self.secrets_manager.update_folder(self.sub_uid, "Fresh rename", folders=[folder])

        self.assertEqual(["get_folders", "update_folder"], server.paths())
        self.assert_renamed_data(self.decoded_payloads(server, key=new_key)[0], "Fresh rename", current)
        self.assertEqual(self.sub_key, folder.folder_key)
        self.assertIsNone(getattr(folder, "data", None))
        self.assertEqual("Cached name", folder.name)

    def test_metadata_refresh_uses_the_new_key_and_changed_gcm_cipher(self):
        new_key = os.urandom(32)
        server = self.serve(self.tree(self.sub_entry(use_gcm=True, key=new_key)))
        folder = self.manual_folder()
        self.assertFalse(folder.use_gcm)

        self.secrets_manager.update_folder(self.sub_uid, "Current cipher", folders=[folder])

        self.assertEqual(["get_folders", "update_folder"], server.paths())
        decoded = self.decoded_payloads(server, key=new_key, use_gcm=True)[0]
        self.assert_renamed_data(decoded, "Current cipher")
        self.assertEqual(self.sub_key, folder.folder_key)
        self.assertFalse(folder.use_gcm)
        self.assertIsNone(folder.data)
        self.assertEqual("Cached name", folder.name)

    def test_legacy_object_without_data_reads_current_data(self):
        server = self.serve(self.tree())
        folder = SimpleNamespace(folder_key=self.sub_key, folder_uid=self.sub_uid,
                                 parent_uid=self.shared_uid, name="Cached name",
                                 use_gcm=False, is_drive=False)

        self.secrets_manager.update_folder(self.sub_uid, "Legacy rename", folders=[folder])

        self.assertEqual(["get_folders", "update_folder"], server.paths())
        self.assert_renamed_data(self.decoded_payloads(server)[0], "Legacy rename")
        self.assertFalse(hasattr(folder, "data"))

    def test_non_object_cached_data_reads_current_data(self):
        for source in ([], "text", 0, False):
            with self.subTest(source=source):
                server = self.serve(self.tree())
                folder = self.manual_folder(data=source)

                self.secrets_manager.update_folder(self.sub_uid, "Fresh rename", folders=[folder])

                self.assertEqual(["get_folders", "update_folder"], server.paths())
                self.assert_renamed_data(self.decoded_payloads(server)[0], "Fresh rename")
                self.assertEqual(source, folder.data)

    def test_encrypted_empty_object_is_complete_data(self):
        server = self.serve(self.tree(self.sub_entry(data={})))

        self.secrets_manager.update_folder(self.sub_uid, "Empty data rename")

        self.assertEqual(["get_folders", "update_folder"], server.paths())
        self.assertEqual({"name": "Empty data rename"}, self.decoded_payloads(server)[0])

    def test_data_without_name_keeps_all_other_fields(self):
        source = copy.deepcopy(self.metadata)
        del source["name"]
        server = self.serve(self.tree(self.sub_entry(data=source)))

        self.secrets_manager.update_folder(self.sub_uid, "Added name")

        self.assertEqual(["get_folders", "update_folder"], server.paths())
        self.assert_renamed_data(self.decoded_payloads(server)[0], "Added name", source)

    def test_missing_response_data_never_sends_a_name_only_update(self):
        for value in (None, "", "absent"):
            with self.subTest(value=value):
                entry = self.sub_entry()
                if value == "absent":
                    del entry["data"]
                else:
                    entry["data"] = value
                server = self.serve(self.tree(entry))

                with self.assertRaises(KeeperError):
                    self.secrets_manager.update_folder(self.sub_uid, "Unsafe rename")

                self.assertEqual(["get_folders", "get_folders"], server.paths())

    def test_invalid_response_data_never_sends_a_name_only_update(self):
        for raw in (b"{broken", b"[]", b"null", b'"text"', b"0", b"false", b"\xff", b""):
            with self.subTest(raw=raw):
                entry = self.sub_entry()
                entry["data"] = b64(CryptoUtils.encrypt_aes_cbc(raw, self.sub_key))
                server = self.serve(self.tree(entry))

                with self.assertRaises(KeeperError):
                    self.secrets_manager.update_folder(self.sub_uid, "Unsafe rename")

                self.assertEqual(["get_folders"], server.paths())

    def test_undecryptable_response_data_never_sends_a_name_only_update(self):
        entry = self.sub_entry()
        entry["data"] = b64(CryptoUtils.encrypt_aes_cbc(b'{"name":"Wrong key"}', os.urandom(32)))
        server = self.serve(self.tree(entry))

        with self.assertRaises(KeeperError):
            self.secrets_manager.update_folder(self.sub_uid, "Unsafe rename")

        self.assertEqual(["get_folders"], server.paths())

    def test_refresh_failure_does_not_use_incomplete_cached_data(self):
        server = self.serve(self.tree(), errors={
            "get_folders": (403, {"error": "access_denied", "message": "Read refused"}),
        })
        folder = self.manual_folder()

        with self.assertRaises(KeeperError):
            self.secrets_manager.update_folder(self.sub_uid, "Unsafe rename", folders=[folder])

        self.assertEqual(["get_folders"], server.paths())

    def test_refresh_does_not_restore_a_folder_missing_from_the_response(self):
        server = self.serve([self.shared_entry()])
        folder = self.manual_folder()

        with self.assertRaises(KeeperError):
            self.secrets_manager.update_folder(self.sub_uid, "Unsafe rename", folders=[folder])

        self.assertEqual(["get_folders"], server.paths())

    def test_incomplete_refreshed_data_is_refused_after_one_read(self):
        entry = self.sub_entry()
        del entry["data"]
        server = self.serve(self.tree(entry))
        folder = self.manual_folder()

        with self.assertRaisesRegex(KeeperError, "complete folder data"):
            self.secrets_manager.update_folder(self.sub_uid, "Unsafe rename", folders=[folder])

        self.assertEqual(["get_folders"], server.paths())

    def test_nsf_guard_runs_before_any_metadata_read(self):
        for data in (None, self.metadata):
            with self.subTest(has_data=data is not None):
                server = self.serve(self.tree())
                folder = self.manual_folder(data=data, parent="", is_drive=True)

                with self.assertRaisesRegex(KeeperError, UPDATE_REFUSED_IN_DRIVE):
                    self.secrets_manager.update_folder(self.sub_uid, "Refused", folders=[folder])

                self.assertEqual([], server.paths())

    def test_top_level_guard_runs_before_any_metadata_read(self):
        for data in (None, self.metadata):
            with self.subTest(has_data=data is not None):
                server = self.serve(self.tree())
                folder = self.manual_folder(data=data, parent="")

                with self.assertRaisesRegex(KeeperError, "is not editable"):
                    self.secrets_manager.update_folder(self.sub_uid, "Refused", folders=[folder])

                self.assertEqual([], server.paths())

    def test_conflicting_cached_parents_still_refuse_without_a_read(self):
        server = self.serve(self.tree())
        folders = [self.manual_folder(data=self.metadata),
                   self.manual_folder(data=self.metadata, parent=new_uid())]

        with self.assertRaisesRegex(KeeperError, "is not editable"):
            self.secrets_manager.update_folder(self.sub_uid, "Refused", folders=folders)

        self.assertEqual([], server.paths())

    def test_refresh_rechecks_the_nsf_guard(self):
        server = self.serve(self.tree())
        old_folder = self.manual_folder()
        current_folder = self.manual_folder(data=self.metadata, parent="", is_drive=True)

        with mock.patch.object(self.secrets_manager, "get_folders", return_value=[current_folder]) as read:
            with self.assertRaisesRegex(KeeperError, UPDATE_REFUSED_IN_DRIVE):
                self.secrets_manager.update_folder(self.sub_uid, "Refused", folders=[old_folder])

        read.assert_called_once_with()
        self.assertEqual([], server.paths())

    def test_refresh_rechecks_the_folder_key(self):
        server = self.serve(self.tree())
        old_folder = self.manual_folder()
        current_folder = self.manual_folder(data=self.metadata)
        current_folder.folder_key = None

        with mock.patch.object(self.secrets_manager, "get_folders", return_value=[current_folder]) as read:
            with self.assertRaisesRegex(KeeperError, "folder key .* not found"):
                self.secrets_manager.update_folder(self.sub_uid, "Refused", folders=[old_folder])

        read.assert_called_once_with()
        self.assertEqual([], server.paths())

    def test_refresh_rechecks_the_top_level_guard(self):
        server = self.serve(self.tree())
        old_folder = self.manual_folder()
        entry = self.sub_entry()
        del entry["parent"]
        entry["folderKey"] = b64(CryptoUtils.encrypt_aes(self.sub_key, self.app_key))
        server.responses["get_folders"]["folders"] = self.tree(entry)

        with self.assertRaisesRegex(KeeperError, "is not editable"):
            self.secrets_manager.update_folder(self.sub_uid, "Refused", folders=[old_folder])

        self.assertEqual(["get_folders"], server.paths())

    def test_refresh_rechecks_conflicting_parents(self):
        server = self.serve(self.tree())
        old_folder = self.manual_folder()
        duplicate = self.sub_entry()
        del duplicate["parent"]
        duplicate["folderKey"] = b64(CryptoUtils.encrypt_aes(self.sub_key, self.app_key))
        server.responses["get_folders"]["folders"].append(duplicate)

        with self.assertRaisesRegex(KeeperError, "is not editable"):
            self.secrets_manager.update_folder(self.sub_uid, "Refused", folders=[old_folder])

        self.assertEqual(["get_folders"], server.paths())
