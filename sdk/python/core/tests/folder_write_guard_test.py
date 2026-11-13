"""Folder rename and delete send a write only for a subfolder of a shared folder.

These tests pin the requests that update_folder() and delete_folder() send, and the results that the SDK
gives for the folders that it does not send.
"""

import inspect
import json
import logging
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import requests

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core import mock as ksm_mock
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.core import KSMCache
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.dtos import KeeperFolder, RecordCreate
from keeper_secrets_manager_core.dto.payload import CreateOptions, KSMHttpResponse
from keeper_secrets_manager_core.exceptions import KeeperError, KeeperThrottleError
from keeper_secrets_manager_core.keeper_globals import keeper_public_keys, logger_name
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.utils import base64_to_bytes, url_safe_str_to_bytes

from keeper_drive_test import (BindingFakeServer, FakeServer, UPDATE_REFUSED_IN_DRIVE, b64, encrypted_name,
                               listed_subfolders, new_uid, padded_drive_name)


def ok_item(folder_uid):
    return {"folderUid": folder_uid, "errorMessage": None, "responseCode": "ok"}


def shared_folder_item(folder_uid):
    """The delete result that the server gives for a shared folder."""
    return {"folderUid": folder_uid,
            "errorMessage": f"Folder [{folder_uid}] is a shared folder and cannot be deleted",
            "responseCode": "access_denied"}


def unknown_folder_item(folder_uid):
    """The delete result that the server gives for a folder that the application does not have."""
    return {"folderUid": folder_uid,
            "errorMessage": f"Folder [{folder_uid}] is either not associated with this device, has already been"
                            " deleted, or doesn't exist",
            "responseCode": "doesnt_exist"}


def not_editable_error(folder_uid):
    """The error that the SDK raises in 17.3.0 when the server refuses to rename a shared folder."""
    return f"Error: access_denied, message=Folder {folder_uid} is not editable"


class FolderWriteGuardTestBase(unittest.TestCase):

    def setUp(self):
        self.secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))
        self.app_key = base64_to_bytes(self.secrets_manager.config.get(ConfigKeys.KEY_APP_KEY))
        self.shared_uid, self.shared_key = new_uid(), os.urandom(32)
        self.sub_uid, self.sub_key = new_uid(), os.urandom(32)
        self.drive_uid, self.drive_key = new_uid(), os.urandom(32)

    def serve(self, responses, errors=None):
        server = FakeServer(responses, errors)
        self.secrets_manager.post_function = server.post_function
        return server

    def serve_fresh_client(self, responses):
        """A client with a new one-time token (a clientKey and no app key) and a server with the bind gate."""
        config = MockConfig.make_config(skip_list=[ConfigKeys.KEY_APP_KEY.value, ConfigKeys.KEY_OWNER_PUBLIC_KEY.value])
        self.secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(config))
        # The SDK removes clientKey from a config that has a clientId, so set it after the constructor
        client_key = os.urandom(32)
        self.secrets_manager.config.set(ConfigKeys.KEY_CLIENT_KEY, CryptoUtils.bytes_to_url_safe_str(client_key))
        self.app_key = os.urandom(32)
        server = BindingFakeServer(responses,
                                   CryptoUtils.bytes_to_url_safe_str(CryptoUtils.encrypt_aes(self.app_key, client_key)),
                                   keeper_public_keys["7"])
        self.secrets_manager.post_function = server.post_function
        return server

    def enable_sdk_log(self):
        """The SDK turns off its logger when no log_level is set; turn it on for this test only."""
        logger = logging.getLogger(logger_name)
        self.addCleanup(setattr, logger, "disabled", logger.disabled)
        logger.disabled = False

    def shared_folder(self, folder_uid=None, folder_key=None, use_gcm=False):
        """A shared folder as get_folders returns it: no parent."""
        folder_uid, folder_key = folder_uid or self.shared_uid, folder_key or self.shared_key
        return {"folderUid": folder_uid, "folderKey": b64(CryptoUtils.encrypt_aes(folder_key, self.app_key)),
                "data": encrypted_name("Shared", folder_key, use_gcm=use_gcm), "isEditable": True}

    def subfolder(self, folder_uid=None, folder_key=None, use_gcm=False, editable=True):
        """A subfolder of the shared folder as get_folders returns it. Its key is wrapped with the shared folder key."""
        folder_uid, folder_key = folder_uid or self.sub_uid, folder_key or self.sub_key
        wrap = CryptoUtils.encrypt_aes if use_gcm else CryptoUtils.encrypt_aes_cbc
        return {"folderUid": folder_uid, "parent": self.shared_uid,
                "folderKey": b64(wrap(folder_key, self.shared_key)),
                "data": encrypted_name("Sub", folder_key, use_gcm=use_gcm), "isEditable": editable}

    def drive_entry(self):
        """An NSF folder as get_folders lists it if the server lists NSF folders: no parent, a zero-padded name."""
        return {"folderUid": self.drive_uid, "folderKey": b64(CryptoUtils.encrypt_aes(self.drive_key, self.app_key)),
                "data": padded_drive_name("Drive", self.drive_key), "isEditable": True}

    def secret_folder(self, folder_uid, folder_key, name=None):
        """A folder with one record as get_secret returns it. Only an NSF folder has a name."""
        record_key = os.urandom(32)
        record_data = json.dumps({"title": "Existing", "type": "login", "fields": [], "custom": []}).encode()
        folder = {"folderUid": folder_uid, "folderKey": b64(CryptoUtils.encrypt_aes(folder_key, self.app_key)),
                  "isEditable": True,
                  "records": [{"recordUid": new_uid(),
                               "recordKey": b64(CryptoUtils.encrypt_aes(record_key, folder_key)),
                               "data": b64(CryptoUtils.encrypt_aes(record_data, record_key)),
                               "revision": 1, "isEditable": True}]}
        if name is not None:
            folder["data"] = encrypted_name(name, folder_key)
        return folder

    def classic_tree(self, *extra):
        return {"folders": [self.shared_folder(), self.subfolder(), *extra]}


class UpdateFolderGuardTest(FolderWriteGuardTestBase):

    def test_classic_subfolder_sends_get_folders_then_update_folder(self):
        server = self.serve({"get_folders": self.classic_tree()})

        self.secrets_manager.update_folder(self.sub_uid, "Renamed")

        self.assertEqual(["get_folders", "update_folder"], server.paths())
        data = url_safe_str_to_bytes(server.payload("update_folder")["data"])
        self.assertEqual("Renamed", json.loads(CryptoUtils.decrypt_aes_cbc(data, self.sub_key))["name"])

    def test_caller_classic_subfolder_sends_only_update_folder(self):
        server = self.serve({})
        folders = [KeeperFolder(self.sub_key, self.sub_uid, self.shared_uid, "Sub")]

        self.secrets_manager.update_folder(self.sub_uid, "Renamed", folders=folders)

        self.assertEqual(["update_folder"], server.paths())

    def test_shared_folder_gives_the_17_3_0_server_error_without_a_write(self):
        for use_gcm in (False, True):
            with self.subTest(use_gcm=use_gcm):
                server = self.serve({"get_folders": {"folders": [self.shared_folder(use_gcm=use_gcm)]}})

                with self.assertRaises(KeeperError) as context:
                    self.secrets_manager.update_folder(self.shared_uid, "Renamed")

                error = context.exception
                self.assertEqual(not_editable_error(self.shared_uid), error.message)
                self.assertEqual(("access_denied", None, None),
                                 (error.result_code, error.status_code, error.additional_info),
                                 "no request ran, so there is no HTTP status")
                self.assertEqual(["get_folders"], server.paths())

    def test_refusal_logs_one_debug_line(self):
        self.serve({"get_folders": {"folders": [self.shared_folder()]}})
        self.enable_sdk_log()

        with self.assertLogs(logger_name, level="DEBUG") as logs:
            with self.assertRaises(KeeperError):
                self.secrets_manager.update_folder(self.shared_uid, "Renamed")

        lines = [x for x in logs.output if "did not send update_folder" in x]
        self.assertEqual(1, len(lines))
        self.assertIn(self.shared_uid, lines[0])

    def test_nsf_shaped_get_folders_entry_is_refused(self):
        """If the server lists NSF folders in get_folders, an NSF folder has no parent and is refused."""
        server = self.serve({"get_folders": self.classic_tree(self.drive_entry())})

        with self.assertRaises(KeeperError) as context:
            self.secrets_manager.update_folder(self.drive_uid, "Renamed")
        self.assertEqual(not_editable_error(self.drive_uid), context.exception.message)
        self.assertEqual(["get_folders"], server.paths())

    def test_folder_listed_twice_is_refused_in_both_orders(self):
        twin = self.shared_folder(folder_uid=self.sub_uid, folder_key=self.sub_key, use_gcm=True)
        for entries in ((self.subfolder(), twin), (twin, self.subfolder())):
            with self.subTest(first_has_parent="parent" in entries[0]):
                server = self.serve({"get_folders": {"folders": [self.shared_folder(), *entries]}})

                with self.assertRaisesRegex(KeeperError, "is not editable"):
                    self.secrets_manager.update_folder(self.sub_uid, "Renamed")
                self.assertEqual(["get_folders"], server.paths())

    def test_folders_come_from_get_folders_as_in_17_3_0(self):
        """A patch or an override of get_folders() feeds update_folder(), as in 17.3.0."""
        server = self.serve({})
        listed = [KeeperFolder(self.sub_key, self.sub_uid, self.shared_uid, "Sub")]

        with mock.patch.object(SecretsManager, "get_folders", return_value=listed):
            self.secrets_manager.update_folder(self.sub_uid, "Renamed")
        self.assertEqual(["update_folder"], server.paths())

        class ListedFolders(SecretsManager):
            def fetch_and_decrypt_folders(self):
                return listed

        self.secrets_manager = ListedFolders(config=self.secrets_manager.config)
        server = self.serve({})
        self.secrets_manager.update_folder(self.sub_uid, "Renamed")
        self.assertEqual(["update_folder"], server.paths())

    def test_caller_list_with_an_nsf_entry_after_a_classic_entry_is_refused(self):
        server = self.serve({})
        folders = [KeeperFolder(self.sub_key, self.sub_uid, self.shared_uid, "Sub"),
                   KeeperFolder(self.sub_key, self.sub_uid, '', "Sub", use_gcm=True, is_drive=True)]

        with self.assertRaisesRegex(KeeperError, UPDATE_REFUSED_IN_DRIVE):
            self.secrets_manager.update_folder(self.sub_uid, "Renamed", folders=folders)
        self.assertEqual([], server.paths())

    def test_caller_list_with_a_second_entry_for_the_folder_is_refused(self):
        other_parent = new_uid()
        for second_parent in ('', other_parent):
            with self.subTest(second_parent=second_parent):
                server = self.serve({})
                folders = [KeeperFolder(self.sub_key, self.sub_uid, self.shared_uid, "Sub"),
                           KeeperFolder(self.sub_key, self.sub_uid, second_parent, "Sub")]

                with self.assertRaisesRegex(KeeperError, "is not editable"):
                    self.secrets_manager.update_folder(self.sub_uid, "Renamed", folders=folders)
                self.assertEqual([], server.paths())

    def test_caller_entries_without_parent_uid_are_refused(self):
        """An entry with only folder_uid and folder_key, which 17.3.0 accepted, counts as a shared folder."""
        server = self.serve({})
        folders = [SimpleNamespace(), SimpleNamespace(folder_uid=self.sub_uid, folder_key=self.sub_key)]

        with self.assertRaisesRegex(KeeperError, "is not editable"):
            self.secrets_manager.update_folder(self.sub_uid, "Renamed", folders=folders)
        self.assertEqual([], server.paths())

    def test_no_get_secret_request_for_any_target(self):
        for folder_uid in (self.sub_uid, self.shared_uid, self.drive_uid, new_uid()):
            with self.subTest(folder_uid=folder_uid):
                server = self.serve({"get_folders": self.classic_tree(),
                                     "get_secret": {"folders": [self.secret_folder(self.drive_uid, self.drive_key,
                                                                                   name="Drive")]}})
                with mock.patch.object(SecretsManager, "_get_folders_with_drive",
                                       side_effect=AssertionError("update_folder must not look up NSF folders")):
                    try:
                        self.secrets_manager.update_folder(folder_uid, "Renamed")
                    except KeeperError:
                        pass
                self.assertNotIn("get_secret", server.paths())

    def test_get_folders_failure_sends_no_update(self):
        server = self.serve({}, errors={"get_folders": (403, {"error": "access_denied", "message": "denied"})})

        with self.assertRaisesRegex(KeeperError, "denied"):
            self.secrets_manager.update_folder(self.sub_uid, "Renamed")
        self.assertEqual(["get_folders"], server.paths())

    def test_read_only_classic_subfolder_is_sent(self):
        """The server refuses it, as in 17.3.0. The SDK does not check isEditable."""
        server = self.serve({"get_folders": {"folders": [self.shared_folder(), self.subfolder(editable=False)]}},
                            errors={"update_folder": (403, {"error": "access_denied",
                                                            "message": f"Folder {self.sub_uid} is not editable"})})

        with self.assertRaises(KeeperError) as context:
            self.secrets_manager.update_folder(self.sub_uid, "Renamed")
        self.assertEqual((not_editable_error(self.sub_uid), 403),
                         (context.exception.message, context.exception.status_code))
        self.assertEqual(["get_folders", "update_folder"], server.paths())

    def test_undecryptable_classic_subfolder_gives_the_17_3_0_not_found_text(self):
        bad = dict(self.subfolder(), folderKey=b64(CryptoUtils.encrypt_aes_cbc(self.sub_key, os.urandom(32))))
        server = self.serve({"get_folders": {"folders": [self.shared_folder(), bad]}})

        with self.assertRaises(KeeperError) as context:
            self.secrets_manager.update_folder(self.sub_uid, "Renamed")
        self.assertEqual(f"Unable to update folder - folder key for {self.sub_uid} not found",
                         context.exception.message)
        self.assertEqual(["get_folders"], server.paths())


class DeleteFolderGuardTest(FolderWriteGuardTestBase):

    def test_classic_subfolder_sends_get_folders_then_delete_folder(self):
        server = self.serve({"get_folders": self.classic_tree(), "delete_folder": {"folders": [ok_item(self.sub_uid)]}})

        result = self.secrets_manager.delete_folder([self.sub_uid])

        self.assertEqual(["get_folders", "delete_folder"], server.paths())
        payload = server.payload("delete_folder")
        self.assertEqual(([self.sub_uid], False), (payload["folderUids"], payload["forceDeletion"]))
        self.assertEqual([ok_item(self.sub_uid)], result)

    def test_all_sent_keeps_the_17_3_0_payload_and_the_server_result(self):
        other_uid = new_uid()
        response = {"folders": [ok_item(other_uid), ok_item(self.sub_uid), ok_item(other_uid)]}
        server = self.serve({"get_folders": listed_subfolders(self.sub_uid, other_uid), "delete_folder": response})

        result = self.secrets_manager.delete_folder((other_uid, self.sub_uid, other_uid), force_deletion=True)

        payload = server.payload("delete_folder")
        self.assertEqual(([other_uid, self.sub_uid, other_uid], True),
                         (payload["folderUids"], payload["forceDeletion"]))
        self.assertEqual(response["folders"], result, "the server result is returned unchanged")

    def test_falsy_list_subclass_is_checked(self):
        class FalsyList(list):
            def __bool__(self):
                return False

        server = self.serve({"get_folders": self.classic_tree()})

        result = self.secrets_manager.delete_folder(FalsyList([self.drive_uid]))

        self.assertEqual([unknown_folder_item(self.drive_uid)], result)
        self.assertEqual(["get_folders"], server.paths())

    def test_force_deletion_is_sent_when_only_part_of_the_list_is_sent(self):
        for force_deletion in (True, False):
            with self.subTest(force_deletion=force_deletion):
                server = self.serve({"get_folders": self.classic_tree(),
                                     "delete_folder": {"folders": [ok_item(self.sub_uid)]}})

                self.secrets_manager.delete_folder([self.sub_uid, self.shared_uid], force_deletion=force_deletion)

                payload = server.payload("delete_folder")
                self.assertEqual(([self.sub_uid], force_deletion), (payload["folderUids"], payload["forceDeletion"]))

    def test_each_refusal_in_a_partly_sent_list_is_logged_once(self):
        refused = {"folderUid": self.sub_uid, "responseCode": "access_denied",
                   "errorMessage": "Folder or folders are not empty, use forceDeletion to delete with the content"}
        self.serve({"get_folders": self.classic_tree(), "delete_folder": {"folders": [refused]}})
        self.enable_sdk_log()

        with self.assertLogs(logger_name, level="ERROR") as logs:
            result = self.secrets_manager.delete_folder([self.sub_uid, self.shared_uid])

        self.assertEqual([refused, shared_folder_item(self.shared_uid)], result)
        self.assertEqual(2, len(logs.records), "one line for the server refusal and one for the SDK item")

    def test_str_input(self):
        server = self.serve({"get_folders": listed_subfolders(self.sub_uid),
                             "delete_folder": {"folders": [ok_item(self.sub_uid)]}})

        self.secrets_manager.delete_folder(self.sub_uid)

        self.assertEqual([self.sub_uid], server.payload("delete_folder")["folderUids"])

    def test_shared_folder_and_unknown_uid_get_the_17_3_0_server_items(self):
        unknown_uid = new_uid()
        server = self.serve({"get_folders": self.classic_tree()})

        result = self.secrets_manager.delete_folder([self.shared_uid, unknown_uid])

        expected = [shared_folder_item(self.shared_uid), unknown_folder_item(unknown_uid)]
        self.assertEqual(json.dumps(expected), json.dumps(result), "the same items, in the key order of the server")
        self.assertEqual(["get_folders"], server.paths())

    def test_nsf_folder_that_get_secret_lists_is_refused_without_get_secret(self):
        drive_folder = self.secret_folder(self.drive_uid, self.drive_key, name="Drive")
        server = self.serve({"get_folders": self.classic_tree(), "get_secret": {"folders": [drive_folder]}})

        result = self.secrets_manager.delete_folder([self.drive_uid])

        self.assertEqual([unknown_folder_item(self.drive_uid)], result)
        self.assertEqual(["get_folders"], server.paths())

    def test_empty_nsf_folder_that_no_read_lists_is_refused(self):
        server = self.serve({"get_folders": self.classic_tree()})

        result = self.secrets_manager.delete_folder(self.drive_uid, force_deletion=True)

        self.assertEqual([unknown_folder_item(self.drive_uid)], result)
        self.assertEqual(["get_folders"], server.paths())

    def test_nsf_shaped_get_folders_entry_is_refused(self):
        server = self.serve({"get_folders": self.classic_tree(self.drive_entry())})

        result = self.secrets_manager.delete_folder([self.drive_uid])

        self.assertEqual([shared_folder_item(self.drive_uid)], result)
        self.assertEqual(["get_folders"], server.paths())

    def test_mixed_list_sends_only_classic_subfolders_and_keeps_the_caller_order(self):
        unknown_uid = new_uid()
        server = self.serve({"get_folders": self.classic_tree(), "delete_folder": {"folders": [ok_item(self.sub_uid)]}})
        self.enable_sdk_log()

        with self.assertLogs(logger_name, level="ERROR") as logs:
            result = self.secrets_manager.delete_folder(
                [self.sub_uid, self.shared_uid, self.drive_uid, unknown_uid, self.sub_uid])

        self.assertEqual(["get_folders", "delete_folder"], server.paths())
        self.assertEqual([self.sub_uid, self.sub_uid], server.payload("delete_folder")["folderUids"])
        self.assertEqual([ok_item(self.sub_uid), shared_folder_item(self.shared_uid),
                          unknown_folder_item(self.drive_uid), unknown_folder_item(unknown_uid)], result)
        self.assertEqual(3, len(logs.records), "each refused folder is logged once")

    def test_refused_item_takes_the_caller_position(self):
        server = self.serve({"get_folders": self.classic_tree(), "delete_folder": {"folders": [ok_item(self.sub_uid)]}})

        result = self.secrets_manager.delete_folder([self.shared_uid, self.sub_uid])

        self.assertEqual([shared_folder_item(self.shared_uid), ok_item(self.sub_uid)], result)
        self.assertEqual([self.sub_uid], server.payload("delete_folder")["folderUids"])

    def test_every_server_item_is_kept(self):
        """A second server item for one folder, or an item for another UID, stays at the end."""
        unknown_uid, other_uid = new_uid(), new_uid()
        extra = [ok_item(self.sub_uid), ok_item(other_uid), "unexpected"]
        self.serve({"get_folders": self.classic_tree(), "delete_folder": {"folders": [ok_item(self.sub_uid), *extra]}})

        result = self.secrets_manager.delete_folder([self.sub_uid, unknown_uid])

        self.assertEqual([ok_item(self.sub_uid), unknown_folder_item(unknown_uid), *extra], result)

    def test_undecryptable_classic_subfolder_is_sent(self):
        """17.3.0 sent such a folder with no lookup. The raw get_folders entry still has its parent."""
        bad = dict(self.subfolder(), folderKey=b64(CryptoUtils.encrypt_aes_cbc(self.sub_key, os.urandom(32))))
        server = self.serve({"get_folders": {"folders": [self.shared_folder(), bad]},
                             "delete_folder": {"folders": [ok_item(self.sub_uid)]}})

        self.assertEqual([ok_item(self.sub_uid)], self.secrets_manager.delete_folder([self.sub_uid]))
        self.assertEqual([self.sub_uid], server.payload("delete_folder")["folderUids"])

    def test_read_only_classic_subfolder_is_sent_and_the_server_item_is_returned(self):
        item = {"folderUid": self.sub_uid, "errorMessage": f"Folder [{self.sub_uid}] is not editable",
                "responseCode": "access_denied"}
        server = self.serve({"get_folders": {"folders": [self.shared_folder(), self.subfolder(editable=False)]},
                             "delete_folder": {"folders": [item]}})

        self.assertEqual([item], self.secrets_manager.delete_folder([self.sub_uid]))
        self.assertEqual(["get_folders", "delete_folder"], server.paths())

    def test_all_refused_sends_no_delete_request(self):
        server = self.serve({"get_folders": self.classic_tree()})

        result = self.secrets_manager.delete_folder([self.shared_uid, self.drive_uid])

        self.assertEqual([shared_folder_item(self.shared_uid), unknown_folder_item(self.drive_uid)], result)
        self.assertEqual(["get_folders"], server.paths())

    def test_empty_input_sends_the_17_3_0_request_without_a_lookup(self):
        for folder_uids, sent in (([], []), (None, None), ((), [])):
            with self.subTest(folder_uids=folder_uids):
                server = self.serve({"delete_folder": {"folders": []}})

                self.assertEqual([], self.secrets_manager.delete_folder(folder_uids))
                self.assertEqual(["delete_folder"], server.paths())
                self.assertEqual(sent, server.payload("delete_folder")["folderUids"])

    def test_non_string_uids_raise_before_any_request(self):
        for folder_uids in ([None], [5], [True], [{}], [[]], [b"uid"], [self.sub_uid, None]):
            with self.subTest(folder_uids=folder_uids):
                server = self.serve({"get_folders": listed_subfolders(self.sub_uid)})

                with self.assertRaisesRegex(KeeperError, "each folder UID must be a string"):
                    self.secrets_manager.delete_folder(folder_uids)
                self.assertEqual([], server.paths())

    def test_lookup_failure_raises_and_sends_no_delete(self):
        for status in (403, 500):
            with self.subTest(status=status):
                server = self.serve({}, errors={"get_folders": (status, {"error": "unknown", "message": "failed"})})

                with self.assertRaisesRegex(KeeperError, "message=failed"):
                    self.secrets_manager.delete_folder([self.sub_uid])
                self.assertEqual(["get_folders"], server.paths())

    def test_lookup_error_without_a_json_body_raises_and_sends_no_delete(self):
        paths = []

        def html_error(url, transmission_key, encrypted_payload, verify_ssl_certs=True, proxy_url=None):
            paths.append(url.rsplit('/', 1)[-1])
            res = requests.Response()
            res._content, res.status_code, res.reason = b"<html>ISE</html>", 500, "Server Error"
            return KSMHttpResponse(res.status_code, res.content, res)

        self.secrets_manager.post_function = html_error
        with self.assertRaises(requests.HTTPError):
            self.secrets_manager.delete_folder([self.sub_uid])
        self.assertEqual(["get_folders"], paths)

    def test_lookup_transport_error_sends_no_delete(self):
        paths = []

        def offline(url, transmission_key, encrypted_payload, verify_ssl_certs=True, proxy_url=None):
            paths.append(url.rsplit('/', 1)[-1])
            raise ConnectionError("offline")

        self.secrets_manager.post_function = offline
        with self.assertRaises(ConnectionError):
            self.secrets_manager.delete_folder([self.sub_uid])
        self.assertEqual(["get_folders"], paths)

    def test_throttled_lookup_raises_and_sends_no_delete(self):
        server = self.serve({}, errors={"get_folders": (403, {"error": "throttled", "message": "slow down"})})

        with mock.patch("keeper_secrets_manager_core.core.time.sleep"):
            with self.assertRaises(KeeperThrottleError):
                self.secrets_manager.delete_folder([self.sub_uid])
        self.assertNotIn("delete_folder", server.paths())

    def test_server_refusal_of_the_whole_request_still_raises(self):
        message = "Folder or folders are not empty, use forceDeletion to delete with the content"
        server = self.serve({"get_folders": self.classic_tree()},
                            errors={"delete_folder": (403, {"error": "access_denied", "message": message})})

        with self.assertRaises(KeeperError) as context:
            self.secrets_manager.delete_folder([self.sub_uid, self.drive_uid])
        self.assertEqual(f"Error: access_denied, message={message}", context.exception.message)
        self.assertEqual(["get_folders", "delete_folder"], server.paths())

    def test_folder_listed_twice_is_refused_in_both_orders(self):
        top = {"folderUid": self.sub_uid}
        for entries in ((self.subfolder(), top), (top, self.subfolder())):
            with self.subTest(first_has_parent="parent" in entries[0]):
                server = self.serve({"get_folders": {"folders": [self.shared_folder(), *entries]}})

                self.assertEqual([shared_folder_item(self.sub_uid)], self.secrets_manager.delete_folder([self.sub_uid]))
                self.assertEqual(["get_folders"], server.paths())

    def test_entry_with_a_parent_that_is_not_a_string_is_refused(self):
        server = self.serve({"get_folders": {"folders": [{"folderUid": self.sub_uid, "parent": 123}]}})

        self.assertEqual([shared_folder_item(self.sub_uid)], self.secrets_manager.delete_folder([self.sub_uid]))
        self.assertEqual(["get_folders"], server.paths())

    def test_caller_list_change_after_the_lookup_does_not_change_the_payload(self):
        folder_uids = [self.sub_uid]
        server = FakeServer({"get_folders": listed_subfolders(self.sub_uid),
                             "delete_folder": {"folders": [ok_item(self.sub_uid)]}})

        def post_function(url, transmission_key, encrypted_payload, verify_ssl_certs=True, proxy_url=None):
            if url.endswith("/get_folders"):
                folder_uids.append(self.drive_uid)
            return server.post_function(url, transmission_key, encrypted_payload, verify_ssl_certs, proxy_url)

        self.secrets_manager.post_function = post_function
        self.secrets_manager.delete_folder(folder_uids)

        self.assertEqual([self.sub_uid], server.payload("delete_folder")["folderUids"])

    def test_new_client_binds_before_the_delete(self):
        server = self.serve_fresh_client({"get_folders": listed_subfolders(self.sub_uid),
                                          "delete_folder": {"folders": [ok_item(self.sub_uid)]}})

        result = self.secrets_manager.delete_folder(self.sub_uid)

        self.assertEqual(["get_folders", "get_folders", "delete_folder"], server.paths())
        self.assertTrue(server.bound, "a read without the public key finishes the binding before the write")
        self.assertEqual([ok_item(self.sub_uid)], result)

    def test_custom_post_function_does_not_serve_the_lookup(self):
        """The SDK sends only get_secret through custom_post_function, so a KSMCache setup does not feed the read."""
        server = self.serve({"get_folders": listed_subfolders(self.sub_uid),
                             "delete_folder": {"folders": [ok_item(self.sub_uid)]}})
        self.secrets_manager.custom_post_function = mock.Mock(side_effect=AssertionError("custom_post_function"))

        self.secrets_manager.delete_folder(self.sub_uid)

        self.secrets_manager.custom_post_function.assert_not_called()
        self.assertEqual(["get_folders", "delete_folder"], server.paths())

    def test_caching_post_function_with_a_stale_get_folders_response_sends_only_listed_subfolders(self):
        """With post_function=KSMCache.caching_post_function, a failed read gets the last cached response."""
        stale = FakeServer({"get_folders": listed_subfolders(self.sub_uid)})
        sent = []

        def offline(url, transmission_key, encrypted_payload, verify_ssl_certs=True, proxy_url=None):
            payload = json.loads(CryptoUtils.decrypt_aes(encrypted_payload.encrypted_payload, transmission_key.key))
            sent.append((url.rsplit('/', 1)[-1], payload))
            raise ConnectionError("offline")

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(KSMCache, "kms_cache_file_name", os.path.join(tmp, "ksm_cache.bin")):
                self.secrets_manager.post_function = KSMCache.caching_post_function
                with mock.patch.object(SecretsManager, "post_function", staticmethod(stale.post_function)):
                    self.secrets_manager.get_folders()
                with mock.patch.object(SecretsManager, "post_function", staticmethod(offline)):
                    result = self.secrets_manager.delete_folder([self.sub_uid, self.drive_uid])

        self.assertEqual(["get_folders", "delete_folder"], [path for path, _ in sent])
        self.assertEqual([self.sub_uid], sent[1][1]["folderUids"], "only the subfolder that the cached response lists")
        self.assertIn(unknown_folder_item(self.drive_uid), result)

    def test_response_queue_mock_answers_the_lookup_first(self):
        """With the public ResponseQueue mock, the first queued response answers the get_folders read."""
        queue = ksm_mock.ResponseQueue(client=self.secrets_manager)
        queue.add_response(ksm_mock.Response())

        self.assertEqual([unknown_folder_item(self.sub_uid)], self.secrets_manager.delete_folder([self.sub_uid]))
        self.assertEqual(0, len(queue.queue))

    def test_refused_items_are_logged_only_with_a_log_level(self):
        self.serve({"get_folders": self.classic_tree()})
        with self.assertNoLogs(logger_name, level="DEBUG"):
            self.secrets_manager.delete_folder([self.shared_uid])

        self.serve({"get_folders": self.classic_tree()})
        self.enable_sdk_log()
        with self.assertLogs(logger_name, level="DEBUG") as logs:
            self.secrets_manager.delete_folder([self.shared_uid])
        self.assertEqual(1, len([x for x in logs.output if x.startswith("DEBUG") and "did not send folder" in x]))
        self.assertEqual(1, len([x for x in logs.output if x.startswith("ERROR") and self.shared_uid in x]))


class CreateFolderGuardTest(FolderWriteGuardTestBase):

    def test_create_payload_always_names_a_shared_folder(self):
        cases = [
            # A subfolder that get_folders does not list, for example an NSF folder
            ({"folders": [self.shared_folder()]}, CreateOptions(self.shared_uid, self.drive_uid), self.shared_uid),
            # An NSF folder as get_folders lists it if the server lists NSF folders
            (self.classic_tree(self.drive_entry()), CreateOptions(self.drive_uid, None), self.drive_uid),
        ]
        for folders, create_options, shared_folder_uid in cases:
            with self.subTest(shared_folder_uid=shared_folder_uid):
                server = self.serve({"get_folders": folders})

                self.secrets_manager.create_folder(create_options, "New")

                payload = server.payload("create_folder")
                self.assertEqual(shared_folder_uid, payload["sharedFolderUid"],
                                 "the server sends a request with a blank sharedFolderUid to the NSF path")

    def test_blank_shared_folder_uid_raises_before_any_request(self):
        server = self.serve({})
        folders = [KeeperFolder(self.shared_key, " ", "", "Blank")]

        with self.assertRaisesRegex(KeeperError, "the shared folder UID is missing"):
            self.secrets_manager.create_folder(CreateOptions(" ", None), "New", folders=folders)
        with self.assertRaisesRegex(KeeperError, "the shared folder UID is missing"):
            SecretsManager.prepare_create_folder_payload(self.secrets_manager.config, CreateOptions(" \t", None), "New",
                                                         self.shared_key)
        self.assertEqual([], server.paths())


class InvarianceTest(FolderWriteGuardTestBase):

    def test_reads_and_record_writes_never_use_the_folder_write_checks(self):
        server = self.serve({
            "get_folders": self.classic_tree(),
            "get_secret": {"folders": [self.secret_folder(self.shared_uid, self.shared_key),
                                       self.secret_folder(self.drive_uid, self.drive_key, name="Drive")]},
            "delete_secret": {"records": []},
        })
        refuse = AssertionError("a folder write check ran")
        with mock.patch.object(SecretsManager, "_get_folder_parents", side_effect=refuse), \
                mock.patch.object(SecretsManager, "_folder_parents", side_effect=refuse), \
                mock.patch.object(SecretsManager, "_merge_folder_results", side_effect=refuse):
            self.secrets_manager.get_folders()
            records = self.secrets_manager.get_secrets()
            classic_record = next(x for x in records if not x.is_drive)
            drive_record = next(x for x in records if x.is_drive)
            self.secrets_manager.create_secret(self.drive_uid, RecordCreate("login", "In NSF"))
            self.secrets_manager.create_secret(self.shared_uid, RecordCreate("login", "In shared folder"))
            self.secrets_manager.create_secret_with_options(CreateOptions(self.shared_uid, self.sub_uid),
                                                            RecordCreate("login", "In subfolder"))
            self.secrets_manager.create_secret_with_options(CreateOptions(self.drive_uid, None),
                                                            RecordCreate("login", "In NSF with options"))
            self.secrets_manager.save(classic_record)
            self.secrets_manager.save(drive_record)
            self.secrets_manager.delete_secret(classic_record.uid)
            self.secrets_manager.delete_secret(drive_record.uid)

        self.assertEqual(["get_folders", "get_secret",
                          "get_secret", "create_secret", "get_secret", "create_secret",
                          "get_folders", "create_secret", "get_folders", "get_secret", "create_secret",
                          "update_secret", "update_secret", "delete_secret", "delete_secret"], server.paths())

    def test_public_signatures_do_not_change(self):
        """Each 17.3.0 parameter keeps its name, its place, its kind, and its default.

        The optional use_gcm and is_drive parameters come after the 17.3.0 parameters, and include_nsf is
        keyword-only (18.0.0).
        """
        empty, positional = inspect.Parameter.empty, inspect.Parameter.POSITIONAL_OR_KEYWORD

        def parameters(function):
            return [(x.name, x.kind, x.default) for x in inspect.signature(function).parameters.values()]

        def expect(*pairs):
            return [(name, positional, default) for name, default in pairs]

        expected = {
            SecretsManager.get_folders: [("self", positional, empty),
                                         ("include_nsf", inspect.Parameter.KEYWORD_ONLY, False)],
            SecretsManager.update_folder: expect(("self", empty), ("folder_uid", empty), ("folder_name", empty),
                                                 ("folders", None)),
            SecretsManager.delete_folder: expect(("self", empty), ("folder_uids", empty), ("force_deletion", False)),
            SecretsManager.create_folder: expect(("self", empty), ("create_options", empty), ("folder_name", empty),
                                                 ("folders", None)),
            SecretsManager.prepare_update_folder_payload: expect(("storage", empty), ("folder_uid", empty),
                                                                 ("folder_name", empty), ("folder_key", empty),
                                                                 ("use_gcm", False)),
            SecretsManager.prepare_delete_folder_payload: expect(("storage", empty), ("folder_uids", empty),
                                                                 ("force_deletion", empty)),
            SecretsManager.prepare_create_folder_payload: expect(("storage", empty), ("create_options", empty),
                                                                 ("folder_name", empty), ("shared_folder_key", empty),
                                                                 ("is_drive", False)),
        }
        for function, params in expected.items():
            with self.subTest(function=function.__name__):
                self.assertEqual(params, parameters(function))


if __name__ == '__main__':
    unittest.main()
