import base64
import json
import os
import unittest

from requests import Response as RequestResponse

from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.payload import KSMHttpResponse
from keeper_secrets_manager_core.utils import base64_to_bytes


class SharedFolderDecryptionTest(unittest.TestCase):

    def test_flat_record_with_inner_folder_uid_uses_folder_key(self):
        """A flat record with innerFolderUid must be decrypted with the folder key, not the app key.

        When a non-SDK client (Commander, Vault UI) creates a record inside a shared folder,
        the backend returns it in response.records[] with innerFolderUid set and recordKey
        encrypted with the folder key. Before KSM-747, the SDK always used the app key,
        silently failing decryption and moving the record to bad_records.
        """
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))
        app_key = base64_to_bytes(secrets_manager.config.get(ConfigKeys.KEY_APP_KEY))

        folder_key = os.urandom(32)
        record_key = os.urandom(32)
        folder_uid = "testFolderUid12345678"
        record_uid = "testRecordUid1234567"

        record_data = json.dumps({
            "type": "login",
            "title": "Shared Folder Login",
            "notes": "",
            "fields": [{"type": "login", "value": ["user@example.com"]}],
            "custom": []
        }).encode()

        raw_response = {
            "encryptedAppKey": None,
            "folders": [{
                "folderUid": folder_uid,
                "folderKey": base64.b64encode(
                    CryptoUtils.encrypt_aes(folder_key, app_key)
                ).decode(),
                "records": []
            }],
            "records": [{
                "recordUid": record_uid,
                "recordKey": base64.b64encode(
                    CryptoUtils.encrypt_aes(record_key, folder_key)
                ).decode(),
                "data": base64.b64encode(
                    CryptoUtils.encrypt_aes(record_data, record_key)
                ).decode(),
                "isEditable": True,
                "files": None,
                "innerFolderUid": folder_uid
            }]
        }

        def post_function(url, transmission_key, encrypted_payload, verify_ssl_certs=True, proxy_url=None):
            content = CryptoUtils.encrypt_aes(
                json.dumps(raw_response).encode(),
                transmission_key.key
            )
            res = RequestResponse()
            res._content = content
            res.status_code = 200
            res.reason = "OK"
            return KSMHttpResponse(res.status_code, res.content, res)

        secrets_manager.post_function = post_function

        sm_response = secrets_manager.get_secrets(full_response=True)

        self.assertEqual(1, len(sm_response.records),
                         "Expected 1 record; got 0 (innerFolderUid path was not decrypted with folder key)")
        self.assertEqual("Shared Folder Login", sm_response.records[0].title,
                         "Record title mismatch after folder-key decryption")
        self.assertEqual(0, len(sm_response.bad_records),
                         "Record landed in bad_records; folder key was not used for decryption")


    def test_record_shared_both_flat_and_via_folder_is_not_duplicated(self):
        """A record returned in both records[] and folders[].records[] must appear exactly once.

        When a record has individual share access AND belongs to a shared folder, the backend
        returns it in both response.records[] (with innerFolderUid) and response.folders[].records[].
        Both copies decrypt correctly, so the SDK must deduplicate by recordUid before returning.
        """
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))
        app_key = base64_to_bytes(secrets_manager.config.get(ConfigKeys.KEY_APP_KEY))

        folder_key = os.urandom(32)
        record_key = os.urandom(32)
        folder_uid = "testFolderUid12345678"
        record_uid = "testRecordUid1234567"

        record_data = json.dumps({
            "type": "login",
            "title": "Dual Path Login",
            "notes": "",
            "fields": [{"type": "login", "value": ["user@example.com"]}],
            "custom": []
        }).encode()

        encrypted_folder_key = base64.b64encode(CryptoUtils.encrypt_aes(folder_key, app_key)).decode()
        encrypted_record_key = base64.b64encode(CryptoUtils.encrypt_aes(record_key, folder_key)).decode()
        encrypted_data = base64.b64encode(CryptoUtils.encrypt_aes(record_data, record_key)).decode()

        record_in_folder = {
            "recordUid": record_uid,
            "recordKey": encrypted_record_key,
            "data": encrypted_data,
            "isEditable": True,
            "files": None,
        }
        record_flat = {
            "recordUid": record_uid,
            "recordKey": encrypted_record_key,
            "data": encrypted_data,
            "isEditable": True,
            "files": None,
            "innerFolderUid": folder_uid,
        }

        raw_response = {
            "encryptedAppKey": None,
            "folders": [{
                "folderUid": folder_uid,
                "folderKey": encrypted_folder_key,
                "records": [record_in_folder],
            }],
            "records": [record_flat],
        }

        def post_function(url, transmission_key, encrypted_payload, verify_ssl_certs=True, proxy_url=None):
            content = CryptoUtils.encrypt_aes(
                json.dumps(raw_response).encode(),
                transmission_key.key
            )
            res = RequestResponse()
            res._content = content
            res.status_code = 200
            res.reason = "OK"
            return KSMHttpResponse(res.status_code, res.content, res)

        secrets_manager.post_function = post_function

        sm_response = secrets_manager.get_secrets(full_response=True)

        self.assertEqual(1, len(sm_response.records),
                         "Record appeared twice; dedup by recordUid is missing")
        self.assertEqual(record_uid, sm_response.records[0].uid,
                         "Returned record has wrong UID")
        self.assertEqual("Dual Path Login", sm_response.records[0].title,
                         "Record title mismatch after dedup")
        self.assertEqual(0, len(sm_response.bad_records),
                         "Unexpected bad_records after dedup")


if __name__ == '__main__':
    unittest.main()
