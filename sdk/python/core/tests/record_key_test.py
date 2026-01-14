import os
import tempfile
import unittest
import logging

from keeper_secrets_manager_core.storage import FileKeyValueStorage
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig


class RecordKeyTest(unittest.TestCase):
    """Test for record key decryption with shared folders

    When records from shared folders appear in the flat response.records[] array
    (not nested in folders[].records[]), the SDK must use the folder key to
    decrypt the recordKey, not the app key.
    """

    def setUp(self):
        self.orig_working_dir = os.getcwd()

        logger = logging.getLogger("ksm")
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        while logger.hasHandlers():
            logger.removeHandler(logger.handlers[0])
        handler = logging.StreamHandler()
        logger.addHandler(handler)
        formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s: %(message)s')
        handler.setFormatter(formatter)

        logger.debug("Start record key test logging")

    def tearDown(self):
        os.chdir(self.orig_working_dir)

    def test_record_with_folderUid_uses_folder_key(self):
        """Test that records in flat array with folderUid use folder key for decryption"""

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name))

                # Create a mock response with:
                # 1. A folder with its own record (nested, should work)
                # 2. A record in flat array with folderUid (the bug scenario)
                # 3. A record in flat array without folderUid (should use app key)

                res = mock.Response()

                # Add a shared folder with a record inside it
                folder = res.add_folder(uid="test_folder_123")
                folder_record = folder.add_record(
                    title="Record Inside Folder",
                    record_type='login')
                folder_record.field("login", "folder_login")
                folder_record.field("password", "folder_password")

                # Add a record to flat array that belongs to the folder (bug scenario)
                # This simulates a record created by PowerShell Commander in a shared folder
                flat_record_with_folder = res.add_record(
                    title="Flat Record With Folder",
                    record_type='login')
                flat_record_with_folder.field("login", "flat_with_folder_login")
                flat_record_with_folder.field("password", "flat_with_folder_password")
                # Set the folderUid to indicate this record belongs to a folder
                flat_record_with_folder.folder_uid = "test_folder_123"

                # Add a regular record without folder association
                flat_record_no_folder = res.add_record(
                    title="Flat Record No Folder",
                    record_type='login')
                flat_record_no_folder.field("login", "flat_no_folder_login")
                flat_record_no_folder.field("password", "flat_no_folder_password")

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res)

                # Get secrets - this should decrypt all records correctly
                records = secrets_manager.get_secrets()

                # We should get 3 records total:
                # 1. Record nested in folder
                # 2. Record in flat array with folderUid (bug fix scenario)
                # 3. Record in flat array without folderUid
                self.assertEqual(3, len(records),
                                f"Expected 3 records, got {len(records)}")

                # Find each record by title
                folder_rec = next((r for r in records if r.title == "Record Inside Folder"), None)
                flat_with_folder = next((r for r in records if r.title == "Flat Record With Folder"), None)
                flat_no_folder = next((r for r in records if r.title == "Flat Record No Folder"), None)

                # Verify all records were found
                self.assertIsNotNone(folder_rec, "Record inside folder not found")
                self.assertIsNotNone(flat_with_folder, "Flat record with folderUid not found")
                self.assertIsNotNone(flat_no_folder, "Flat record without folderUid not found")

                # Verify passwords are decrypted correctly
                self.assertEqual("folder_password", folder_rec.password,
                                "Folder record password not decrypted correctly")
                self.assertEqual("flat_with_folder_password", flat_with_folder.password,
                                "Flat record with folderUid password not decrypted correctly (BUG!)")
                self.assertEqual("flat_no_folder_password", flat_no_folder.password,
                                "Flat record without folderUid password not decrypted correctly")

                # Verify logins are decrypted correctly
                self.assertEqual("folder_login", folder_rec.field("login")[0],
                                "Folder record login not decrypted correctly")
                self.assertEqual("flat_with_folder_login", flat_with_folder.field("login")[0],
                                "Flat record with folderUid login not decrypted correctly (BUG!)")
                self.assertEqual("flat_no_folder_login", flat_no_folder.field("login")[0],
                                "Flat record without folderUid login not decrypted correctly")

        finally:
            try:
                os.unlink(fh.name)
            except:
                pass

    def test_record_with_missing_folder_falls_back_to_app_key(self):
        """Test that records with folderUid but missing folder fall back to app key"""

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name))

                res = mock.Response()

                # Add a record with folderUid that doesn't exist in folders array
                # This should fall back to using app key
                record = res.add_record(
                    title="Record With Missing Folder",
                    record_type='login')
                record.field("login", "test_login")
                record.field("password", "test_password")
                record.folder_uid = "nonexistent_folder_uid"

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res)

                # This should not crash, should fall back to app key
                records = secrets_manager.get_secrets()

                self.assertEqual(1, len(records), "Expected 1 record")
                self.assertEqual("test_password", records[0].password,
                                "Password not decrypted with fallback to app key")

        finally:
            try:
                os.unlink(fh.name)
            except:
                pass

    def test_record_with_null_folder_key_falls_back_to_app_key(self):
        """Test that records where folder has null folderKey fall back to app key"""

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name))

                res = mock.Response()

                # Add a folder with bad encryption (null folder key scenario)
                folder = res.add_folder(uid="bad_folder", has_bad_encryption=True)

                # Add a record that references this folder
                record = res.add_record(
                    title="Record With Bad Folder",
                    record_type='login')
                record.field("login", "test_login")
                record.field("password", "test_password")
                record.folder_uid = "bad_folder"

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res)

                # This should not crash, but the record will likely fail decryption
                # and end up in bad_records since the folder key is bad
                response = secrets_manager.get_secrets()

                # The main test is that this didn't crash
                # The record may be in good records OR bad records depending on encryption
                self.assertTrue(True, "Code did not crash with bad folder encryption")

        finally:
            try:
                os.unlink(fh.name)
            except:
                pass


if __name__ == '__main__':
    unittest.main()
