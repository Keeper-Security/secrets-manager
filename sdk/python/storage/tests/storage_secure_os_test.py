import os
import sys
import tempfile
import unittest
from enum import Enum

from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.mock import MockConfig

from keeper_secrets_manager_storage.storage_secure_os import (
    SecureOSStorage,
    is_valid_checksum,
)


class MockChecksums(Enum):
    MOCK_EXEC_PATH_CHECKSUM = (
        "712B227DDF2C13F218D217428A10B892B0D66201696C17331A808D18A52AD70F"
    )


class SecureOSTest(unittest.TestCase):
    def setUp(self):
        self.orig_working_dir = os.getcwd()

        # Create mock secure storage executable
        self.mock_exec_path = os.path.join(
            self.orig_working_dir, "tests", "mock_secure_exec.py"
        )

        # sys.executable returns the path of the current python interpreter
        # which is used to run the mock_secure_exec.py file
        self.python_interpreter = sys.executable

        # Create a temporary directory to store temp files
        self.test_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        # WCMChecksums = self.original_wcm_checksums
        # LKUChecksums = self.original_lku_checksums
        self.test_dir.cleanup()

    def test_secure_os_storage(self):
        mock_config = MockConfig.make_config()
        storage = SecureOSStorage(app_name="TEST", exec_path="test.exe")

        # test set() and get()
        storage.set(ConfigKeys.KEY_CLIENT_ID, mock_config.get("clientId"))
        storage.set(ConfigKeys.KEY_APP_KEY, mock_config.get("appKey"))
        storage.set(ConfigKeys.KEY_PRIVATE_KEY, mock_config.get("privateKey"))
        self.assertEqual(
            mock_config.get("clientId"), storage.get(ConfigKeys.KEY_CLIENT_ID)
        )
        self.assertEqual(mock_config.get("appKey"), storage.get(ConfigKeys.KEY_APP_KEY))
        self.assertEqual(
            mock_config.get("privateKey"), storage.get(ConfigKeys.KEY_PRIVATE_KEY)
        )

        # test contains()
        self.assertTrue(storage.contains(ConfigKeys.KEY_CLIENT_ID))

        # test delete()
        storage.delete(ConfigKeys.KEY_CLIENT_ID)
        self.assertIsNone(storage.get(ConfigKeys.KEY_CLIENT_ID))

        # test delete_all()
        storage.delete_all()
        self.assertIsNone(storage.get(ConfigKeys.KEY_APP_KEY))

    def test_secure_os_storage_read_storage(self):
        storage = SecureOSStorage(
            app_name="TEST",
            exec_path=self.mock_exec_path,
            run_as=self.python_interpreter,
            _lku_checksums=MockChecksums,
            _wcm_checksums=MockChecksums,
        )

        storage.read_storage()
        self.assertIsNotNone(storage.get(ConfigKeys.KEY_CLIENT_ID))

    def test_secure_os_storage_save_storage(self):
        storage = SecureOSStorage(
            app_name="TEST",
            exec_path=self.mock_exec_path,
            run_as=self.python_interpreter,
            _lku_checksums=MockChecksums,
            _wcm_checksums=MockChecksums,
        )
        storage.config = MockConfig.make_config()

        # Test save_storage() doesn't raise an exception
        storage.save_storage()

    def test_is_valid_checksum(self):
        # Test valid checksum
        self.assertTrue(is_valid_checksum(self.mock_exec_path, MockChecksums))

        # Test invalid checksum
        file_path = os.path.join(self.test_dir.name, "invalid.txt")
        with open(file_path, "w") as f:
            f.write("Invalid checksum")

        self.assertFalse(is_valid_checksum(file_path, MockChecksums))
