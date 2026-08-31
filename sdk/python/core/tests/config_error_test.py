import json
import unittest
from unittest.mock import patch

from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core import utils
from keeper_secrets_manager_core.dto.payload import QueryOptions
from keeper_secrets_manager_core.mock import MockConfig


class ConfigErrorTest(unittest.TestCase):
    """Test suite for improved error messages when config is malformed."""

    def test_malformed_base64_in_utils(self):
        """Test that base64_to_bytes raises KeeperError with helpful message for malformed base64."""

        # Test with incorrect padding (length that triggers binascii.Error)
        malformed_base64 = "ABC"  # Length 3 - will trigger "Incorrect padding" error
        with self.assertRaises(KeeperError) as context:
            utils.base64_to_bytes(malformed_base64)

        self.assertIn("Failed to decode base64 data", str(context.exception))
        self.assertIn("configuration", str(context.exception).lower())

    def test_malformed_private_key_in_crypto(self):
        """Test that der_base64_private_key_to_private_key raises KeeperError with helpful message."""

        # Test with malformed base64 private key
        malformed_private_key = "INVALID_BASE64_KEY"
        with self.assertRaises(KeeperError) as context:
            CryptoUtils.der_base64_private_key_to_private_key(malformed_private_key)

        error_message = str(context.exception)
        self.assertIn("Error parsing private key", error_message)
        self.assertIn("configuration", error_message.lower())

    def test_truncated_private_key(self):
        """Test error message when private key is truncated (common user error)."""

        # Create a valid config then corrupt the private key
        config_dict = MockConfig.make_config()

        # Truncate the private key (simulate copy-paste error)
        original_private_key = config_dict['privateKey']
        config_dict['privateKey'] = original_private_key[:50]  # Truncate to 50 chars

        # Try to use this config
        with self.assertRaises(KeeperError) as context:
            storage = InMemoryKeyValueStorage(config_dict)
            secrets_manager = SecretsManager(config=storage)
            # This should fail when trying to use the private key
            CryptoUtils.der_base64_private_key_to_private_key(
                storage.get(ConfigKeys.KEY_PRIVATE_KEY)
            )

        error_message = str(context.exception)
        self.assertIn("Error parsing private key", error_message)
        self.assertIn("configuration", error_message.lower())

    def test_private_key_with_incorrect_padding(self):
        """Test error when private key has incorrect padding (common when truncated)."""

        config_dict = MockConfig.make_config()

        # Truncate private key to create padding error
        # Remove last few chars to create invalid length
        original_private_key = config_dict['privateKey']
        # Create a string with length not divisible by 4 (after removing padding)
        config_dict['privateKey'] = original_private_key.rstrip('=')[:50]  # Invalid length

        with self.assertRaises(KeeperError) as context:
            storage = InMemoryKeyValueStorage(config_dict)
            CryptoUtils.der_base64_private_key_to_private_key(
                storage.get(ConfigKeys.KEY_PRIVATE_KEY)
            )

        error_message = str(context.exception)
        # Should get a helpful error message
        self.assertTrue(
            "Error parsing private key" in error_message or
            "Failed to decode base64 data" in error_message
        )

    def test_extract_public_key_with_bad_private_key(self):
        """Test extract_public_key_bytes with malformed private key."""

        malformed_private_key = "BAD_KEY_DATA"
        with self.assertRaises(KeeperError) as context:
            CryptoUtils.extract_public_key_bytes(malformed_private_key)

        error_message = str(context.exception)
        # Should get helpful error about private key or config
        self.assertTrue(
            "private key" in error_message.lower() or
            "configuration" in error_message.lower()
        )

    def test_invalid_base64_length(self):
        """Test with invalid base64 string (wrong length after padding)."""

        # Length 1 - triggers "number of data characters cannot be 1 more than multiple of 4"
        invalid_base64 = "A"
        with self.assertRaises(KeeperError) as context:
            utils.base64_to_bytes(invalid_base64)

        error_message = str(context.exception)
        self.assertIn("Failed to decode base64 data", error_message)
        self.assertIn("configuration", error_message.lower())

    def test_empty_private_key(self):
        """Test with empty private key string."""

        with self.assertRaises(KeeperError) as context:
            CryptoUtils.der_base64_private_key_to_private_key("")

        error_message = str(context.exception)
        self.assertTrue(
            "Error parsing private key" in error_message or
            "Error loading private key" in error_message
        )

    # ------------------------------------------------------------------
    # KSM-808: None-guard regression tests for config-decoding utilities
    # ------------------------------------------------------------------

    def test_base64_to_bytes_none_raises_keeper_error(self):
        """KSM-808: base64_to_bytes(None) must raise KeeperError, not TypeError."""
        with self.assertRaises(KeeperError) as context:
            utils.base64_to_bytes(None)
        message = str(context.exception)
        self.assertIn("None", message)
        self.assertIn("configuration", message.lower())

    def test_url_safe_str_to_bytes_none_raises_keeper_error(self):
        """KSM-808: url_safe_str_to_bytes(None) must raise KeeperError, not TypeError."""
        with self.assertRaises(KeeperError) as context:
            utils.url_safe_str_to_bytes(None)
        message = str(context.exception)
        self.assertIn("None", message)
        self.assertIn("configuration", message.lower())

    def test_base64_to_string_none_raises_keeper_error(self):
        """KSM-808: base64_to_string(None) must raise KeeperError, not TypeError."""
        with self.assertRaises(KeeperError) as context:
            utils.base64_to_string(None)
        message = str(context.exception)
        self.assertIn("None", message)
        self.assertIn("configuration", message.lower())

    def test_cryptoutils_url_safe_str_to_bytes_none_raises_keeper_error(self):
        """KSM-808: CryptoUtils.url_safe_str_to_bytes(None) must raise KeeperError."""
        with self.assertRaises(KeeperError) as context:
            CryptoUtils.url_safe_str_to_bytes(None)
        message = str(context.exception)
        self.assertIn("None", message)
        self.assertIn("configuration", message.lower())

    # ------------------------------------------------------------------
    # InMemoryKeyValueStorage must raise KeeperError (not a cryptic
    # TypeError) when given a malformed base64/JSON config string
    # ------------------------------------------------------------------

    def test_inmemory_storage_malformed_config_raises_keeper_error(self):
        """A single-char config string must raise KeeperError, not a cryptic TypeError."""
        with self.assertRaises(KeeperError) as context:
            InMemoryKeyValueStorage("A")
        message = str(context.exception)
        self.assertIn("Could not load config data", message)

    def test_inmemory_storage_non_json_string_raises_keeper_error(self):
        """A non-JSON, non-base64 config string raises a clear KeeperError."""
        with self.assertRaises(KeeperError) as context:
            InMemoryKeyValueStorage("not a valid config")
        message = str(context.exception)
        self.assertIn("Could not load config data", message)

    def _make_secrets_manager_with_config(self, config_overrides=None, skip_keys=None):
        """Build a SecretsManager whose InMemoryKeyValueStorage is missing the requested keys."""
        skip_keys = skip_keys or []
        config_dict = MockConfig.make_config()
        for key in skip_keys:
            config_dict.pop(key, None)
        if config_overrides:
            config_dict.update(config_overrides)
        storage = InMemoryKeyValueStorage(config_dict)
        return SecretsManager(config=storage)

    def test_fetch_records_missing_client_key_in_config(self):
        """KSM-808: rebind path (server returns encryptedAppKey) names 'clientKey' when missing."""
        sm = self._make_secrets_manager_with_config(skip_keys=["clientKey"])
        rebind_response = json.dumps({
            "encryptedAppKey": "Zm9vYmFy",
            "records": [],
            "folders": [],
        }).encode("utf-8")

        with patch.object(sm, "_post_query", return_value=rebind_response):
            with self.assertRaises(KeeperError) as context:
                sm.fetch_and_decrypt_secrets(QueryOptions(records_filter=[], folders_filter=[]))

        message = str(context.exception)
        self.assertIn("clientKey", message)
        self.assertIn("One-Time Token", message)

    def test_fetch_records_missing_app_key_in_config(self):
        """KSM-808: already-bound path (no encryptedAppKey from server) names 'appKey' when missing."""
        sm = self._make_secrets_manager_with_config(skip_keys=["appKey"])
        already_bound_response = json.dumps({
            "records": [],
            "folders": [],
        }).encode("utf-8")

        with patch.object(sm, "_post_query", return_value=already_bound_response):
            with self.assertRaises(KeeperError) as context:
                sm.fetch_and_decrypt_secrets(QueryOptions(records_filter=[], folders_filter=[]))

        message = str(context.exception)
        self.assertIn("appKey", message)
        self.assertIn("One-Time Token", message)

    def test_fetch_and_decrypt_folders_missing_app_key(self):
        """KSM-808: fetch_and_decrypt_folders names 'appKey' when missing from config."""
        sm = self._make_secrets_manager_with_config(skip_keys=["appKey"])
        folders_response = json.dumps({
            "folders": [{"folderUid": "abc", "folderKey": "Zm9v"}],
        }).encode("utf-8")

        with patch.object(sm, "_post_query", return_value=folders_response):
            with self.assertRaises(KeeperError) as context:
                sm.fetch_and_decrypt_folders()

        message = str(context.exception)
        self.assertIn("appKey", message)
        self.assertIn("One-Time Token", message)

    def test_fetch_and_decrypt_folders_skips_undecryptable_folder(self):
        """A folder that fails to decrypt is skipped; the good folder still returns.

        Regression for the getFolders crash-safety fix: per-folder decryption is
        wrapped in try/except so one bad folder key no longer aborts the whole call.
        """
        app_key = CryptoUtils.generate_encryption_key_bytes()
        sm = self._make_secrets_manager_with_config(
            config_overrides={"appKey": utils.bytes_to_base64(app_key)}
        )

        good_folder_key = CryptoUtils.generate_encryption_key_bytes()
        good_folder_key_enc = utils.bytes_to_base64(
            CryptoUtils.encrypt_aes(good_folder_key, app_key)
        )
        good_folder_data_enc = utils.bytes_to_base64(
            CryptoUtils.encrypt_aes_cbc(
                json.dumps({"name": "Good Folder"}).encode("utf-8"), good_folder_key
            )
        )

        bad_folder_key_enc = utils.bytes_to_base64(b"this is not a valid folder key")

        folders_response = json.dumps({
            "folders": [
                {
                    "folderUid": "good-uid",
                    "folderKey": good_folder_key_enc,
                    "data": good_folder_data_enc,
                },
                {
                    "folderUid": "bad-uid",
                    "folderKey": bad_folder_key_enc,
                },
            ],
        }).encode("utf-8")

        with patch.object(sm, "_post_query", return_value=folders_response):
            folders = sm.fetch_and_decrypt_folders()

        self.assertEqual(len(folders), 1)
        self.assertEqual(folders[0].folder_uid, "good-uid")
        self.assertEqual(folders[0].name, "Good Folder")


if __name__ == '__main__':
    unittest.main()
