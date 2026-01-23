import unittest

from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core import utils
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


if __name__ == '__main__':
    unittest.main()
