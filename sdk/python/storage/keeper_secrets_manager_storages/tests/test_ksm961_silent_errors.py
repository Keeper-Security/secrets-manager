"""KSM-961 (Critical): encrypt/decrypt failures must raise, not silently corrupt storage."""
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch


def _azure_storage(config_path: str):
    from keeper_secrets_manager_storage.storage_azure_keyvault import AzureKeyValueStorage
    key_store = [None]

    def wrap(algo, key):
        key_store[0] = key
        m = MagicMock()
        m.encrypted_key = b'\x01' * 256
        return m

    def unwrap(algo, enc):
        m = MagicMock()
        m.key = key_store[0]
        return m

    mc = MagicMock()
    mc.wrap_key.side_effect = wrap
    mc.unwrap_key.side_effect = unwrap

    with patch('keeper_secrets_manager_storage.storage_azure_keyvault.CryptographyClient', return_value=mc), \
         patch('keeper_secrets_manager_storage.storage_azure_keyvault.DefaultAzureCredential'):
        return AzureKeyValueStorage('https://vault.example.com/keys/k', config_path)


def _aws_kms_storage(config_path: str):
    from keeper_secrets_manager_hsm.storage_aws_kms import AwsKmsKeyValueStorage
    mk = MagicMock()
    mk.encrypt.side_effect = lambda **kw: {'CiphertextBlob': kw['Plaintext']}
    mk.decrypt.side_effect = lambda **kw: {'Plaintext': kw['CiphertextBlob']}

    with patch('keeper_secrets_manager_hsm.storage_aws_kms.boto3') as mb:
        mb.client.return_value = mk
        return AwsKmsKeyValueStorage('alias/test', config_path)


# ---------------------------------------------------------------------------
# Azure: wrap_key failure must not silently write empty blob
# ---------------------------------------------------------------------------

class TestKsm961AzureEncryptError(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        self.storage = _azure_storage(self.config_path)

    def tearDown(self):
        self._d.cleanup()

    def test_save_raises_on_wrap_key_failure(self):
        """KSM-961: save_storage must raise when Azure wrap_key fails, not silently corrupt."""
        # Record original file size (valid encrypted blob from init)
        original_size = os.path.getsize(self.config_path)

        self.storage.crypto_client.wrap_key.side_effect = Exception('Azure vault unreachable')

        with self.assertRaises(Exception,
                               msg='save_storage must raise when wrap_key fails'):
            self.storage.save_storage({'clientId': 'test'})

        # File must not have been overwritten with an empty blob
        current_size = os.path.getsize(self.config_path)
        self.assertGreater(current_size, 2,
                           'config file must not be truncated after a failed save')
        self.assertEqual(current_size, original_size,
                         'config file must be unchanged after a failed save')

    def test_read_raises_on_unwrap_key_failure(self):
        """KSM-961: read_storage must raise when Azure unwrap_key fails."""
        self.storage.config = {}  # clear cache to force re-read from disk
        self.storage.crypto_client.unwrap_key.side_effect = Exception('Azure vault unreachable')

        with self.assertRaises(Exception,
                               msg='read_storage must raise when unwrap_key fails'):
            self.storage.read_storage()


# ---------------------------------------------------------------------------
# AWS KMS: ClientError on encrypt must propagate, not silently corrupt
# ---------------------------------------------------------------------------

class TestKsm961AwsKmsEncryptError(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        self.storage = _aws_kms_storage(self.config_path)

    def tearDown(self):
        self._d.cleanup()

    def test_save_raises_on_client_error(self):
        """KSM-961: save_storage must raise when KMS encrypt raises ClientError."""
        from botocore.exceptions import ClientError
        original_size = os.path.getsize(self.config_path)

        self.storage.kms_client.encrypt.side_effect = ClientError(
            {'Error': {'Code': 'KMSInvalidStateException', 'Message': 'Key disabled'}},
            'Encrypt')

        with self.assertRaises(Exception,
                               msg='save_storage must raise when KMS encrypt fails'):
            self.storage.save_storage({'clientId': 'test'})

        current_size = os.path.getsize(self.config_path)
        self.assertEqual(current_size, original_size,
                         'config file must be unchanged after a failed save')

    def test_load_raises_on_decrypt_client_error(self):
        """KSM-961: __load_config must raise when KMS decrypt raises ClientError."""
        from botocore.exceptions import ClientError
        self.storage.config = {}  # clear cache to force re-read
        self.storage.kms_client.decrypt.side_effect = ClientError(
            {'Error': {'Code': 'KMSInvalidStateException', 'Message': 'Key disabled'}},
            'Decrypt')

        with self.assertRaises(Exception,
                               msg='read_storage must raise when KMS decrypt fails'):
            self.storage.read_storage()


if __name__ == '__main__':
    unittest.main()
