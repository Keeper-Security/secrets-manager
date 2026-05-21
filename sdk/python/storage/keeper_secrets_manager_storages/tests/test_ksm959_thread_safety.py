"""KSM-959: regression tests — all KeyValueStorage backends must carry a threading.RLock."""
import os
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers to construct each backend without live cloud credentials
# ---------------------------------------------------------------------------

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


def _aws_secret_storage():
    from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider
    with patch.object(AwsConfigProvider, 'from_ec2instance_config'):
        return AwsSecretStorage('test-secret')


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestKsm959AzureLock(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.storage = _azure_storage(os.path.join(self._d.name, 'cfg.json'))

    def tearDown(self):
        self._d.cleanup()

    def test_has_reentrant_lock(self):
        """AzureKeyValueStorage must carry a threading.RLock (KSM-959)."""
        self.assertTrue(hasattr(self.storage, '_lock'),
                        'AzureKeyValueStorage is missing _lock attribute')
        self.assertIsInstance(self.storage._lock, type(threading.RLock()),
                              '_lock must be an RLock instance')


class TestKsm959AwsKmsLock(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.storage = _aws_kms_storage(os.path.join(self._d.name, 'cfg.json'))

    def tearDown(self):
        self._d.cleanup()

    def test_has_reentrant_lock(self):
        """AwsKmsKeyValueStorage must carry a threading.RLock (KSM-959)."""
        self.assertTrue(hasattr(self.storage, '_lock'),
                        'AwsKmsKeyValueStorage is missing _lock attribute')
        self.assertIsInstance(self.storage._lock, type(threading.RLock()),
                              '_lock must be an RLock instance')


class TestKsm959AwsSecretLock(unittest.TestCase):
    def setUp(self):
        self.storage = _aws_secret_storage()

    def test_has_reentrant_lock(self):
        """AwsSecretStorage must carry a threading.RLock (KSM-959)."""
        self.assertTrue(hasattr(self.storage, '_lock'),
                        'AwsSecretStorage is missing _lock attribute')
        self.assertIsInstance(self.storage._lock, type(threading.RLock()),
                              '_lock must be an RLock instance')


if __name__ == '__main__':
    unittest.main()
