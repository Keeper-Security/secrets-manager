"""KSM-962: delete_all() must remove the backing config file (file-backed backends)."""
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


class TestKsm962AzureDeleteAll(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        self.storage = _azure_storage(self.config_path)

    def tearDown(self):
        self._d.cleanup()

    def test_delete_all_removes_config_file(self):
        """KSM-962: AzureKeyValueStorage.delete_all() must remove the backing file."""
        self.assertTrue(os.path.exists(self.config_path),
                        'config file should exist before delete_all')
        self.storage.delete_all()
        self.assertFalse(os.path.exists(self.config_path),
                         'config file must be removed by delete_all')

    def test_delete_all_clears_in_memory_config(self):
        """KSM-962: in-memory config must be empty after delete_all."""
        self.storage.config = {'clientId': 'test'}
        result = self.storage.delete_all()
        self.assertEqual(result, {}, 'delete_all must return empty dict')
        self.assertEqual(self.storage.config, {}, 'in-memory config must be empty')


class TestKsm962AwsKmsDeleteAll(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        self.storage = _aws_kms_storage(self.config_path)

    def tearDown(self):
        self._d.cleanup()

    def test_delete_all_removes_config_file(self):
        """KSM-962: AwsKmsKeyValueStorage.delete_all() must remove the backing file."""
        self.assertTrue(os.path.exists(self.config_path),
                        'config file should exist before delete_all')
        self.storage.delete_all()
        self.assertFalse(os.path.exists(self.config_path),
                         'config file must be removed by delete_all')

    def test_delete_all_clears_in_memory_config(self):
        """KSM-962: in-memory config must be empty after delete_all."""
        self.storage.config = {'clientId': 'test'}
        result = self.storage.delete_all()
        self.assertEqual(result, {}, 'delete_all must return empty dict')
        self.assertEqual(self.storage.config, {}, 'in-memory config must be empty')


if __name__ == '__main__':
    unittest.main()
