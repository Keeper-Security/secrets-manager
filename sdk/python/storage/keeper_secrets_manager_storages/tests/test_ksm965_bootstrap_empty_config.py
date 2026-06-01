"""KSM-965: __load_config must use 'if config is not None:' so a plaintext {} config
is recognized and re-encrypted rather than falling into the binary decrypt path."""
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from keeper_secrets_manager_storage.storage_azure_keyvault import BLOB_HEADER


def _make_azure_crypto_mock():
    """Returns a CryptographyClient mock that performs a real AES-GCM roundtrip."""
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
    return mc


class TestKsm965AzureBootstrap(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')

    def tearDown(self):
        self._d.cleanup()

    def _build_storage(self):
        from keeper_secrets_manager_storage.storage_azure_keyvault import AzureKeyValueStorage
        mc = _make_azure_crypto_mock()
        with patch('keeper_secrets_manager_storage.storage_azure_keyvault.CryptographyClient', return_value=mc), \
             patch('keeper_secrets_manager_storage.storage_azure_keyvault.DefaultAzureCredential'):
            return AzureKeyValueStorage('https://vault.example.com/keys/k', self.config_path), mc

    def test_plaintext_empty_config_loads_without_error(self):
        """KSM-965: loading a pre-existing plaintext {} must not raise."""
        with open(self.config_path, 'w') as f:
            f.write('{}')

        storage, _ = self._build_storage()
        self.assertEqual(storage.config, {})

    def test_plaintext_empty_config_triggers_re_encryption(self):
        """KSM-965: a plaintext {} must be re-encrypted (wrap_key called, unwrap_key not called)."""
        with open(self.config_path, 'w') as f:
            f.write('{}')

        _, mc = self._build_storage()

        self.assertEqual(mc.wrap_key.call_count, 1,
                         'wrap_key must be called once to re-encrypt the plaintext config')
        mc.unwrap_key.assert_not_called()

    def test_plaintext_empty_config_file_becomes_blob(self):
        """KSM-965: after first load of plaintext {}, the file must be a binary blob."""
        with open(self.config_path, 'w') as f:
            f.write('{}')

        self._build_storage()

        with open(self.config_path, 'rb') as fh:
            header = fh.read(2)
        self.assertEqual(header, BLOB_HEADER,
                         'plaintext {} must be re-encrypted on first load')


class TestKsm965AwsKmsBootstrap(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')

    def tearDown(self):
        self._d.cleanup()

    def _build_storage_with_mock(self):
        from keeper_secrets_manager_hsm.storage_aws_kms import AwsKmsKeyValueStorage
        kms_mock = MagicMock()
        kms_mock.encrypt.side_effect = lambda **kw: {'CiphertextBlob': kw['Plaintext']}
        kms_mock.decrypt.side_effect = lambda **kw: {'Plaintext': kw['CiphertextBlob']}
        with patch('keeper_secrets_manager_hsm.storage_aws_kms.boto3') as mb:
            mb.client.return_value = kms_mock
            storage = AwsKmsKeyValueStorage('alias/test', self.config_path)
        return storage, kms_mock

    def test_plaintext_empty_config_triggers_re_encryption(self):
        """KSM-965: AwsKmsKeyValueStorage must encrypt a plaintext {} on first load, not decrypt it."""
        with open(self.config_path, 'w') as f:
            f.write('{}')

        storage, kms_mock = self._build_storage_with_mock()

        kms_mock.encrypt.assert_called_once()
        kms_mock.decrypt.assert_not_called()
        self.assertEqual(storage.config, {})


if __name__ == '__main__':
    unittest.main()
