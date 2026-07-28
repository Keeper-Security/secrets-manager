"""KSM-964: decrypt_config() must default to autosave=False to avoid destroying encryption."""
import inspect
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from keeper_secrets_manager_storage.storage_azure_keyvault import BLOB_HEADER


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


class TestKsm964AzureDecryptConfig(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        self.storage = _azure_storage(self.config_path)

    def tearDown(self):
        self._d.cleanup()

    def test_default_autosave_is_false(self):
        """KSM-964: AzureKeyValueStorage.decrypt_config() must default to autosave=False."""
        sig = inspect.signature(self.storage.decrypt_config)
        default = sig.parameters['autosave'].default
        self.assertIs(default, False,
                      f'autosave must default to False, got {default!r}')

    def test_decrypt_config_no_args_does_not_overwrite_file(self):
        """KSM-964: decrypt_config() with no args must not overwrite the encrypted blob."""
        with open(self.config_path, 'rb') as fh:
            before = fh.read()
        self.assertEqual(before[:2], BLOB_HEADER,
                         'config file should be an encrypted blob before decrypt_config')

        self.storage.decrypt_config()  # no args → should NOT overwrite

        with open(self.config_path, 'rb') as fh:
            after = fh.read()
        self.assertEqual(before, after,
                         'decrypt_config() with no args must leave the encrypted file unchanged')


class TestKsm964AwsKmsDecryptConfig(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        self.storage = _aws_kms_storage(self.config_path)

    def tearDown(self):
        self._d.cleanup()

    def test_default_autosave_is_false(self):
        """KSM-964: AwsKmsKeyValueStorage.decrypt_config() must default to autosave=False."""
        sig = inspect.signature(self.storage.decrypt_config)
        default = sig.parameters['autosave'].default
        self.assertIs(default, False,
                      f'autosave must default to False, got {default!r}')


if __name__ == '__main__':
    unittest.main()
