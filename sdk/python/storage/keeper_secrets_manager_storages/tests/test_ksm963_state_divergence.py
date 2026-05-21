"""KSM-963: self.config must not diverge from disk state when a save fails."""
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from keeper_secrets_manager_core.configkeys import ConfigKeys


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


class TestKsm963AzureStateDivergence(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        self.storage = _azure_storage(self.config_path)

    def tearDown(self):
        self._d.cleanup()

    def test_config_unchanged_after_failed_save(self):
        """KSM-963: self.config must not be mutated if the disk write fails."""
        original_config = dict(self.storage.config)

        # Make wrap_key fail on the next save attempt
        self.storage.crypto_client.wrap_key.side_effect = Exception('vault unreachable')

        with self.assertRaises(Exception):
            self.storage.set(ConfigKeys.KEY_HOSTNAME, 'new-hostname')

        self.assertEqual(self.storage.config, original_config,
                         'self.config must match disk state after a failed save')


class TestKsm963AwsKmsStateDivergence(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        self.storage = _aws_kms_storage(self.config_path)

    def tearDown(self):
        self._d.cleanup()

    def test_config_unchanged_after_failed_save(self):
        """KSM-963: self.config must not be mutated if the KMS encrypt fails."""
        from botocore.exceptions import ClientError
        original_config = dict(self.storage.config)

        self.storage.kms_client.encrypt.side_effect = ClientError(
            {'Error': {'Code': 'KMSInvalidStateException', 'Message': 'Key disabled'}},
            'Encrypt')

        with self.assertRaises(Exception):
            self.storage.set(ConfigKeys.KEY_HOSTNAME, 'new-hostname')

        self.assertEqual(self.storage.config, original_config,
                         'self.config must match disk state after a failed save')


if __name__ == '__main__':
    unittest.main()
