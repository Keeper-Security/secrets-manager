"""KSM-960: regression tests — SHA-256 change-detection hash + 12-byte AES-GCM nonce."""
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


def _aws_secret_storage():
    from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider
    with patch.object(AwsConfigProvider, 'from_ec2instance_config'):
        return AwsSecretStorage('test-secret')


def _nonce_len_from_blob(blob: bytes) -> int:
    """Parse the Azure encrypted blob and return the nonce length (chunk 2)."""
    assert blob[:2] == BLOB_HEADER, 'not an Azure encrypted blob'
    pos = 2
    for chunk_idx in range(1, 3):  # parse chunks 1 (encrypted_key) and 2 (nonce)
        chunk_len = int.from_bytes(blob[pos:pos + 2], 'big')
        pos += 2
        if chunk_idx == 2:
            return chunk_len
        pos += chunk_len
    raise ValueError('blob too short')


# ---------------------------------------------------------------------------
# Hash function tests — all backends
# ---------------------------------------------------------------------------

class TestKsm960AzureHash(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        self.storage = _azure_storage(self.config_path)

    def tearDown(self):
        self._d.cleanup()

    def test_hash_is_sha256(self):
        """KSM-960: change-detection hash must be SHA-256 (64 hex chars), not MD5 (32)."""
        h = self.storage.last_saved_config_hash
        self.assertEqual(len(h), 64,
                         f'expected 64-char SHA-256 digest, got {len(h)}-char: {h!r}')


class TestKsm960AwsKmsHash(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        self.storage = _aws_kms_storage(self.config_path)

    def tearDown(self):
        self._d.cleanup()

    def test_hash_is_sha256(self):
        """KSM-960: change-detection hash must be SHA-256 (64 hex chars), not MD5 (32)."""
        h = self.storage.last_saved_config_hash
        self.assertEqual(len(h), 64,
                         f'expected 64-char SHA-256 digest, got {len(h)}-char: {h!r}')


class TestKsm960AwsSecretHash(unittest.TestCase):
    def setUp(self):
        self.storage = _aws_secret_storage()
        # Manually set config + hash to simulate a prior save using SHA-256
        import hashlib, json
        self.storage.config = {'clientId': 'test'}
        cfg_json = json.dumps(self.storage.config, indent=4, sort_keys=True)
        self.storage.last_saved_config_hash = hashlib.md5(cfg_json.encode()).hexdigest()

    def test_save_produces_sha256_hash(self):
        """KSM-960: __save_config must store a SHA-256 hash after writing."""
        from unittest.mock import MagicMock
        self.storage.provider.write_config = MagicMock(return_value='')
        # Force a save by changing the config
        import json
        new_cfg = {'clientId': 'changed'}
        with patch.object(self.storage, '_AwsSecretStorage__save_config',
                          wraps=self.storage._AwsSecretStorage__save_config):
            self.storage.config = new_cfg
            self.storage.last_saved_config_hash = ''  # force save
            self.storage.save_storage(new_cfg)
        h = self.storage.last_saved_config_hash
        self.assertEqual(len(h), 64,
                         f'expected 64-char SHA-256 digest after save, got {len(h)}-char: {h!r}')


# ---------------------------------------------------------------------------
# Azure-specific: AES-GCM nonce must be 12 bytes
# ---------------------------------------------------------------------------

class TestKsm960AzureNonce(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        self.storage = _azure_storage(self.config_path)

    def tearDown(self):
        self._d.cleanup()

    def test_nonce_is_12_bytes(self):
        """KSM-960: AES-GCM nonce must be 96-bit (12 bytes) per NIST SP 800-38D."""
        with open(self.config_path, 'rb') as fh:
            blob = fh.read()
        nonce_len = _nonce_len_from_blob(blob)
        self.assertEqual(nonce_len, 12, f'nonce must be 12 bytes, got {nonce_len}')


if __name__ == '__main__':
    unittest.main()
