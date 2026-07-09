"""KSM-972: non-UTF8 bytes that are not the \xff\xff blob header must raise a clear
typed exception identifying the file as invalid encrypted config, not a raw
UnicodeDecodeError or JSONDecodeError."""
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# b'\xde\xad\xbe\xef\xca\xfe': not the \xff\xff HSM/Azure blob header,
# not valid UTF-8 (\xbe at position 2 is an unexpected continuation byte).
CORRUPT_BYTES = b'\xde\xad\xbe\xef\xca\xfe'


# ---------------------------------------------------------------------------
# nfast (stub out nfpython/nfkm at import time — no hardware required)
# ---------------------------------------------------------------------------

# Inject mocks before any test imports storage_hsm_nfast so the module-level
# 'import nfpython, nfkm' succeeds without the nShield SDK installed.
_nfpython_stub = MagicMock()
_nfkm_stub = MagicMock()
# __load_key calls conn.transact(); configure status='OK' so it doesn't raise.
_conn_stub = MagicMock()
_conn_stub.transact.return_value.status = 'OK'
_nfpython_stub.connection.return_value = _conn_stub

if 'nfpython' not in sys.modules:
    sys.modules['nfpython'] = _nfpython_stub
if 'nfkm' not in sys.modules:
    sys.modules['nfkm'] = _nfkm_stub


class TestKsm972NfastCorruptConfig(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        with open(self.config_path, 'wb') as fh:
            fh.write(CORRUPT_BYTES)

    def tearDown(self):
        self._d.cleanup()

    def test_non_utf8_raises_typed_exception(self):
        """KSM-972: HsmNfastKeyValueStorage must raise a clear config-format Exception,
        not a bare UnicodeDecodeError, when the config file contains non-UTF8 bytes."""
        from keeper_secrets_manager_hsm.storage_hsm_nfast import HsmNfastKeyValueStorage

        with self.assertRaises(Exception) as ctx:
            HsmNfastKeyValueStorage('app', 'ksm', self.config_path)

        msg = str(ctx.exception)
        self.assertIn('not a valid encrypted config file', msg,
                      'Exception message must identify the file as an invalid encrypted config')
        self.assertNotIn('utf-8 encoded', msg,
                         'Exception message must not mislead about UTF-8 encoding')
        self.assertNotIsInstance(ctx.exception, UnicodeDecodeError,
                                 'Exception must not be a bare UnicodeDecodeError')


# ---------------------------------------------------------------------------
# AWS KMS (identity mock — decrypt returns bytes unchanged)
# ---------------------------------------------------------------------------

class TestKsm972AwsKmsCorruptConfig(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        with open(self.config_path, 'wb') as fh:
            fh.write(CORRUPT_BYTES)

    def tearDown(self):
        self._d.cleanup()

    def _build_storage(self):
        from keeper_secrets_manager_hsm.storage_aws_kms import AwsKmsKeyValueStorage
        mk = MagicMock()
        # Identity mock: decrypt returns the raw ciphertext as plaintext.
        # For non-UTF8 input this causes plaintext.decode('utf8') to raise
        # UnicodeDecodeError inside __decrypt_buffer — which is the path KSM-972 fixes.
        mk.decrypt.side_effect = lambda **kw: {'Plaintext': kw['CiphertextBlob']}
        with patch('keeper_secrets_manager_hsm.storage_aws_kms.boto3') as mb:
            mb.client.return_value = mk
            return AwsKmsKeyValueStorage('alias/test', self.config_path)

    def test_non_utf8_raises_typed_exception(self):
        """KSM-972: AwsKmsKeyValueStorage must raise a clear config-format Exception,
        not a bare UnicodeDecodeError, when the identity mock returns non-UTF8 bytes."""
        with self.assertRaises(Exception) as ctx:
            self._build_storage()

        msg = str(ctx.exception)
        self.assertIn('not a valid encrypted config file', msg,
                      'Exception message must identify the file as an invalid encrypted config')
        self.assertNotIsInstance(ctx.exception, UnicodeDecodeError,
                                 'Exception must not be a bare UnicodeDecodeError')


# ---------------------------------------------------------------------------
# Azure (crypto mock — __decrypt_buffer returns "" for non-blob header bytes)
# ---------------------------------------------------------------------------

def _make_azure_crypto_mock():
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


class TestKsm972AzureCorruptConfig(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        with open(self.config_path, 'wb') as fh:
            fh.write(CORRUPT_BYTES)

    def tearDown(self):
        self._d.cleanup()

    def _build_storage(self):
        from keeper_secrets_manager_storage.storage_azure_keyvault import AzureKeyValueStorage
        mc = _make_azure_crypto_mock()
        with patch('keeper_secrets_manager_storage.storage_azure_keyvault.CryptographyClient', return_value=mc), \
             patch('keeper_secrets_manager_storage.storage_azure_keyvault.DefaultAzureCredential'):
            return AzureKeyValueStorage('https://vault.example.com/keys/k', self.config_path)

    def test_non_utf8_raises_typed_exception(self):
        """KSM-972: AzureKeyValueStorage must raise a clear config-format Exception,
        not a bare JSONDecodeError, when the config file contains non-UTF8 non-blob bytes."""
        with self.assertRaises(Exception) as ctx:
            self._build_storage()

        msg = str(ctx.exception)
        self.assertIn('not a valid encrypted config file', msg,
                      'Exception message must identify the file as an invalid encrypted config')
        # Confirm it's not the raw JSON parse error
        from json import JSONDecodeError
        self.assertNotIsInstance(ctx.exception, JSONDecodeError,
                                 'Exception must not be a bare JSONDecodeError')


if __name__ == '__main__':
    unittest.main()
