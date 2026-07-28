"""KSM-978: All three encrypted backends must raise the KSM-972 friendly exception
("is not a valid encrypted config file") when __decrypt_buffer returns empty.

- HsmNfast: valid \xff\xff header + malformed body → __decrypt_buffer returns "" →
  json.loads("") raises bare JSONDecodeError (bypasses KSM-972 wrapper). Fix: guard before json.loads.
- AwsKms: KMS returns empty bytes → config_json == "" → only logger.error, no raise (unlike Azure).
  Fix: raise instead of log-only.

Azure already handles this correctly and serves as the reference implementation.
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# b'\xff\xff' + malformed body:
# - header matches HSM_BLOB_HEADER → is_blob=True, decrypt path entered
# - mech_len = 0xDEAD = 57005 but only 4 bytes follow → success=False → __decrypt_buffer returns ""
MALFORMED_BLOB = b'\xff\xff' + b'\xde\xad\xbe\xef\xca\xfe'

# Any non-JSON binary bytes — causes is_json() to return False → AwsKms decrypt path entered
BINARY_BYTES = b'\xff\xfe\xfd\xfc'


# ---------------------------------------------------------------------------
# nfast (stub nfpython/nfkm at import time — no hardware required)
# Mirrors the setup in test_ksm972_corrupt_config.py
# ---------------------------------------------------------------------------

_nfpython_stub = MagicMock()
_nfkm_stub = MagicMock()
_conn_stub = MagicMock()
_conn_stub.transact.return_value.status = 'OK'
_nfpython_stub.connection.return_value = _conn_stub

if 'nfpython' not in sys.modules:
    sys.modules['nfpython'] = _nfpython_stub
if 'nfkm' not in sys.modules:
    sys.modules['nfkm'] = _nfkm_stub


class TestKsm978NfastMalformedBody(unittest.TestCase):
    """HsmNfast: valid header + malformed body must raise the KSM-972 wrapper, not JSONDecodeError."""

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        with open(self.config_path, 'wb') as fh:
            fh.write(MALFORMED_BLOB)

    def tearDown(self):
        self._d.cleanup()

    def test_malformed_body_raises_typed_exception(self):
        """KSM-978: HsmNfast must raise a clear config-format Exception when __decrypt_buffer
        returns "" for a valid-header/malformed-body blob, not a bare JSONDecodeError."""
        from keeper_secrets_manager_hsm.storage_hsm_nfast import HsmNfastKeyValueStorage
        from json import JSONDecodeError

        with self.assertRaises(Exception) as ctx:
            HsmNfastKeyValueStorage('app', 'ksm', self.config_path)

        msg = str(ctx.exception)
        self.assertIn('not a valid encrypted config file', msg,
                      'Exception must identify the file as an invalid encrypted config')
        self.assertNotIsInstance(ctx.exception, JSONDecodeError,
                                 'Exception must not be a bare JSONDecodeError')


# ---------------------------------------------------------------------------
# AWS KMS (mock KMS client to return empty plaintext)
# ---------------------------------------------------------------------------

class TestKsm978AwsKmsEmptyPlaintext(unittest.TestCase):
    """AwsKms: empty __decrypt_buffer result must raise, not silently log. Parity with Azure."""

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')
        with open(self.config_path, 'wb') as fh:
            fh.write(BINARY_BYTES)

    def tearDown(self):
        self._d.cleanup()

    def _build_storage(self):
        from keeper_secrets_manager_hsm.storage_aws_kms import AwsKmsKeyValueStorage
        mk = MagicMock()
        # KMS returns empty plaintext — the empty-decrypt path (lines 150-151 pre-fix)
        mk.decrypt.return_value = {'Plaintext': b''}
        with patch('keeper_secrets_manager_hsm.storage_aws_kms.boto3') as mb:
            mb.client.return_value = mk
            return AwsKmsKeyValueStorage('alias/test', self.config_path)

    def test_empty_decrypt_raises_typed_exception(self):
        """KSM-978: AwsKmsKeyValueStorage must raise when KMS decrypts to empty bytes,
        matching Azure's behavior at the equivalent site."""
        with self.assertRaises(Exception) as ctx:
            self._build_storage()

        msg = str(ctx.exception)
        self.assertIn('not a valid encrypted config file', msg,
                      'Exception must identify the file as an invalid encrypted config')


if __name__ == '__main__':
    unittest.main()
