"""KSM-979: __save_config and create_config_file_if_missing must be atomic across
all three encrypted backends (Azure, AwsKms, HsmNfast).

Scenario A — no 0-byte stub on encrypt failure:
  create_config_file_if_missing opens the file before encrypting. If __encrypt_buffer
  raises, the file is left at 0 bytes. Fix: encrypt before opening any file; write to
  <path>.tmp; os.replace on success; unlink .tmp on failure.

Scenario B — original preserved when write() fails:
  __save_config opens <path> with "wb" (truncating it), then writes the encrypted blob.
  If write() fails (ENOSPC, EIO), the original config is gone. Fix: write to <path>.tmp
  first; os.replace only on success; original <path> is never touched on failure.
"""
import builtins
import errno
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# nfast (stub nfpython/nfkm at import time — no hardware required)
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


# ---------------------------------------------------------------------------
# Azure crypto helper (round-trip mock — same as test_ksm972_corrupt_config)
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


# ---------------------------------------------------------------------------
# Shared helper: intercept wb writes to config_path (or .tmp), truncate/create
# the file, but raise OSError when write() is called.
#
# Before fix: intercepts config_path directly (truncates the original).
# After fix: intercepts config_path + ".tmp" (original never opened).
# Either way the patched_open intercepts both paths, so the test distinguishes
# the two cases through the post-failure file content assertion.
# ---------------------------------------------------------------------------

def _failing_write_open(config_path):
    _real_open = builtins.open

    def _patched(path, mode='r', *args, **kwargs):
        if str(path) in (str(config_path), str(config_path) + '.tmp') and mode == 'wb':
            fh = _real_open(path, mode, *args, **kwargs)
            fh.write = MagicMock(side_effect=OSError(errno.ENOSPC, "No space left on device"))
            return fh
        return _real_open(path, mode, *args, **kwargs)

    return _patched


# ===========================================================================
# AWS KMS
# ===========================================================================

class TestKsm979AwsKms(unittest.TestCase):
    """KSM-979: AwsKmsKeyValueStorage atomic write."""

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')

    def tearDown(self):
        self._d.cleanup()

    def _make_kms_mock(self):
        mk = MagicMock()
        mk.encrypt.return_value = {'CiphertextBlob': b'\x01\x02\x03kms_ciphertext'}
        mk.decrypt.return_value = {'Plaintext': b'{}'}
        return mk

    def test_scenario_a_no_stub_on_encrypt_failure(self):
        """KSM-979 Scenario A: create_config_file_if_missing must not leave a 0-byte stub
        when __encrypt_buffer raises. Before fix: open() creates the file before encrypt,
        so a failure leaves a 0-byte stub on disk."""
        from keeper_secrets_manager_hsm.storage_aws_kms import AwsKmsKeyValueStorage
        mk = MagicMock()
        mk.encrypt.side_effect = Exception("KMS encrypt failed")
        with patch('keeper_secrets_manager_hsm.storage_aws_kms.boto3') as mb:
            mb.client.return_value = mk
            with self.assertRaises(Exception):
                AwsKmsKeyValueStorage('alias/test', self.config_path)
        self.assertFalse(
            os.path.exists(self.config_path),
            "0-byte stub left on disk after encrypt failure in create_config_file_if_missing",
        )

    def test_scenario_b_original_preserved_on_write_failure(self):
        """KSM-979 Scenario B: __save_config must leave the original config intact when
        write() fails. Before fix: open(path, 'wb') truncates the original; write failure
        leaves a 0-byte file."""
        from keeper_secrets_manager_hsm.storage_aws_kms import AwsKmsKeyValueStorage
        from keeper_secrets_manager_core.configkeys import ConfigKeys
        mk = self._make_kms_mock()
        with patch('keeper_secrets_manager_hsm.storage_aws_kms.boto3') as mb:
            mb.client.return_value = mk
            storage = AwsKmsKeyValueStorage('alias/test', self.config_path)
        original_content = open(self.config_path, 'rb').read()
        self.assertGreater(len(original_content), 0, "Setup: config file must not be empty")
        with patch('builtins.open', new=_failing_write_open(self.config_path)):
            with self.assertRaises(Exception):
                storage.set(ConfigKeys.KEY_CLIENT_ID, "new_value")
        post_content = open(self.config_path, 'rb').read()
        self.assertEqual(
            original_content, post_content,
            "File was corrupted by failed save — original content must be preserved",
        )


# ===========================================================================
# Azure KeyVault
# ===========================================================================

class TestKsm979Azure(unittest.TestCase):
    """KSM-979: AzureKeyValueStorage atomic write."""

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')

    def tearDown(self):
        self._d.cleanup()

    def _build_storage(self):
        from keeper_secrets_manager_storage.storage_azure_keyvault import AzureKeyValueStorage
        mc = _make_azure_crypto_mock()
        with patch('keeper_secrets_manager_storage.storage_azure_keyvault.CryptographyClient',
                   return_value=mc), \
             patch('keeper_secrets_manager_storage.storage_azure_keyvault.DefaultAzureCredential'):
            storage = AzureKeyValueStorage('https://vault.example.com/keys/k', self.config_path)
        return storage

    def test_scenario_a_no_stub_on_encrypt_failure(self):
        """KSM-979 Scenario A: Azure create_config_file_if_missing must not leave a 0-byte stub
        when wrap_key raises."""
        from keeper_secrets_manager_storage.storage_azure_keyvault import AzureKeyValueStorage
        mc = MagicMock()
        mc.wrap_key.side_effect = Exception("Azure KV wrap_key failed")
        with patch('keeper_secrets_manager_storage.storage_azure_keyvault.CryptographyClient',
                   return_value=mc), \
             patch('keeper_secrets_manager_storage.storage_azure_keyvault.DefaultAzureCredential'):
            with self.assertRaises(Exception):
                AzureKeyValueStorage('https://vault.example.com/keys/k', self.config_path)
        self.assertFalse(
            os.path.exists(self.config_path),
            "0-byte stub left on disk after encrypt failure in create_config_file_if_missing",
        )

    def test_scenario_b_original_preserved_on_write_failure(self):
        """KSM-979 Scenario B: Azure __save_config must leave the original config intact
        when write() fails."""
        from keeper_secrets_manager_core.configkeys import ConfigKeys
        storage = self._build_storage()
        original_content = open(self.config_path, 'rb').read()
        self.assertGreater(len(original_content), 0, "Setup: config file must not be empty")
        with patch('builtins.open', new=_failing_write_open(self.config_path)):
            with self.assertRaises(Exception):
                storage.set(ConfigKeys.KEY_CLIENT_ID, "new_value")
        post_content = open(self.config_path, 'rb').read()
        self.assertEqual(
            original_content, post_content,
            "File was corrupted by failed save — original content must be preserved",
        )


# ===========================================================================
# HsmNfast
# ===========================================================================

class TestKsm979HsmNfast(unittest.TestCase):
    """KSM-979: HsmNfastKeyValueStorage atomic write."""

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self._d.name, 'cfg.json')

    def tearDown(self):
        self._d.cleanup()

    def test_scenario_a_no_stub_on_encrypt_failure(self):
        """KSM-979 Scenario A: HsmNfast create_config_file_if_missing must not leave a 0-byte
        stub when __encrypt_buffer raises."""
        from keeper_secrets_manager_hsm.storage_hsm_nfast import HsmNfastKeyValueStorage
        with patch.object(HsmNfastKeyValueStorage,
                          '_HsmNfastKeyValueStorage__encrypt_buffer',
                          side_effect=Exception("HSM encrypt failed")):
            with self.assertRaises(Exception):
                HsmNfastKeyValueStorage('app', 'ksm', self.config_path)
        self.assertFalse(
            os.path.exists(self.config_path),
            "0-byte stub left on disk after encrypt failure in create_config_file_if_missing",
        )

    def test_scenario_b_original_preserved_on_write_failure(self):
        """KSM-979 Scenario B: HsmNfast __save_config must leave the original config intact
        when write() fails. Uses name-mangled patches since nfpython is hardware-only."""
        from keeper_secrets_manager_hsm.storage_hsm_nfast import HsmNfastKeyValueStorage
        from keeper_secrets_manager_core.configkeys import ConfigKeys
        FAKE_BLOB = b'\xff\xff\x00\x01\x02\x03'
        with patch.object(HsmNfastKeyValueStorage,
                          '_HsmNfastKeyValueStorage__encrypt_buffer',
                          return_value=FAKE_BLOB), \
             patch.object(HsmNfastKeyValueStorage,
                          '_HsmNfastKeyValueStorage__decrypt_buffer',
                          return_value='{}'):
            storage = HsmNfastKeyValueStorage('app', 'ksm', self.config_path)
            original_content = open(self.config_path, 'rb').read()
            self.assertGreater(len(original_content), 0, "Setup: config file must not be empty")
            with patch('builtins.open', new=_failing_write_open(self.config_path)):
                with self.assertRaises(Exception):
                    storage.set(ConfigKeys.KEY_CLIENT_ID, "new_value")
        post_content = open(self.config_path, 'rb').read()
        self.assertEqual(
            original_content, post_content,
            "File was corrupted by failed save — original content must be preserved",
        )


if __name__ == '__main__':
    unittest.main()
