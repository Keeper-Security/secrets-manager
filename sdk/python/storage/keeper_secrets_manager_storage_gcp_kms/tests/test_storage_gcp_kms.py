import json
import logging
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


BLOB_HEADER = b"\xff\xff"


def _parse_blob_parts(blob):
    """Parse a KSM GCP KMS blob into its 4 length-prefixed parts: [enc_key, nonce, tag, ciphertext]."""
    pos = 2  # skip BLOB_HEADER
    parts = []
    for _ in range(4):
        part_len = int.from_bytes(blob[pos:pos + 2], "big")
        pos += 2
        parts.append(blob[pos:pos + part_len])
        pos += part_len
    return parts


def _make_blob(encrypted_key, nonce, tag, ciphertext):
    buf = bytearray(BLOB_HEADER)
    for part in [encrypted_key, nonce, tag, ciphertext]:
        buf.extend(len(part).to_bytes(2, "big"))
        buf.extend(part)
    return bytes(buf)


def make_mock_session(client_mock):
    session = MagicMock()
    session.get_crypto_client.return_value = client_mock
    session.getToken.return_value = "fake-token"
    return session


def make_key_config(resource_uri="projects/p/locations/global/keyRings/r/cryptoKeys/k"):
    from keeper_secrets_manager_storage_gcp_kms.kms_key_config import GCPKeyConfig
    cfg = MagicMock(spec=GCPKeyConfig)
    cfg.to_key_name.return_value = resource_uri
    return cfg


class TestGetKeyDetailsFailure:
    """KSM-938 regression: missing cloudkms.cryptoKeys.get permission must raise, not silently continue."""

    def test_init_raises_on_get_crypto_key_permission_denied(self, tmp_path):
        from keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms import GCPKeyValueStorage

        client_mock = MagicMock()
        client_mock.get_crypto_key.side_effect = Exception("403 Permission denied: cloudkms.cryptoKeys.get")
        session_mock = make_mock_session(client_mock)
        key_cfg = make_key_config()

        config_path = str(tmp_path / "ksm-config.json")

        with pytest.raises(Exception, match="403"):
            GCPKeyValueStorage(config_path, key_cfg, session_mock)

    def test_config_not_written_plaintext_on_init_failure(self, tmp_path):
        """When init fails due to permission denied, an existing plaintext config must not be re-written."""
        from keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms import GCPKeyValueStorage

        config_path = tmp_path / "ksm-config.json"
        original_content = json.dumps({"clientId": "test-id", "appKey": "secret"}).encode()
        config_path.write_bytes(original_content)

        client_mock = MagicMock()
        client_mock.get_crypto_key.side_effect = Exception("403 Permission denied: cloudkms.cryptoKeys.get")
        session_mock = make_mock_session(client_mock)
        key_cfg = make_key_config()

        with pytest.raises(Exception):
            GCPKeyValueStorage(str(config_path), key_cfg, session_mock)

        assert config_path.read_bytes() == original_content, (
            "Config file was modified despite init failure — credentials may have been re-written in plaintext"
        )


class TestNonce12Bytes:
    """KSM-943 regression: encrypt_buffer must use a 96-bit (12-byte) nonce per NIST SP 800-38D."""

    def test_encrypted_blob_contains_12_byte_nonce(self):
        from keeper_secrets_manager_storage_gcp_kms.utils import encrypt_buffer

        fake_enc_key = get_random_bytes(32)
        logger = logging.getLogger("test")

        with patch(
            "keeper_secrets_manager_storage_gcp_kms.utils.encrypt_data_and_validate_crc",
            return_value=fake_enc_key,
        ):
            blob = encrypt_buffer(
                is_asymmetric=False,
                message="ksm-config-test",
                crypto_client=MagicMock(),
                key_properties=MagicMock(),
                encryption_algorithm=MagicMock(),
                logger=logger,
                token=None,
            )

        assert blob[:2] == BLOB_HEADER
        parts = _parse_blob_parts(blob)
        nonce = parts[1]
        assert len(nonce) == 12, f"Expected 12-byte nonce (NIST SP 800-38D), got {len(nonce)}"


class TestBackwardCompatNonce16:
    """KSM-943: decrypt_buffer must still handle blobs encrypted with the old 16-byte nonce."""

    def test_decrypt_buffer_handles_legacy_16_byte_nonce(self):
        from keeper_secrets_manager_storage_gcp_kms.utils import decrypt_buffer

        message = '{"clientId": "legacy-id"}'
        aes_key = get_random_bytes(32)
        nonce_16 = get_random_bytes(16)

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce_16)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())

        blob = _make_blob(get_random_bytes(32), nonce_16, tag, ciphertext)
        logger = logging.getLogger("test")

        with patch(
            "keeper_secrets_manager_storage_gcp_kms.utils.decrypt_data_and_validate_crc",
            return_value=aes_key,
        ):
            result = decrypt_buffer(
                is_asymmetric=False,
                ciphertext=blob,
                crypto_client=MagicMock(),
                key_properties=MagicMock(),
                logger=logger,
                token=None,
            )

        assert result == message
