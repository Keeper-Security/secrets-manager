import json
import logging
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import google_crc32c
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


def _make_storage_stub(config=None, config_file_location=None):
    """Return a GCPKeyValueStorage instance with __init__ bypassed and state set directly."""
    import threading
    from keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms import GCPKeyValueStorage
    from keeper_secrets_manager_storage_gcp_kms.constants import KeyPurpose
    with patch.object(GCPKeyValueStorage, '__init__', return_value=None):
        storage = GCPKeyValueStorage.__new__(GCPKeyValueStorage)
    storage.config = config if config is not None else {}
    storage.config_file_location = config_file_location or ""
    storage.logger = logging.getLogger("test")
    storage.is_asymmetric = False
    storage.key_purpose_details = KeyPurpose.ENCRYPT_DECRYPT
    storage.gcp_session_config = MagicMock()
    storage.crypto_client = MagicMock()
    storage.gcp_key_config = MagicMock()
    storage.encryption_algorithm = MagicMock()
    storage._lock = threading.RLock()
    return storage


class TestReadStorageCopyIsolation:
    """KSM-944: read_storage() must return a copy, not a live dict reference."""

    def test_returned_dict_is_not_live_reference(self):
        storage = _make_storage_stub(config={"clientId": "original", "appKey": "secret"})
        result = storage.read_storage()
        result["clientId"] = "hacked"
        assert storage.config["clientId"] == "original", (
            "read_storage() returned a live reference — caller mutation changed internal state"
        )

    def test_copy_contains_all_keys(self):
        data = {"clientId": "test-id", "appKey": "key", "hostname": "host"}
        storage = _make_storage_stub(config=data)
        result = storage.read_storage()
        assert result == data


class TestDecryptConfigDefaultAutosaveFalse:
    """KSM-944: decrypt_config() must not write plaintext to disk when called without arguments."""

    def _write_fake_blob(self, path):
        aes_key = get_random_bytes(32)
        nonce = get_random_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(b"{}")
        blob = _make_blob(get_random_bytes(32), nonce, tag, ciphertext)
        path.write_bytes(blob)
        return blob

    def test_default_does_not_overwrite_file(self, tmp_path):
        config_path = tmp_path / "ksm-config.json"
        original_blob = self._write_fake_blob(config_path)

        storage = _make_storage_stub(config_file_location=str(config_path))
        plaintext = '{"clientId": "test-id"}'

        with patch("keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.decrypt_buffer", return_value=plaintext):
            result = storage.decrypt_config()

        assert result == plaintext
        assert config_path.read_bytes() == original_blob, (
            "decrypt_config() with default args wrote plaintext to disk — credentials exposed"
        )

    def test_autosave_true_writes_plaintext(self, tmp_path):
        config_path = tmp_path / "ksm-config.json"
        self._write_fake_blob(config_path)

        storage = _make_storage_stub(config_file_location=str(config_path))
        plaintext = '{"clientId": "test-id"}'

        with patch("keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.decrypt_buffer", return_value=plaintext):
            result = storage.decrypt_config(autosave=True)

        assert result == plaintext
        assert config_path.read_text() == plaintext


class TestSymmetricDecryptVersionPinning:
    """KSM-945 regression: symmetric client.decrypt must use the version-pinned key name."""

    def test_client_decrypt_called_with_versioned_key_name(self):
        from keeper_secrets_manager_storage_gcp_kms.utils import decrypt_data_and_validate_crc

        versioned_name = "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
        unversioned_name = "projects/p/locations/global/keyRings/r/cryptoKeys/k"

        key_props = MagicMock()
        key_props.to_resource_name.return_value = versioned_name
        key_props.to_key_name.return_value = unversioned_name

        fake_plaintext = get_random_bytes(32)
        fake_plaintext_crc = google_crc32c.value(fake_plaintext)

        client = MagicMock()
        client.decrypt.return_value = MagicMock(
            plaintext=fake_plaintext,
            plaintext_crc32c=fake_plaintext_crc,
        )

        options = {
            "ciphertext": get_random_bytes(32),
            "crypto_client": client,
            "key_properties": key_props,
            "is_asymmetric": False,
            "token": None,
            "logger": logging.getLogger("test"),
        }

        decrypt_data_and_validate_crc(options)

        called_name = client.decrypt.call_args[1]["request"].name
        assert called_name == versioned_name, (
            f"Expected version-pinned key name, got: {called_name}"
        )
        assert called_name != unversioned_name


class TestDeleteLastKeyPersists:
    """KSM-944 regression: delete() of the last config key must clear internal state.

    Before the fix, delete() went through read_storage() (a copy), so del config[kv]
    only mutated the copy. __save_config({}) then hit the falsy-check and skipped
    updating self.config, silently leaving the deleted key in memory and on disk.
    """

    def test_delete_last_key_clears_internal_state(self, tmp_path):
        from keeper_secrets_manager_core.configkeys import ConfigKeys

        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"placeholder")

        storage = _make_storage_stub(
            config={"clientId": "test-id"},
            config_file_location=str(config_path),
        )
        storage.last_saved_config_hash = "old-hash"

        with patch(
            "keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.encrypt_buffer",
            return_value=b"fake-blob",
        ):
            storage.delete(ConfigKeys.KEY_CLIENT_ID)

        assert storage.config == {}, (
            "delete() of the last config key left internal state non-empty — deletion was silently lost"
        )


class TestConcurrentSet:
    """KSM-946 regression: concurrent set() calls must not raise or corrupt internal state."""

    def test_concurrent_set_no_data_loss(self, tmp_path):
        import threading
        from keeper_secrets_manager_core.configkeys import ConfigKeys

        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"placeholder")

        storage = _make_storage_stub(
            config={"clientId": "initial"},
            config_file_location=str(config_path),
        )
        storage.last_saved_config_hash = ""

        errors = []

        with patch(
            "keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.encrypt_buffer",
            return_value=b"fake-blob",
        ), patch.object(storage, "create_config_file_if_missing"):
            barrier = threading.Barrier(2)

            def writer(value):
                try:
                    barrier.wait()
                    for _ in range(200):
                        storage.set(ConfigKeys.KEY_CLIENT_ID, value)
                except Exception as e:
                    errors.append(e)

            t1 = threading.Thread(target=writer, args=("value_A",))
            t2 = threading.Thread(target=writer, args=("value_B",))
            t1.start()
            t2.start()
            t1.join()
            t2.join()

        assert not errors, f"Concurrent set() raised: {errors}"
        final = storage.config.get("clientId")
        assert final in ("value_A", "value_B"), f"Config corrupted: {storage.config}"
