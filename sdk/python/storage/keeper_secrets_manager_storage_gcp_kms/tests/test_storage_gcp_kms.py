import json
import logging
import os
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
    """Return a GCPKeyValueStorage instance with __init__ bypassed and state set directly.

    `cls.__new__(cls)` allocates a bare instance without invoking __init__, so no patch
    of __init__ is needed — only `cls(...)` would trigger __init__ via type.__call__.
    """
    import threading
    from keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms import GCPKeyValueStorage
    from keeper_secrets_manager_storage_gcp_kms.constants import KeyPurpose
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


class TestSymmetricDecryptUsesUnversionedName:
    """KSM-945: GCP cryptoKeys.decrypt requires the unversioned CryptoKey name;
    the version is read from the ciphertext envelope. A versioned CryptoKeyVersion
    path is rejected with INVALID_ARGUMENT. Only asymmetric_decrypt takes a version.
    """

    VERSIONED = "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    UNVERSIONED = "projects/p/locations/global/keyRings/r/cryptoKeys/k"

    def _decrypt_options(self, is_asymmetric, client):
        key_props = MagicMock()
        key_props.to_resource_name.return_value = self.VERSIONED
        key_props.to_key_name.return_value = self.UNVERSIONED
        return {
            "ciphertext": get_random_bytes(32),
            "crypto_client": client,
            "key_properties": key_props,
            "is_asymmetric": is_asymmetric,
            "token": None,
            "logger": logging.getLogger("test"),
        }

    def _make_client(self, attr):
        fake_plaintext = get_random_bytes(32)
        fake_plaintext_crc = google_crc32c.value(fake_plaintext)
        client = MagicMock()
        getattr(client, attr).return_value = MagicMock(
            plaintext=fake_plaintext,
            plaintext_crc32c=fake_plaintext_crc,
        )
        return client

    def test_symmetric_decrypt_uses_unversioned_key_name(self):
        from keeper_secrets_manager_storage_gcp_kms.utils import decrypt_data_and_validate_crc

        client = self._make_client("decrypt")
        decrypt_data_and_validate_crc(self._decrypt_options(False, client))

        called_name = client.decrypt.call_args[1]["request"].name
        assert called_name == self.UNVERSIONED, (
            f"symmetric decrypt must use unversioned CryptoKey name, got: {called_name}"
        )
        assert "cryptoKeyVersions" not in called_name

    def test_asymmetric_decrypt_uses_versioned_resource_name(self):
        from keeper_secrets_manager_storage_gcp_kms.utils import decrypt_data_and_validate_crc

        client = self._make_client("asymmetric_decrypt")
        decrypt_data_and_validate_crc(self._decrypt_options(True, client))

        called_name = client.asymmetric_decrypt.call_args[1]["request"].name
        assert called_name == self.VERSIONED, (
            f"asymmetric decrypt must use versioned CryptoKeyVersion name, got: {called_name}"
        )


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
    """KSM-946 regression: concurrent set() calls must not raise or lose writes."""

    def test_concurrent_set_no_data_loss(self, tmp_path):
        import threading
        from keeper_secrets_manager_core.configkeys import ConfigKeys

        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"placeholder")

        # Two threads write to different keys concurrently. Without RLock, one thread's
        # read-mutate-save cycle overwrites the other's key entirely. With RLock each
        # cycle is atomic, so both keys survive.
        storage = _make_storage_stub(
            config={},
            config_file_location=str(config_path),
        )
        storage.last_saved_config_hash = ""

        errors = []

        with patch(
            "keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.encrypt_buffer",
            return_value=b"fake-blob",
        ), patch.object(storage, "create_config_file_if_missing"):
            barrier = threading.Barrier(2)

            def writer_a():
                try:
                    barrier.wait()
                    for _ in range(200):
                        storage.set(ConfigKeys.KEY_CLIENT_ID, "value_A")
                except Exception as e:
                    errors.append(e)

            def writer_b():
                try:
                    barrier.wait()
                    for _ in range(200):
                        storage.set(ConfigKeys.KEY_APP_KEY, "value_B")
                except Exception as e:
                    errors.append(e)

            t1 = threading.Thread(target=writer_a)
            t2 = threading.Thread(target=writer_b)
            t1.start()
            t2.start()
            t1.join()
            t2.join()

        assert not errors, f"Concurrent set() raised: {errors}"
        assert storage.config.get("clientId") == "value_A", (
            f"KEY_CLIENT_ID lost to concurrent set() race: config={storage.config}"
        )
        assert storage.config.get("appKey") == "value_B", (
            f"KEY_APP_KEY lost to concurrent set() race: config={storage.config}"
        )


class TestChangeKeyRaisesOnFailure:
    """KSM-942 regression: change_key() must raise (not return True) when re-encryption fails,
    and the active key config (gcp_key_config) must be restored so the storage remains functional.
    """

    def test_change_key_raises_when_get_key_details_fails(self):
        from keeper_secrets_manager_storage_gcp_kms.kms_key_config import GCPKeyConfig

        old_key_config = MagicMock(spec=GCPKeyConfig)
        new_key_config = MagicMock(spec=GCPKeyConfig)

        storage = _make_storage_stub(config={"clientId": "test-id"})
        storage.gcp_key_config = old_key_config

        with patch.object(
            storage, "get_key_details",
            side_effect=Exception("403 new key permission denied"),
        ):
            with pytest.raises(Exception):
                storage.change_key(new_key_config)

        assert storage.gcp_key_config is old_key_config, (
            "change_key() did not restore the original key config after failure"
        )

    def test_change_key_raises_when_save_fails(self, tmp_path):
        from keeper_secrets_manager_storage_gcp_kms.kms_key_config import GCPKeyConfig
        from keeper_secrets_manager_storage_gcp_kms.constants import KeyPurpose

        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"placeholder")

        old_key_config = MagicMock(spec=GCPKeyConfig)
        new_key_config = MagicMock(spec=GCPKeyConfig)
        new_key_config.to_key_name.return_value = "projects/p/locations/global/keyRings/r/cryptoKeys/new-key"

        storage = _make_storage_stub(
            config={"clientId": "test-id"},
            config_file_location=str(config_path),
        )
        storage.gcp_key_config = old_key_config
        old_algo = storage.encryption_algorithm
        storage.last_saved_config_hash = ""

        # get_crypto_key returns an asymmetric key so get_key_details mutates
        # is_asymmetric, key_purpose_details, and encryption_algorithm before the
        # save step fails — verifying that the rollback covers all four attributes.
        asymmetric_response = MagicMock()
        asymmetric_response.purpose = KeyPurpose.ASYMMETRIC_DECRYPT
        asymmetric_response.version_template.algorithm = MagicMock()
        storage.crypto_client.get_crypto_key.return_value = asymmetric_response

        with patch(
            "keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.encrypt_buffer",
            side_effect=Exception("KMS save failed"),
        ), patch.object(storage, "create_config_file_if_missing"):
            with pytest.raises(Exception):
                storage.change_key(new_key_config)

        assert storage.gcp_key_config is old_key_config, (
            "change_key() did not restore gcp_key_config after save failure"
        )
        assert storage.is_asymmetric is False, (
            "change_key() did not restore is_asymmetric after save failure"
        )
        assert storage.key_purpose_details == KeyPurpose.ENCRYPT_DECRYPT, (
            "change_key() did not restore key_purpose_details after save failure"
        )
        assert storage.encryption_algorithm is old_algo, (
            "change_key() did not restore encryption_algorithm after save failure"
        )


class TestEncryptBufferPropagatesKMSError:
    """KSM-939 regression: encrypt_buffer() must raise on KMS failure, not return empty bytes.
    __save_config() must propagate the error so callers (set, save_storage) know the write failed.
    """

    def test_encrypt_buffer_raises_on_kms_failure(self):
        from keeper_secrets_manager_storage_gcp_kms.utils import encrypt_buffer

        logger = logging.getLogger("test")

        with patch(
            "keeper_secrets_manager_storage_gcp_kms.utils.encrypt_data_and_validate_crc",
            side_effect=Exception("403 KMS permission denied"),
        ):
            with pytest.raises(Exception, match="403"):
                encrypt_buffer(
                    is_asymmetric=False,
                    message="ksm-config-test",
                    crypto_client=MagicMock(),
                    key_properties=MagicMock(),
                    encryption_algorithm=MagicMock(),
                    logger=logger,
                    token=None,
                )

    def test_set_raises_when_kms_is_unavailable(self, tmp_path):
        from keeper_secrets_manager_core.configkeys import ConfigKeys

        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"placeholder")

        storage = _make_storage_stub(
            config={"clientId": "original"},
            config_file_location=str(config_path),
        )
        storage.last_saved_config_hash = ""

        with patch(
            "keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.encrypt_buffer",
            side_effect=Exception("KMS unavailable"),
        ), patch.object(storage, "create_config_file_if_missing"):
            with pytest.raises(Exception, match="KMS unavailable"):
                storage.set(ConfigKeys.KEY_CLIENT_ID, "new-value")

        assert storage.config == {"clientId": "original"}, (
            "set() raised but self.config was mutated — in-memory and on-disk state diverged"
        )

    def test_delete_does_not_mutate_on_kms_failure(self, tmp_path):
        from keeper_secrets_manager_core.configkeys import ConfigKeys

        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"placeholder")

        storage = _make_storage_stub(
            config={"clientId": "original", "appKey": "secret"},
            config_file_location=str(config_path),
        )
        storage.last_saved_config_hash = ""

        with patch(
            "keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.encrypt_buffer",
            side_effect=Exception("KMS unavailable"),
        ), patch.object(storage, "create_config_file_if_missing"):
            with pytest.raises(Exception, match="KMS unavailable"):
                storage.delete(ConfigKeys.KEY_CLIENT_ID)

        assert storage.config == {"clientId": "original", "appKey": "secret"}, (
            "delete() raised but self.config was mutated — in-memory and on-disk state diverged"
        )


class TestDeleteAllWipesDisk:
    """KSM-940 regression: delete_all() must remove the config file from disk so no credential
    bytes remain readable; file removal happens before clearing in-memory state so a failed
    os.remove() does not leave both sides inconsistent.
    """

    def test_delete_all_removes_config_file(self, tmp_path):
        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"fake-encrypted-credentials-blob")

        storage = _make_storage_stub(
            config={"clientId": "test-id", "appKey": "secret"},
            config_file_location=str(config_path),
        )

        storage.delete_all()

        assert not config_path.exists(), (
            "delete_all() left the config file on disk — credentials may still be readable"
        )
        assert storage.config == {}

    def test_delete_all_removes_file_before_clearing_memory(self, tmp_path):
        """os.remove() must run before self.config.clear() so that a failed remove cannot
        self-heal via read_storage() re-loading credentials from the untouched file."""
        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"fake-encrypted-credentials-blob")

        storage = _make_storage_stub(
            config={"clientId": "test-id", "appKey": "secret"},
            config_file_location=str(config_path),
        )

        config_at_remove_time = {}

        def recording_remove(path):
            config_at_remove_time.update(storage.config)

        with patch("keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.os.remove", side_effect=recording_remove), \
             patch("keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.os.path.exists", return_value=True):
            storage.delete_all()

        assert config_at_remove_time == {"clientId": "test-id", "appKey": "secret"}, (
            "os.remove() ran after config.clear() — config was already empty at removal time"
        )


class TestSetRaisesOnReadOnlyFile:
    """KSM-941 regression: set() must raise when the disk write fails due to file permissions.
    In-memory and on-disk state must not silently diverge.
    """

    @pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        reason="chmod 0o444 does not block writes when running as root",
    )
    def test_set_raises_on_permission_error(self, tmp_path):
        from keeper_secrets_manager_core.configkeys import ConfigKeys

        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"placeholder")

        storage = _make_storage_stub(
            config={"clientId": "original"},
            config_file_location=str(config_path),
        )
        storage.last_saved_config_hash = ""

        config_path.chmod(0o444)
        try:
            with patch(
                "keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.encrypt_buffer",
                return_value=b"fake-blob",
            ), patch.object(storage, "create_config_file_if_missing"):
                with pytest.raises((PermissionError, OSError)):
                    storage.set(ConfigKeys.KEY_CLIENT_ID, "new-value")
        finally:
            config_path.chmod(0o644)


class TestLoadConfigEmptyDictBootstrap:
    """KSM-948 regression: load_config() must leave self.config as a dict (never None)
    when the on-disk file's parsed JSON is an empty dict — the documented fresh-install
    bootstrap pattern from the README."""

    def test_init_with_plaintext_empty_dict_file_leaves_config_as_dict(self, tmp_path):
        from keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms import GCPKeyValueStorage
        from keeper_secrets_manager_storage_gcp_kms.constants import KeyPurpose
        from keeper_secrets_manager_core.configkeys import ConfigKeys

        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"{}")

        key_obj = MagicMock()
        key_obj.purpose = KeyPurpose.ENCRYPT_DECRYPT
        key_obj.version_template.algorithm = MagicMock()
        client_mock = MagicMock()
        client_mock.get_crypto_key.return_value = key_obj
        session_mock = make_mock_session(client_mock)
        key_cfg = make_key_config()

        with patch(
            "keeper_secrets_manager_storage_gcp_kms.storage_gcp_kms.encrypt_buffer",
            return_value=b"fake-blob",
        ):
            storage = GCPKeyValueStorage(str(config_path), key_cfg, session_mock)

            assert storage.config == {}, (
                "KSM-948: load_config() left self.config as None after empty-dict bootstrap"
            )

            # Subsequent operations must not crash on dict(None).
            storage.set(ConfigKeys.KEY_CLIENT_ID, "abc")

        assert storage.config[ConfigKeys.KEY_CLIENT_ID.value] == "abc"
