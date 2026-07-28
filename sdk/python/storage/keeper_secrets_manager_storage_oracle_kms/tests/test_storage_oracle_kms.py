import base64
import json
import logging
import os
import threading
from unittest.mock import MagicMock, patch

import pytest
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


BLOB_HEADER = b"\xff\xff"


def _parse_blob_parts(blob):
    """Parse a KSM Oracle KMS blob into its 4 length-prefixed parts: [enc_key, nonce, tag, ciphertext]."""
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


def _make_kms_encrypt_response(plaintext_bytes):
    """OCI KmsCryptoClient.encrypt() returns an object with .data.ciphertext as base64 string."""
    resp = MagicMock()
    resp.data.ciphertext = base64.b64encode(plaintext_bytes).decode()
    return resp


def _make_kms_decrypt_response(plaintext_bytes):
    """OCI KmsCryptoClient.decrypt() returns an object with .data.plaintext as base64 string."""
    resp = MagicMock()
    resp.data.plaintext = base64.b64encode(plaintext_bytes).decode()
    return resp


def _make_management_response(algorithm="AES"):
    """OCI KmsManagementClient.get_key() returns an object with .data.key_shape.algorithm."""
    from oci.key_management.models import KeyShape
    resp = MagicMock()
    if algorithm == "AES":
        resp.data.key_shape.algorithm = KeyShape.ALGORITHM_AES
    elif algorithm == "RSA":
        resp.data.key_shape.algorithm = KeyShape.ALGORITHM_RSA
    else:
        resp.data.key_shape.algorithm = algorithm
    return resp


class TestGetKeyDetailsFailure:
    """KSM-950 regression: KMS get_key permission denial / failure must raise at init,
    not silently leave plaintext credentials on disk."""

    def test_init_raises_on_get_key_permission_denied(self, tmp_path):
        from keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage import OracleKeyValueStorage

        config_path = str(tmp_path / "ksm-config.json")

        with patch("keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.OciKmsClient") as oci_client_cls:
            crypto_client = MagicMock()
            mgmt_client = MagicMock()
            mgmt_client.get_key.side_effect = Exception("NotAuthorizedOrNotFound: get_key denied")
            oci_client_cls.return_value.get_crypto_client.return_value = crypto_client
            oci_client_cls.return_value.get_management_client.return_value = mgmt_client

            with pytest.raises(Exception, match="NotAuthorizedOrNotFound"):
                OracleKeyValueStorage(
                    key_id="ocid1.key.oc1..fake",
                    key_version=None,
                    config_file_location=config_path,
                    oci_session_config=MagicMock(),
                    logger=logging.getLogger("test"),
                )

    def test_config_not_written_plaintext_on_init_failure(self, tmp_path):
        """When init fails due to KMS permission denial, an existing plaintext config must not be re-written."""
        from keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage import OracleKeyValueStorage

        config_path = tmp_path / "ksm-config.json"
        original_content = json.dumps({"clientId": "test-id", "appKey": "secret"}).encode()
        config_path.write_bytes(original_content)

        with patch("keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.OciKmsClient") as oci_client_cls:
            mgmt_client = MagicMock()
            mgmt_client.get_key.side_effect = Exception("NotAuthorizedOrNotFound: get_key denied")
            oci_client_cls.return_value.get_crypto_client.return_value = MagicMock()
            oci_client_cls.return_value.get_management_client.return_value = mgmt_client

            with pytest.raises(Exception):
                OracleKeyValueStorage(
                    key_id="ocid1.key.oc1..fake",
                    key_version=None,
                    config_file_location=str(config_path),
                    oci_session_config=MagicMock(),
                    logger=logging.getLogger("test"),
                )

        assert config_path.read_bytes() == original_content, (
            "Config file was modified despite init failure — credentials may have been re-written in plaintext"
        )

    def test_init_does_not_write_plaintext_brace_before_encrypt(self, tmp_path):
        """KSM-950: create_config_file_if_missing must never write plaintext b'{}' before encryption."""
        from keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage import OracleKeyValueStorage

        config_path = tmp_path / "ksm-config.json"
        # File does not exist; init should never create it as plaintext

        with patch("keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.OciKmsClient") as oci_client_cls, \
             patch("keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.encrypt_buffer",
                   side_effect=Exception("KMS denied")):
            crypto_client = MagicMock()
            mgmt_client = MagicMock()
            mgmt_client.get_key.return_value = _make_management_response("AES")
            oci_client_cls.return_value.get_crypto_client.return_value = crypto_client
            oci_client_cls.return_value.get_management_client.return_value = mgmt_client

            with pytest.raises(Exception):
                OracleKeyValueStorage(
                    key_id="ocid1.key.oc1..fake",
                    key_version=None,
                    config_file_location=str(config_path),
                    oci_session_config=MagicMock(),
                    logger=logging.getLogger("test"),
                )

        # If create_config_file_if_missing wrote plaintext "{}" first, then encryption failed,
        # the file would now contain b"{}" plaintext.
        if config_path.exists():
            assert config_path.read_bytes() != b"{}", (
                "Plaintext '{}' left on disk after KMS encrypt failure — KSM-950 regression"
            )


class TestNonce12Bytes:
    """KSM-954 regression: encrypt_buffer must use a 96-bit (12-byte) nonce per NIST SP 800-38D."""

    def test_encrypted_blob_contains_12_byte_nonce(self):
        from keeper_secrets_manager_storage_oracle_kms.utils import encrypt_buffer

        fake_enc_key = get_random_bytes(32)
        logger = logging.getLogger("test")

        crypto_client = MagicMock()
        crypto_client.encrypt.return_value = _make_kms_encrypt_response(fake_enc_key)

        blob = encrypt_buffer(
            key_id="ocid1.key.oc1..fake",
            message="ksm-config-test",
            crypto_client=crypto_client,
            key_version_id=None,
            is_asymmetric=False,
            logger=logger,
        )

        assert blob[:2] == BLOB_HEADER
        parts = _parse_blob_parts(blob)
        nonce = parts[1]
        assert len(nonce) == 12, f"Expected 12-byte nonce (NIST SP 800-38D), got {len(nonce)}"


class TestBackwardCompatNonce16:
    """KSM-954: decrypt_buffer must still handle blobs encrypted with the old 16-byte nonce."""

    def test_decrypt_buffer_handles_legacy_16_byte_nonce(self):
        from keeper_secrets_manager_storage_oracle_kms.utils import decrypt_buffer

        message = '{"clientId": "legacy-id"}'
        aes_key = get_random_bytes(32)
        nonce_16 = get_random_bytes(16)

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce_16)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())

        blob = _make_blob(get_random_bytes(32), nonce_16, tag, ciphertext)
        logger = logging.getLogger("test")

        crypto_client = MagicMock()
        crypto_client.decrypt.return_value = _make_kms_decrypt_response(aes_key)

        result = decrypt_buffer(
            key_id="ocid1.key.oc1..fake",
            ciphertext=blob,
            crypto_client=crypto_client,
            key_version_id=None,
            is_asymmetric=False,
            logger=logger,
        )

        assert result == message


class TestSha256Hashing:
    """KSM-954: config-change hashing must use SHA-256, not MD5."""

    def test_save_config_uses_sha256_not_md5(self):
        import hashlib
        storage = _make_storage_stub(config={})
        storage.config_file_location = "/tmp/does-not-matter"

        config = {"clientId": "test-id"}
        expected_hash = hashlib.sha256(
            json.dumps(config, sort_keys=True, indent=4).encode()
        ).hexdigest()

        with patch(
            "keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.encrypt_buffer",
            return_value=b"fake-blob",
        ), patch.object(storage, "create_config_file_if_missing"), \
           patch("builtins.open", new=MagicMock()):
            storage.save_storage(config)

        assert storage.last_saved_config_hash == expected_hash, (
            f"save_storage did not use SHA-256 (got {storage.last_saved_config_hash[:16]}..., expected {expected_hash[:16]}...)"
        )


def _make_storage_stub(config=None, config_file_location=None):
    """Return an OracleKeyValueStorage instance with __init__ bypassed and state set directly.

    `cls.__new__(cls)` allocates a bare instance without invoking __init__, so no patch
    of __init__ is needed — only `cls(...)` would trigger __init__ via type.__call__.
    """
    from keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage import OracleKeyValueStorage
    storage = OracleKeyValueStorage.__new__(OracleKeyValueStorage)
    storage.config = config if config is not None else {}
    storage.config_file_location = config_file_location or ""
    storage.logger = logging.getLogger("test")
    storage.is_asymmetric = False
    storage.key_id = "ocid1.key.oc1..fake"
    storage.key_version_id = None
    storage.crypto_client = MagicMock()
    storage.management_client = MagicMock()
    storage._lock = threading.RLock()
    storage.last_saved_config_hash = ""
    return storage


class TestReadStorageCopyIsolation:
    """KSM-955: read_storage() must return a copy, not a live dict reference."""

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
    """KSM-955: decrypt_config() must not write plaintext to disk when called without arguments."""

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

        with patch(
            "keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.decrypt_buffer",
            return_value=plaintext,
        ):
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

        with patch(
            "keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.decrypt_buffer",
            return_value=plaintext,
        ):
            result = storage.decrypt_config(autosave=True)

        assert result == plaintext
        assert config_path.read_text() == plaintext


class TestDeleteLastKeyPersists:
    """KSM-955 regression: delete() of the last config key must clear internal state.

    Before the save-then-commit rewrite, delete() routed through read_storage() (now a
    copy), so del config[kv] only mutated the copy. __save_config({}) then hit the
    last-saved-hash equality check and skipped updating self.config, silently leaving
    the deleted key in memory and on disk.
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
            "keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.encrypt_buffer",
            return_value=b"fake-blob",
        ):
            storage.delete(ConfigKeys.KEY_CLIENT_ID)

        assert storage.config == {}, (
            "delete() of the last config key left internal state non-empty — deletion was silently lost"
        )


class TestConcurrentSet:
    """KSM-956 regression: concurrent set() calls must not raise or lose writes."""

    def test_concurrent_set_no_data_loss(self, tmp_path):
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

        errors = []

        with patch(
            "keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.encrypt_buffer",
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
    """Validates that change_key() rolls back the key fields on failure.

    Oracle's change_key already had rollback before v1.1.0 (one of the few bugs we
    did NOT inherit from the GCP template) — this test guards against regression.
    """

    def test_change_key_raises_when_get_key_details_fails(self):
        storage = _make_storage_stub(config={"clientId": "test-id"})
        old_key_id = storage.key_id
        old_key_version_id = storage.key_version_id

        with patch.object(
            storage, "get_key_details",
            side_effect=Exception("NotAuthorizedOrNotFound for new key"),
        ):
            with pytest.raises(Exception):
                storage.change_key("ocid1.key.oc1..new-key", "v2")

        assert storage.key_id == old_key_id, (
            "change_key() did not restore the original key_id after failure"
        )
        assert storage.key_version_id == old_key_version_id, (
            "change_key() did not restore the original key_version_id after failure"
        )

    def test_change_key_raises_when_save_fails(self, tmp_path):
        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"placeholder")

        storage = _make_storage_stub(
            config={"clientId": "test-id"},
            config_file_location=str(config_path),
        )
        old_key_id = storage.key_id
        old_is_asymmetric = storage.is_asymmetric

        # Mock get_key_details to flip is_asymmetric so we can verify the rollback covers it
        def fake_get_key_details():
            storage.is_asymmetric = True

        with patch.object(storage, "get_key_details", side_effect=fake_get_key_details), \
             patch("keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.encrypt_buffer",
                   side_effect=Exception("KMS save failed")), \
             patch.object(storage, "create_config_file_if_missing"):
            with pytest.raises(Exception):
                storage.change_key("ocid1.key.oc1..new-key", "v2")

        assert storage.key_id == old_key_id, (
            "change_key() did not restore key_id after save failure"
        )
        assert storage.is_asymmetric == old_is_asymmetric, (
            "change_key() did not restore is_asymmetric after save failure"
        )


class TestEncryptBufferPropagatesKMSError:
    """KSM-951 regression: encrypt_buffer() must raise on KMS failure, not return empty bytes.
    __save_config() must propagate the error so callers (set, save_storage) know the write failed.
    """

    def test_encrypt_buffer_raises_on_kms_failure(self):
        from keeper_secrets_manager_storage_oracle_kms.utils import encrypt_buffer

        logger = logging.getLogger("test")
        crypto_client = MagicMock()
        crypto_client.encrypt.side_effect = Exception("NotAuthorizedOrNotFound: encrypt denied")

        with pytest.raises(Exception, match="NotAuthorizedOrNotFound"):
            encrypt_buffer(
                key_id="ocid1.key.oc1..fake",
                message="ksm-config-test",
                crypto_client=crypto_client,
                key_version_id=None,
                is_asymmetric=False,
                logger=logger,
            )

    def test_decrypt_buffer_raises_on_kms_failure(self):
        from keeper_secrets_manager_storage_oracle_kms.utils import decrypt_buffer

        logger = logging.getLogger("test")
        # Build a syntactically valid blob so we reach the KMS call before failing
        blob = _make_blob(get_random_bytes(32), get_random_bytes(12), get_random_bytes(16), b"x" * 16)
        crypto_client = MagicMock()
        crypto_client.decrypt.side_effect = Exception("NotAuthorizedOrNotFound: decrypt denied")

        with pytest.raises(Exception, match="NotAuthorizedOrNotFound"):
            decrypt_buffer(
                key_id="ocid1.key.oc1..fake",
                ciphertext=blob,
                crypto_client=crypto_client,
                key_version_id=None,
                is_asymmetric=False,
                logger=logger,
            )

    def test_set_raises_when_kms_is_unavailable(self, tmp_path):
        from keeper_secrets_manager_core.configkeys import ConfigKeys

        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"placeholder")

        storage = _make_storage_stub(
            config={"clientId": "original"},
            config_file_location=str(config_path),
        )

        with patch(
            "keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.encrypt_buffer",
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

        with patch(
            "keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.encrypt_buffer",
            side_effect=Exception("KMS unavailable"),
        ), patch.object(storage, "create_config_file_if_missing"):
            with pytest.raises(Exception, match="KMS unavailable"):
                storage.delete(ConfigKeys.KEY_CLIENT_ID)

        assert storage.config == {"clientId": "original", "appKey": "secret"}, (
            "delete() raised but self.config was mutated — in-memory and on-disk state diverged"
        )


class TestDeleteAllWipesDisk:
    """KSM-952 regression: delete_all() must remove the config file from disk so no credential
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
        """os.remove() must run before self.config = {} so that a failed remove cannot
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

        with patch("keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.os.remove",
                   side_effect=recording_remove), \
             patch("keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.os.path.exists",
                   return_value=True):
            storage.delete_all()

        assert config_at_remove_time == {"clientId": "test-id", "appKey": "secret"}, (
            "os.remove() ran after config was cleared — config was already empty at removal time"
        )


class TestSetRaisesOnReadOnlyFile:
    """KSM-953 regression: set() must raise when the disk write fails due to file permissions.
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

        config_path.chmod(0o444)
        try:
            with patch(
                "keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.encrypt_buffer",
                return_value=b"fake-blob",
            ), patch.object(storage, "create_config_file_if_missing"):
                with pytest.raises((PermissionError, OSError)):
                    storage.set(ConfigKeys.KEY_CLIENT_ID, "new-value")
        finally:
            config_path.chmod(0o644)


class TestLoadConfigEmptyBootstrap:
    """KSM-957 regression: load_config() must leave self.config as a dict (never None),
    including when the on-disk JSON parses cleanly to an empty {}."""

    def test_load_config_handles_empty_json_dict(self, tmp_path):
        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"{}")

        storage = _make_storage_stub(config_file_location=str(config_path))
        storage.config = None  # simulate fresh init state before load_config

        with patch.object(storage, "create_config_file_if_missing"):
            storage.load_config()

        assert storage.config is not None, (
            "load_config() left self.config as None after parsing empty {} JSON — KSM-957 regression"
        )
        assert storage.config == {}
        assert storage.last_saved_config_hash != ""

    def test_set_after_empty_bootstrap_does_not_crash(self, tmp_path):
        from keeper_secrets_manager_core.configkeys import ConfigKeys

        config_path = tmp_path / "ksm-config.json"
        config_path.write_bytes(b"{}")

        storage = _make_storage_stub(config_file_location=str(config_path))
        storage.config = None

        with patch.object(storage, "create_config_file_if_missing"), \
             patch("keeper_secrets_manager_storage_oracle_kms.oracle_key_value_storage.encrypt_buffer",
                   return_value=b"fake-blob"):
            storage.load_config()
            storage.set(ConfigKeys.KEY_CLIENT_ID, "abc")

        assert storage.config.get("clientId") == "abc"
