import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest


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
