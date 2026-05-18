import unittest
from unittest.mock import patch, MagicMock

from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import keeper_public_keys
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage


class IL5DynamicKeyTest(unittest.TestCase):

    def test_layer1_generate_transmission_key_uses_custom_key(self):
        """Layer 1: generate_transmission_key uses custom key bytes instead of the hardcoded map."""
        custom_key_b64 = keeper_public_keys['7']  # borrow a real key's bytes as the "custom" key

        with patch('keeper_secrets_manager_core.core.CryptoUtils.public_encrypt') as mock_encrypt:
            mock_encrypt.return_value = b'fake_encrypted'
            SecretsManager.generate_transmission_key('20', custom_key_b64)

        mock_encrypt.assert_called_once()
        # First arg to public_encrypt is the transmission key bytes; second is the server public key bytes
        used_key_bytes = mock_encrypt.call_args[0][1]
        from keeper_secrets_manager_core.utils import url_safe_str_to_bytes
        self.assertEqual(used_key_bytes, url_safe_str_to_bytes(custom_key_b64))

    def test_layer1_generate_transmission_key_raises_without_custom_key(self):
        """Layer 1: unknown key_id with no custom key still raises ValueError."""
        with self.assertRaises(ValueError):
            SecretsManager.generate_transmission_key('20')

    def test_layer2_ott_4segment_writes_key_material_to_config(self):
        """Layer 2: 4-segment IL5 OTT writes key_id and server public key into config at init time."""
        custom_key_b64 = keeper_public_keys['7']
        config = InMemoryKeyValueStorage()

        # IL5:[clientKey]:[keyId]:[serverPublicKeyBase64]
        il5_token = 'IL5:fakeClientKey123456789012345:20:' + custom_key_b64

        secrets_manager = SecretsManager(token=il5_token, config=config)

        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY), custom_key_b64)
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), '20')

    def test_layer3_programmatic_params_write_key_material_to_config(self):
        """Layer 3: server_public_key / server_public_key_id constructor params write to config."""
        custom_key_b64 = keeper_public_keys['7']
        config = InMemoryKeyValueStorage(MockConfig.make_json())

        secrets_manager = SecretsManager(
            config=config,
            server_public_key=custom_key_b64,
            server_public_key_id='20',
        )

        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY), custom_key_b64)
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), '20')

    def test_key_rotation_retries_with_custom_key(self):
        """When the server sends a key-rotation error with key_id=20 and a custom key is configured,
        the SDK updates the key_id and retries instead of raising ValueError."""
        custom_key_b64 = keeper_public_keys['7']
        config = InMemoryKeyValueStorage(MockConfig.make_json())

        secrets_manager = SecretsManager(
            config=config,
            server_public_key=custom_key_b64,
            server_public_key_id='10',
        )

        # First response: server requests key rotation to key 20
        error_response = mock.Response(
            client=secrets_manager,
            content='{"error": "key", "key_id": 20}',
            status_code=400,
            reason="Bad Request",
        )

        # Second response: success with one record
        success_response = mock.Response()
        rec = success_response.add_record(title="IL5 Record")
        rec.field("login", "il5_user")

        res_queue = mock.ResponseQueue(client=secrets_manager)
        res_queue.add_response(error_response)
        res_queue.add_response(success_response)

        records = secrets_manager.get_secrets([])

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, "IL5 Record")
        # key_id should have been updated to '20' by the rotation handler
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), '20')


if __name__ == '__main__':
    unittest.main()
