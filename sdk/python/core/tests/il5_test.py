import unittest
from unittest.mock import patch, MagicMock

from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import keeper_public_keys
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage


class IL5DynamicKeyTest(unittest.TestCase):

    # Synthetic key id that is not in the built-in keeper_public_keys registry —
    # used throughout these tests as the "custom" key id without referencing
    # any specific deployment's id.
    CUSTOM_KEY_ID = '99'

    def test_layer1_generate_transmission_key_uses_custom_key(self):
        """Layer 1: generate_transmission_key uses custom key bytes instead of the hardcoded map."""
        custom_key_b64 = keeper_public_keys['7']  # borrow a real key's bytes as the "custom" key

        with patch('keeper_secrets_manager_core.core.CryptoUtils.public_encrypt') as mock_encrypt:
            mock_encrypt.return_value = b'fake_encrypted'
            SecretsManager.generate_transmission_key(self.CUSTOM_KEY_ID, custom_key_b64)

        mock_encrypt.assert_called_once()
        # First arg to public_encrypt is the transmission key bytes; second is the server public key bytes
        used_key_bytes = mock_encrypt.call_args[0][1]
        from keeper_secrets_manager_core.utils import url_safe_str_to_bytes
        self.assertEqual(used_key_bytes, url_safe_str_to_bytes(custom_key_b64))

    def test_layer1_generate_transmission_key_raises_without_custom_key(self):
        """Layer 1: unknown key_id with no custom key still raises ValueError."""
        with self.assertRaises(ValueError):
            SecretsManager.generate_transmission_key(self.CUSTOM_KEY_ID)

    def test_layer2_ott_4segment_writes_key_material_to_config(self):
        """Layer 2: 4-segment IL5 OTT writes key_id and server public key into config at init time."""
        custom_key_b64 = keeper_public_keys['7']
        config = InMemoryKeyValueStorage()

        # IL5:[clientKey]:[keyId]:[serverPublicKeyBase64]
        il5_token = 'IL5:fakeClientKey123456789012345:' + self.CUSTOM_KEY_ID + ':' + custom_key_b64

        secrets_manager = SecretsManager(token=il5_token, config=config)

        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY), custom_key_b64)
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), self.CUSTOM_KEY_ID)

    def test_layer3_programmatic_params_write_key_material_to_config(self):
        """Layer 3: server_public_key / server_public_key_id constructor params write to config."""
        custom_key_b64 = keeper_public_keys['7']
        config = InMemoryKeyValueStorage(MockConfig.make_json())

        secrets_manager = SecretsManager(
            config=config,
            server_public_key=custom_key_b64,
            server_public_key_id=self.CUSTOM_KEY_ID,
        )

        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY), custom_key_b64)
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), self.CUSTOM_KEY_ID)

    def test_key_rotation_retries_with_custom_key(self):
        """When the server sends a key-rotation error pointing at a key id not in the built-in
        registry and a custom key is configured, the SDK updates the key_id and retries instead
        of raising ValueError."""
        custom_key_b64 = keeper_public_keys['7']
        config = InMemoryKeyValueStorage(MockConfig.make_json())

        secrets_manager = SecretsManager(
            config=config,
            server_public_key=custom_key_b64,
            server_public_key_id='10',
        )

        # First response: server requests key rotation to an id outside the built-in registry
        error_response = mock.Response(
            client=secrets_manager,
            content='{"error": "key", "key_id": ' + self.CUSTOM_KEY_ID + '}',
            status_code=400,
            reason="Bad Request",
        )

        # Second response: success with one record
        success_response = mock.Response()
        rec = success_response.add_record(title="Custom-Key Record")
        rec.field("login", "test_user")

        res_queue = mock.ResponseQueue(client=secrets_manager)
        res_queue.add_response(error_response)
        res_queue.add_response(success_response)

        records = secrets_manager.get_secrets([])

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].title, "Custom-Key Record")
        # key_id should have been updated by the rotation handler
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), self.CUSTOM_KEY_ID)


    def test_layer1_config_file_supplies_custom_key(self):
        """Layer 1: a config that already contains serverPublicKey is honored on construction
        with no token and no programmatic params — the custom key is preserved in config."""
        custom_key_b64 = keeper_public_keys['7']
        config = InMemoryKeyValueStorage(MockConfig.make_json())
        config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY, custom_key_b64)
        config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, self.CUSTOM_KEY_ID)

        SecretsManager(config=config)

        # Construction must not clobber the pre-existing custom key or reset the unknown
        # key_id back to the default 10
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY), custom_key_b64)
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), self.CUSTOM_KEY_ID)

    def test_layer_precedence_programmatic_beats_token_beats_config(self):
        """Precedence: programmatic params > 4-segment token > pre-existing config values."""
        config_key = keeper_public_keys['7']
        token_key = keeper_public_keys['8']
        programmatic_key = keeper_public_keys['9']

        # Seed config with a Layer 1 value
        config = InMemoryKeyValueStorage()
        config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY, config_key)
        config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, 'config-id')

        # Layer 2 (token) and Layer 3 (programmatic) both supplied; programmatic must win
        il5_token = 'IL5:fakeClientKey123456789012345:token-id:' + token_key

        SecretsManager(
            token=il5_token,
            config=config,
            server_public_key=programmatic_key,
            server_public_key_id='programmatic-id',
        )

        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY), programmatic_key)
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), 'programmatic-id')

    def test_token_beats_config_when_no_programmatic_params(self):
        """Token (Layer 2) overrides pre-existing config (Layer 1) when programmatic params absent."""
        config_key = keeper_public_keys['7']
        token_key = keeper_public_keys['8']

        config = InMemoryKeyValueStorage()
        config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY, config_key)
        config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, 'config-id')

        il5_token = 'IL5:fakeClientKey123456789012345:token-id:' + token_key

        SecretsManager(token=il5_token, config=config)

        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY), token_key)
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), 'token-id')

    # --- Parser hardening (KSM-932 follow-up) -----------------------------------

    def test_malformed_il5_token_3_segments_raises(self):
        """IL5 tokens with 3 segments must fail loud, not silently drop the third segment."""
        with self.assertRaises(ValueError):
            SecretsManager(token='IL5:fakeClientKey:' + self.CUSTOM_KEY_ID, config=InMemoryKeyValueStorage())

    def test_malformed_il5_token_5_segments_raises(self):
        """IL5 tokens with more than 4 segments must fail loud, not silently drop the extras."""
        custom_key_b64 = keeper_public_keys['7']
        token = 'IL5:fakeClientKey:' + self.CUSTOM_KEY_ID + ':' + custom_key_b64 + ':extra'
        with self.assertRaises(ValueError):
            SecretsManager(token=token, config=InMemoryKeyValueStorage())

    def test_malformed_il5_token_empty_segments_raises(self):
        """IL5 tokens with empty keyId or serverPublicKey segments must fail loud."""
        custom_key_b64 = keeper_public_keys['7']
        # Empty keyId
        with self.assertRaises(ValueError):
            SecretsManager(token='IL5:fakeClientKey::' + custom_key_b64, config=InMemoryKeyValueStorage())
        # Empty serverPublicKey
        with self.assertRaises(ValueError):
            SecretsManager(token='IL5:fakeClientKey:' + self.CUSTOM_KEY_ID + ':', config=InMemoryKeyValueStorage())

    def test_malformed_il5_token_invalid_base64_raises(self):
        """IL5 tokens with a non-base64 serverPublicKey segment must fail at construction, not deeper in the stack."""
        with self.assertRaises(ValueError):
            SecretsManager(
                token='IL5:fakeClientKey:' + self.CUSTOM_KEY_ID + ':not!valid@base64',
                config=InMemoryKeyValueStorage(),
            )

    def test_non_il5_token_with_extra_segments_is_unchanged(self):
        """A non-IL5 prefix with extra segments must not trigger the IL5 parser path —
        commercial/standard tokens stay backwards-compatible."""
        config = InMemoryKeyValueStorage()
        # US prefix with extra segments — historically these were silently dropped; preserving that.
        SecretsManager(token='US:fakeClientKey123456789012345:extra:more', config=config)
        # No custom key should have been written
        self.assertIsNone(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY))


if __name__ == '__main__':
    unittest.main()
