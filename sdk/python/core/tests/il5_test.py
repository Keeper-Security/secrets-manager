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

    def test_layer2_ott_4segment_custom_host_writes_key_material_to_config(self):
        """A 4-part OTT with a custom host (not IL5) keeps the host and the key pair."""
        custom_key_b64 = keeper_public_keys['7']
        config = InMemoryKeyValueStorage()

        token = 'smk.example.com:fakeClientKey123456789012345:' + self.CUSTOM_KEY_ID + ':' + custom_key_b64
        SecretsManager(token=token, config=config)

        self.assertEqual(config.get(ConfigKeys.KEY_HOSTNAME), 'smk.example.com')
        self.assertEqual(config.get(ConfigKeys.KEY_CLIENT_KEY), 'fakeClientKey123456789012345')
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY), custom_key_b64)
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), self.CUSTOM_KEY_ID)

    def test_two_part_cloud_token_writes_no_key_material(self):
        """A 2-part cloud OTT does not write a custom server key."""
        config = InMemoryKeyValueStorage()
        SecretsManager(token='US:fakeClientKey123456789012345', config=config)
        self.assertIsNone(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY))

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
        config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, '11')

        # Layer 2 (token) and Layer 3 (programmatic) both supplied; programmatic must win
        il5_token = 'IL5:fakeClientKey123456789012345:13:' + token_key

        SecretsManager(
            token=il5_token,
            config=config,
            server_public_key=programmatic_key,
            server_public_key_id='12',
        )

        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY), programmatic_key)
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), '12')

    def test_token_beats_config_when_no_programmatic_params(self):
        """Token (Layer 2) overrides pre-existing config (Layer 1) when programmatic params absent."""
        config_key = keeper_public_keys['7']
        token_key = keeper_public_keys['8']

        config = InMemoryKeyValueStorage()
        config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY, config_key)
        config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, '11')

        il5_token = 'IL5:fakeClientKey123456789012345:13:' + token_key

        SecretsManager(token=il5_token, config=config)

        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY), token_key)
        self.assertEqual(config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), '13')

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

    def test_cloud_region_token_with_key_material_raises(self):
        """A cloud region other than IL5 with key segments fails closed. It must not fall back to the built-in key."""
        key = keeper_public_keys['7']
        with self.assertRaises(ValueError) as ctx:
            SecretsManager(token='US:fakeClientKey123456789012345:70:' + key, config=InMemoryKeyValueStorage())
        self.assertIn('IL5 or a self-managed', str(ctx.exception))

    def test_unsupported_segment_count_raises(self):
        """Only 1, 2 or 4 segments are valid. A 3-segment custom host and a 5-segment token raise."""
        key = keeper_public_keys['7']
        for token in ('smk.example.com:fakeClientKey123456789012345:70',
                      'US:fakeClientKey123456789012345:extra',
                      'smk.example.com:fakeClientKey123456789012345:70:' + key + ':extra'):
            with self.assertRaises(ValueError, msg=token):
                SecretsManager(token=token, config=InMemoryKeyValueStorage())

    def test_bad_server_key_is_rejected_before_any_network_call(self):
        """The key segment must be 65 bytes, start with 0x04 and be a point on P-256."""
        from base64 import urlsafe_b64encode

        def bytes_to_url_safe_str(b):
            return urlsafe_b64encode(b).decode().rstrip('=')

        bad_keys = {
            'short': bytes_to_url_safe_str(b'\x04' + b'\x01' * 31),
            'long': bytes_to_url_safe_str(b'\x04' + b'\x01' * 70),
            'prefix': bytes_to_url_safe_str(b'\x03' + b'\x01' * 64),
            'not on curve': bytes_to_url_safe_str(b'\x04' + b'\x01' * 64),
            'not base64': 'not!valid@base64',
        }
        for name, bad in bad_keys.items():
            for host in ('smk.example.com', 'IL5'):
                with patch('keeper_secrets_manager_core.core.requests.post') as post:
                    with self.assertRaises(ValueError, msg=name):
                        SecretsManager(token=host + ':fakeClientKey123456789012345:70:' + bad, config=InMemoryKeyValueStorage())
                    post.assert_not_called()
            with self.assertRaises(ValueError, msg=name):
                SecretsManager(token='US:fakeClientKey', server_public_key=bad, server_public_key_id='70',
                               config=InMemoryKeyValueStorage())

    def test_bad_key_id_raises(self):
        """The key id is digits only and in 1..65535."""
        key = keeper_public_keys['7']
        for key_id in ('abc', '0', '65536', '-1', '7 ', '+7', '\u0663'):
            with self.assertRaises(ValueError, msg=key_id):
                SecretsManager(token='smk.example.com:fakeClientKey123456789012345:' + key_id + ':' + key,
                               config=InMemoryKeyValueStorage())
        with self.assertRaises(ValueError):
            SecretsManager(token='US:fakeClientKey', server_public_key=key, server_public_key_id='x',
                           config=InMemoryKeyValueStorage())

    def test_empty_host_or_token_segment_raises(self):
        key = keeper_public_keys['7']
        for token in (':fakeClientKey123456789012345:70:' + key, 'smk.example.com::70:' + key):
            with self.assertRaises(ValueError, msg=token):
                SecretsManager(token=token, config=InMemoryKeyValueStorage())

    def test_error_message_names_token_kind(self):
        with self.assertRaises(ValueError) as il5:
            SecretsManager(token='IL5:fakeClientKey123456789012345:70:', config=InMemoryKeyValueStorage())
        self.assertIn('IL5', str(il5.exception))
        with self.assertRaises(ValueError) as sm:
            SecretsManager(token='smk.example.com:fakeClientKey123456789012345:70:', config=InMemoryKeyValueStorage())
        self.assertIn('self-managed', str(sm.exception))
        self.assertNotIn('IL5', str(sm.exception))

    def test_env_hostname_does_not_override_pinned_self_managed_host(self):
        """A pinned server key belongs to its host. KSM_HOSTNAME must not redirect the request."""
        from keeper_secrets_manager_core import helpers
        key = keeper_public_keys['7']
        config = InMemoryKeyValueStorage()
        SecretsManager(token='smk.example.com:fakeClientKey123456789012345:70:' + key, config=config)
        with patch.dict('os.environ', {'KSM_HOSTNAME': 'evil.example.net'}):
            self.assertEqual(helpers.get_server(None, config), 'smk.example.com')
            # Cloud mode (no pinned key) still honors KSM_HOSTNAME.
            self.assertEqual(helpers.get_server(None, InMemoryKeyValueStorage()), 'evil.example.net')


if __name__ == '__main__':
    unittest.main()
