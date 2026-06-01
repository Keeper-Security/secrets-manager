"""KSM-967: AwsSecretStorage default constructor must call __load_config(); __load_config must
accept valid JSON configs that lack privateKey rather than raising with a misleading error."""
import unittest
from unittest.mock import patch


class TestKsm967DefaultConstructorLoadsConfig(unittest.TestCase):
    def test_default_constructor_loads_config(self):
        """KSM-967: AwsSecretStorage() must populate self.config without requiring a helper call."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider

        valid_config = '{"clientId": "test-id", "privateKey": "abc123"}'

        with patch.object(AwsConfigProvider, 'from_ec2instance_config'), \
             patch.object(AwsConfigProvider, 'read_config', return_value=valid_config):
            storage = AwsSecretStorage('my-secret')

        self.assertNotEqual(storage.config, {},
                            'AwsSecretStorage() must call __load_config(); config must not be empty')
        self.assertEqual(storage.config.get('clientId'), 'test-id')

    def test_default_constructor_config_matches_secret(self):
        """KSM-967: config populated in __init__ must reflect the value returned by read_config."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider

        secret_payload = '{"clientId": "my-client", "privateKey": "secret-key-value"}'

        with patch.object(AwsConfigProvider, 'from_ec2instance_config'), \
             patch.object(AwsConfigProvider, 'read_config', return_value=secret_payload):
            storage = AwsSecretStorage('my-secret')

        self.assertEqual(storage.config.get('privateKey'), 'secret-key-value')


class TestKsm967LoadConfigAcceptsJsonWithoutPrivateKey(unittest.TestCase):
    def _build_storage(self, config_json: str):
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider
        with patch.object(AwsConfigProvider, 'from_default_config'), \
             patch.object(AwsConfigProvider, 'read_config', return_value=config_json):
            storage = AwsSecretStorage.__new__(AwsSecretStorage)
            storage.provider = AwsConfigProvider('test')
            # Call from_default_config which triggers __load_config
            with patch.object(storage.provider, 'from_default_config'), \
                 patch.object(storage.provider, 'read_config', return_value=config_json):
                storage.from_default_config('test')
        return storage

    def test_accepts_bootstrap_token_config(self):
        """KSM-967: __load_config must accept a JSON config without privateKey (bootstrap token only)."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider

        bootstrap_config = '{"clientKey": "one-time-bootstrap-token"}'

        with patch.object(AwsConfigProvider, 'from_ec2instance_config'), \
             patch.object(AwsConfigProvider, 'read_config', return_value=bootstrap_config):
            # Before fix: raises ValueError("... the value must be a valid JSON")
            # After fix: accepted as valid JSON dict
            storage = AwsSecretStorage('my-secret')

        self.assertEqual(storage.config.get('clientKey'), 'one-time-bootstrap-token')

    def test_accepts_empty_json_config(self):
        """KSM-967: __load_config must accept {} without raising."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider

        with patch.object(AwsConfigProvider, 'from_ec2instance_config'), \
             patch.object(AwsConfigProvider, 'read_config', return_value='{}'):
            storage = AwsSecretStorage('my-secret')

        self.assertIsInstance(storage.config, dict)

    def test_missing_private_key_error_names_field(self):
        """KSM-967: if caller checks for privateKey, error must name the missing field (not 'valid JSON')."""
        # This is a documentation/behavior test — after fix, __load_config accepts the config;
        # any privateKey validation is the downstream SDK's responsibility.
        # Verify the old misleading error is gone.
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider

        partial_config = '{"clientId": "test"}'  # valid JSON, no privateKey

        try:
            with patch.object(AwsConfigProvider, 'from_ec2instance_config'), \
                 patch.object(AwsConfigProvider, 'read_config', return_value=partial_config):
                storage = AwsSecretStorage('my-secret')
            # After fix: no exception, config is loaded
            self.assertEqual(storage.config.get('clientId'), 'test')
        except ValueError as e:
            # Before fix: raises with misleading "the value must be a valid JSON" message
            self.fail(f'__load_config must not raise for valid JSON: {e}')


if __name__ == '__main__':
    unittest.main()
