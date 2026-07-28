"""KSM-977: AwsSecretStorage.__load_config() must propagate exceptions from
AwsConfigProvider.read_config() rather than swallowing them. Affected entry points:
default constructor, from_default_config, from_profile_config, from_ec2instance_config,
from_custom_config."""
import unittest
from unittest.mock import patch, MagicMock


_AWS_ERROR = Exception("Failed to read config from AWS secret 'my-secret': AccessDeniedException")


class TestKsm977LoadConfigExceptionPropagation(unittest.TestCase):
    def test_default_constructor_raises_when_read_config_raises(self):
        """KSM-977: AwsSecretStorage() must raise when read_config raises, not return silently."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider

        with patch.object(AwsConfigProvider, 'from_ec2instance_config'), \
             patch.object(AwsConfigProvider, 'read_config', side_effect=_AWS_ERROR):
            with self.assertRaises(ValueError,
                                   msg='AwsSecretStorage() must raise ValueError when read_config raises'):
                AwsSecretStorage('my-secret')

    def test_default_constructor_error_contains_secret_name(self):
        """KSM-977: raised ValueError must identify the secret name."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider

        with patch.object(AwsConfigProvider, 'from_ec2instance_config'), \
             patch.object(AwsConfigProvider, 'read_config', side_effect=_AWS_ERROR):
            with self.assertRaises(ValueError) as ctx:
                AwsSecretStorage('my-secret')

        self.assertIn('my-secret', str(ctx.exception))

    def test_from_default_config_raises_when_read_config_raises(self):
        """KSM-977: from_default_config must raise when read_config raises."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider

        storage = AwsSecretStorage.__new__(AwsSecretStorage)
        storage.provider = AwsConfigProvider('my-secret')
        storage.config = {}
        storage.last_saved_config_hash = ""

        with patch.object(storage.provider, 'from_default_config'), \
             patch.object(storage.provider, 'read_config', side_effect=_AWS_ERROR):
            with self.assertRaises(ValueError,
                                   msg='from_default_config must raise ValueError when read_config raises'):
                storage.from_default_config('my-secret')

    def test_from_profile_config_raises_when_read_config_raises(self):
        """KSM-977: from_profile_config must raise when read_config raises."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider

        storage = AwsSecretStorage.__new__(AwsSecretStorage)
        storage.provider = AwsConfigProvider('my-secret')
        storage.config = {}
        storage.last_saved_config_hash = ""

        with patch.object(storage.provider, 'from_profile_config'), \
             patch.object(storage.provider, 'read_config', side_effect=_AWS_ERROR):
            with self.assertRaises(ValueError,
                                   msg='from_profile_config must raise ValueError when read_config raises'):
                storage.from_profile_config('my-secret', 'my-profile')

    def test_from_ec2instance_config_raises_when_read_config_raises(self):
        """KSM-977: from_ec2instance_config must raise when read_config raises.

        Uses class-level patches because from_ec2instance_config creates a new
        AwsConfigProvider instance internally — instance-level patches on the old
        provider are irrelevant after the swap.
        """
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider

        storage = AwsSecretStorage.__new__(AwsSecretStorage)
        storage.provider = AwsConfigProvider('my-secret')
        storage.config = {}
        storage.last_saved_config_hash = ""

        with patch.object(AwsConfigProvider, 'from_ec2instance_config'), \
             patch.object(AwsConfigProvider, 'read_config', side_effect=_AWS_ERROR):
            with self.assertRaises(ValueError,
                                   msg='from_ec2instance_config must raise ValueError when read_config raises'):
                storage.from_ec2instance_config('my-secret')

    def test_from_custom_config_raises_when_read_config_raises(self):
        """KSM-977: from_custom_config must raise when read_config raises."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsSecretStorage, AwsConfigProvider

        with patch.object(AwsConfigProvider, 'from_ec2instance_config'), \
             patch.object(AwsConfigProvider, 'read_config', return_value='{"clientId": "init"}'):
            storage = AwsSecretStorage('my-secret')

        with patch.object(storage.provider, 'from_custom_config'), \
             patch.object(storage.provider, 'read_config', side_effect=_AWS_ERROR):
            with self.assertRaises(ValueError,
                                   msg='from_custom_config must raise ValueError when read_config raises'):
                storage.from_custom_config('my-secret', 'key-id', 'secret-key', 'us-east-1')


if __name__ == '__main__':
    unittest.main()
