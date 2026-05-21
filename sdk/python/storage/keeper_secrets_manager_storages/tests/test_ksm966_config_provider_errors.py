"""KSM-966: AwsConfigProvider error handling — _get_instance_region must raise when IMDS
is unavailable; read_config must raise instead of silently returning empty on AWS errors."""
import unittest
from unittest.mock import MagicMock, patch


class TestKsm966InstanceRegion(unittest.TestCase):
    def test_get_instance_region_raises_when_imds_unavailable(self):
        """KSM-966: _get_instance_region must raise when all IMDS region detection fails."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsConfigProvider

        provider = AwsConfigProvider('my-secret')  # non-ARN key — cannot extract region from key

        with patch('keeper_secrets_manager_storage.storage_aws_secret.IMDSFetcher') as mock_imds, \
             patch('keeper_secrets_manager_storage.storage_aws_secret.IMDSRegionProvider') as mock_irp:
            mock_imds.return_value._get_request.side_effect = Exception('IMDS unavailable')
            mock_irp.return_value.provide.side_effect = Exception('IMDS unavailable')

            with self.assertRaises(Exception,
                                   msg='_get_instance_region must raise when IMDS is unavailable'):
                provider._get_instance_region()

    def test_arn_key_skips_imds(self):
        """KSM-966: an ARN key must resolve region without IMDS (no exception)."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsConfigProvider

        arn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret'
        provider = AwsConfigProvider(arn)

        # IMDS would fail if called — but ARN path must bypass it
        with patch('keeper_secrets_manager_storage.storage_aws_secret.IMDSFetcher') as mock_imds, \
             patch('keeper_secrets_manager_storage.storage_aws_secret.IMDSRegionProvider') as mock_irp:
            mock_imds.return_value._get_request.side_effect = Exception('IMDS unavailable')
            mock_irp.return_value.provide.side_effect = Exception('IMDS unavailable')

            region = provider._get_instance_region()

        self.assertEqual(region, 'us-east-1')


class TestKsm966ReadConfig(unittest.TestCase):
    def test_read_config_raises_on_aws_error(self):
        """KSM-966: read_config must raise when AWS Secrets Manager returns an error."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsConfigProvider

        provider = AwsConfigProvider('my-secret')
        provider.fallback = False

        with patch.object(provider, '_get_client') as mock_client, \
             patch.object(provider, '_get_secret_aws') as mock_get:
            mock_client.return_value = MagicMock()
            mock_get.return_value = {
                'value': None,
                'not_found': False,
                'error': 'AccessDeniedException: User is not authorized to read secret'
            }

            with self.assertRaises(Exception,
                                   msg='read_config must raise when AWS returns an error'):
                provider.read_config()

    def test_read_config_raises_on_fallback_error(self):
        """KSM-966: read_config must raise when both primary and fallback calls fail."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsConfigProvider

        provider = AwsConfigProvider('my-secret')
        provider.fallback = True

        with patch.object(provider, '_get_client') as mock_client, \
             patch.object(provider, '_get_secret_aws') as mock_get, \
             patch('keeper_secrets_manager_storage.storage_aws_secret.boto3') as mock_boto3:
            mock_client.return_value = MagicMock()
            mock_boto3.client.return_value = MagicMock()
            mock_get.return_value = {
                'value': None,
                'not_found': False,
                'error': 'NetworkError: Connection timeout'
            }

            with self.assertRaises(Exception,
                                   msg='read_config must raise when fallback also fails'):
                provider.read_config()

    def test_read_config_success_returns_value(self):
        """KSM-966: read_config must return the value when AWS call succeeds."""
        from keeper_secrets_manager_storage.storage_aws_secret import AwsConfigProvider

        provider = AwsConfigProvider('my-secret')
        provider.fallback = False

        with patch.object(provider, '_get_client') as mock_client, \
             patch.object(provider, '_get_secret_aws') as mock_get:
            mock_client.return_value = MagicMock()
            mock_get.return_value = {
                'value': '{"clientId": "abc"}',
                'not_found': False,
                'error': None
            }

            result = provider.read_config()

        self.assertEqual(result, '{"clientId": "abc"}')


if __name__ == '__main__':
    unittest.main()
