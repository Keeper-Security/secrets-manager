import unittest
from unittest.mock import patch, MagicMock

from botocore.exceptions import NoRegionError


class TestGetClientNonEc2(unittest.TestCase):
    def _provider(self, fallback: bool):
        from keeper_secrets_manager_storage.storage_aws_secret import AwsConfigProvider, AwsConfigType

        provider = AwsConfigProvider('my-secret')
        provider.config_type = AwsConfigType.EC2INSTANCE
        provider.fallback = fallback
        provider.region = ""
        return provider

    def test_get_client_raises_actionable_error_without_fallback(self):
        provider = self._provider(fallback=False)

        with patch.object(provider, 'boto3_session') as mock_session:
            mock_session.client.side_effect = NoRegionError()
            with self.assertRaises(Exception) as ctx:
                provider._get_client()

        self.assertIn('EC2 instance', str(ctx.exception))
        self.assertIn('--fallback', str(ctx.exception))

    def test_get_client_falls_back_when_fallback_true(self):
        from keeper_secrets_manager_storage.storage_aws_secret import boto3

        provider = self._provider(fallback=True)

        with patch.object(provider, 'boto3_session') as mock_session, \
             patch.object(boto3, 'client', return_value=MagicMock()) as mock_boto3_client:
            mock_session.client.side_effect = NoRegionError()
            client = provider._get_client()

        mock_boto3_client.assert_called_once_with('secretsmanager')
        self.assertIsNotNone(client)


class TestGetInstanceRegionNonEc2(unittest.TestCase):
    def test_get_instance_region_uses_short_timeout(self):
        from keeper_secrets_manager_storage.storage_aws_secret import AwsConfigProvider

        provider = AwsConfigProvider('my-secret')

        with patch('keeper_secrets_manager_storage.storage_aws_secret.IMDSFetcher') as mock_fetcher_cls:
            mock_fetcher_cls.return_value._get_request.return_value = None
            with patch('keeper_secrets_manager_storage.storage_aws_secret.IMDSRegionProvider') as mock_region_provider_cls:
                mock_region_provider_cls.return_value.provide.return_value = ""
                region = provider._get_instance_region()

        self.assertEqual(region, "")
        for call in mock_fetcher_cls.call_args_list:
            self.assertEqual(call.kwargs.get('timeout'), 1)
            self.assertEqual(call.kwargs.get('num_attempts'), 1)


if __name__ == '__main__':
    unittest.main()
