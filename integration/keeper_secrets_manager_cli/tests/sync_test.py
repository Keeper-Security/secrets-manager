import unittest
from unittest.mock import Mock, MagicMock, patch
import json
from click.testing import CliRunner
from keeper_secrets_manager_cli.sync import Sync
from keeper_secrets_manager_cli.exception import KsmCliException


class SyncTest(unittest.TestCase):
    """Test cases for AWS KMS JSON sync functionality"""

    def setUp(self):
        """Set up test fixtures"""
        super().setUp()  # Call parent setUp for logger cleanup
        self.cli_mock = Mock()
        self.cli_mock.client = Mock()
        self.cli_mock.output = Mock()  # Mock the output method

        # Create Sync instance with mocked logger
        with patch('keeper_secrets_manager_cli.sync.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            self.sync = Sync(cli=self.cli_mock)
            self.sync.logger = mock_logger

    def test_validate_overlapping_kms_keys(self):
        """Test that overlapping KMS keys between formats raises an error"""
        with self.assertRaises(KsmCliException) as context:
            self.sync.sync_values(
                type='aws',
                map=[
                    ('my_key', 'keeper://record1/field/password'),  # Plain format
                    ('my_key+json_key', 'keeper://record2/field/api_key')  # JSON format for same KMS key
                ]
            )
        self.assertIn("Cannot use both plain and JSON format for the same KMS key", str(context.exception))

    def test_allow_mixed_formats_different_keys(self):
        """Test that mixing formats with different KMS keys is allowed"""
        # Mock _get_secret to return values
        self.sync._get_secret = Mock(side_effect=['value1', 'value2', 'value3'])

        # This should not raise an exception
        try:
            self.sync.sync_values(
                type='aws',
                map=[
                    ('plain_key1', 'keeper://record1/field/password'),  # Plain format
                    ('plain_key2', 'keeper://record2/field/api_key'),   # Plain format
                    ('json_key+field1', 'keeper://record3/field/data')  # JSON format for different key
                ]
            )
        except KsmCliException as e:
            if "Cannot use both plain and JSON format" in str(e):
                self.fail(f"Should allow mixed formats with different KMS keys: {e}")

    def test_validate_duplicate_json_keys(self):
        """Test that duplicate JSON keys within same KMS key raises an error"""
        with self.assertRaises(KsmCliException) as context:
            self.sync.sync_values(
                type='aws',
                map=[
                    ('kms_key+json_key1', 'keeper://record1/field/password'),
                    ('kms_key+json_key1', 'keeper://record2/field/api_key')
                ]
            )
        self.assertIn("Duplicate keys found:", str(context.exception))
        self.assertIn("Duplicate JSON keys within same KMS key", str(context.exception))

    def test_validate_duplicate_plain_keys(self):
        """Test that duplicate plain keys raises an error"""
        with self.assertRaises(KsmCliException) as context:
            self.sync.sync_values(
                type='aws',
                map=[
                    ('plain_key', 'keeper://record1/field/password'),
                    ('plain_key', 'keeper://record2/field/api_key'),
                    ('plain_key', 'keeper://record3/field/token')
                ]
            )
        self.assertIn("Duplicate keys found:", str(context.exception))
        self.assertIn("Duplicate plain keys: 'plain_key' (appears 3 times)", str(context.exception))

    def test_validate_all_duplicate_types(self):
        """Test that all types of duplicates are reported together"""
        with self.assertRaises(KsmCliException) as context:
            self.sync.sync_values(
                type='aws',
                map=[
                    # Duplicate plain keys
                    ('plain_key1', 'keeper://record1/field/password'),
                    ('plain_key1', 'keeper://record2/field/api_key'),
                    # Duplicate JSON keys within same KMS key
                    ('json_key+field1', 'keeper://record3/field/data1'),
                    ('json_key+field1', 'keeper://record4/field/data2'),
                    # Overlapping key between formats
                    ('overlap_key', 'keeper://record5/field/plain'),
                    ('overlap_key+json_field', 'keeper://record6/field/json')
                ]
            )
        error_msg = str(context.exception)
        self.assertIn("Duplicate keys found:", error_msg)
        self.assertIn("Duplicate plain keys: 'plain_key1' (appears 2 times)", error_msg)
        self.assertIn("Duplicate JSON keys within same KMS key", error_msg)
        self.assertIn("Cannot use both plain and JSON format for the same KMS key(s): overlap_key", error_msg)

    @patch('boto3.client')
    def test_sync_aws_json_dry_run(self, mock_boto_client):
        """Test dry run with JSON format"""
        # Setup mocks
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock existing JSON value in AWS
        existing_json = {"existing_key": "existing_value"}
        mock_client.get_secret_value.return_value = {
            'SecretString': json.dumps(existing_json)
        }

        # Mock Keeper secrets
        self.cli_mock.client.get_secrets.return_value = [Mock(
            uid='cred_uid',
            get_standard_field_value=Mock(return_value=None),
            get_custom_field_value=Mock(side_effect=lambda field, _: {
                'AWS Access Key ID': 'test_key_id',
                'AWS Secret Access Key': 'test_secret',
                'AWS Region Name': 'us-east-1'
            }.get(field))
        )]

        # Mock get_secret to return values
        self.sync._get_secret = Mock(side_effect=['value1', 'value2'])

        # Capture output
        output_data = []
        self.sync._output = Mock(side_effect=lambda data: output_data.append(data))

        # Run dry run
        map_data = [
            {"mapKey": "kms_key+json_key1", "mapNotation": "keeper://rec1/field", "srcValue": "value1", "dstValue": None},
            {"mapKey": "kms_key+json_key2", "mapNotation": "keeper://rec2/field", "srcValue": "value2", "dstValue": None}
        ]

        self.sync.sync_aws_json(
            credentials='cred_uid',
            dry_run=True,
            preserve_missing=False,
            map=map_data
        )

        # Verify it read the existing value
        mock_client.get_secret_value.assert_called_with(SecretId='kms_key')

        # Verify output shows existing values
        self.assertEqual(len(output_data), 1)
        self.assertIsNone(output_data[0][0]["dstValue"])  # json_key1 doesn't exist yet
        self.assertIsNone(output_data[0][1]["dstValue"])  # json_key2 doesn't exist yet

    @patch('boto3.client')
    def test_sync_aws_json_merge_existing(self, mock_boto_client):
        """Test merging with existing JSON values"""
        # Setup mocks
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock existing JSON value
        existing_json = {"existing_key": "existing_value", "json_key1": "old_value"}
        mock_client.get_secret_value.return_value = {
            'SecretString': json.dumps(existing_json)
        }

        # Mock successful update
        mock_client.put_secret_value.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}

        # Mock Keeper credentials
        self.cli_mock.client.get_secrets.return_value = [Mock(
            uid='cred_uid',
            get_standard_field_value=Mock(return_value=None),
            get_custom_field_value=Mock(side_effect=lambda field, _: {
                'AWS Access Key ID': 'test_key_id',
                'AWS Secret Access Key': 'test_secret',
                'AWS Region Name': 'us-east-1'
            }.get(field))
        )]

        # Mock get_secret
        self.sync._get_secret = Mock(side_effect=['new_value1', 'new_value2'])

        # Capture output
        self.sync._output = Mock()

        # Run sync
        map_data = [
            {"mapKey": "kms_key+json_key1", "mapNotation": "keeper://rec1/field", "srcValue": "new_value1", "dstValue": None},
            {"mapKey": "kms_key+json_key2", "mapNotation": "keeper://rec2/field", "srcValue": "new_value2", "dstValue": None}
        ]

        self.sync.sync_aws_json(
            credentials='cred_uid',
            dry_run=False,
            preserve_missing=False,
            map=map_data
        )

        # Verify the correct JSON was written (merged)
        mock_client.put_secret_value.assert_called_once()
        call_args = mock_client.put_secret_value.call_args
        written_json = json.loads(call_args[1]['SecretString'])

        # Should have existing_key preserved and new values added/updated
        self.assertEqual(written_json['existing_key'], 'existing_value')
        self.assertEqual(written_json['json_key1'], 'new_value1')  # Updated
        self.assertEqual(written_json['json_key2'], 'new_value2')  # Added

    @patch('boto3.client')
    def test_sync_aws_json_preserve_plaintext(self, mock_boto_client):
        """Test preserving existing plaintext value when converting to JSON"""
        # Setup mocks
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock existing plaintext value
        mock_client.get_secret_value.return_value = {
            'SecretString': 'existing_plaintext_value'
        }

        # Mock successful update
        mock_client.put_secret_value.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}

        # Mock Keeper credentials
        self.cli_mock.client.get_secrets.return_value = [Mock(
            uid='cred_uid',
            get_standard_field_value=Mock(return_value=None),
            get_custom_field_value=Mock(side_effect=lambda field, _: {
                'AWS Access Key ID': 'test_key_id',
                'AWS Secret Access Key': 'test_secret',
                'AWS Region Name': 'us-east-1'
            }.get(field))
        )]

        # Mock get_secret
        self.sync._get_secret = Mock(return_value='new_value')

        # Capture output
        self.sync._output = Mock()

        # Run sync
        map_data = [
            {"mapKey": "kms_key+json_key1", "mapNotation": "keeper://rec1/field", "srcValue": "new_value", "dstValue": None}
        ]

        self.sync.sync_aws_json(
            credentials='cred_uid',
            dry_run=False,
            preserve_missing=False,
            map=map_data
        )

        # Verify the plaintext was preserved in special key
        mock_client.put_secret_value.assert_called_once()
        call_args = mock_client.put_secret_value.call_args
        written_json = json.loads(call_args[1]['SecretString'])

        self.assertEqual(written_json['_preserved_plaintext'], 'existing_plaintext_value')
        self.assertEqual(written_json['json_key1'], 'new_value')

    @patch('boto3.client')
    def test_sync_aws_json_create_new(self, mock_boto_client):
        """Test creating new KMS key with JSON format"""
        # Setup mocks
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock key doesn't exist
        from botocore.exceptions import ClientError
        mock_client.get_secret_value.side_effect = ClientError(
            {'Error': {'Code': 'ResourceNotFoundException'}},
            'GetSecretValue'
        )

        # Mock successful create
        mock_client.create_secret.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}

        # Mock Keeper credentials
        self.cli_mock.client.get_secrets.return_value = [Mock(
            uid='cred_uid',
            get_standard_field_value=Mock(return_value=None),
            get_custom_field_value=Mock(side_effect=lambda field, _: {
                'AWS Access Key ID': 'test_key_id',
                'AWS Secret Access Key': 'test_secret',
                'AWS Region Name': 'us-east-1'
            }.get(field))
        )]

        # Mock get_secret
        self.sync._get_secret = Mock(return_value='value1')

        # Capture output
        self.sync._output = Mock()

        # Run sync
        map_data = [
            {"mapKey": "new_kms_key+json_key1", "mapNotation": "keeper://rec1/field", "srcValue": "value1", "dstValue": None}
        ]

        self.sync.sync_aws_json(
            credentials='cred_uid',
            dry_run=False,
            preserve_missing=False,
            map=map_data
        )

        # Verify new secret was created as JSON even with single value
        mock_client.create_secret.assert_called_once()
        call_args = mock_client.create_secret.call_args
        written_json = json.loads(call_args[1]['SecretString'])

        self.assertEqual(written_json['json_key1'], 'value1')
        self.assertEqual(len(written_json), 1)


    @patch('boto3.client')
    def test_sync_mixed_formats(self, mock_boto_client):
        """Test syncing with both plain and JSON formats for different keys"""
        # Setup mocks
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock get_secret_value to return different values for different keys
        def get_secret_side_effect(SecretId):
            if SecretId == 'plain_key':
                return {'SecretString': 'existing_plain_value'}
            elif SecretId == 'json_key':
                return {'SecretString': '{"existing": "json_value"}'}
            else:
                from botocore.exceptions import ClientError
                raise ClientError(
                    {'Error': {'Code': 'ResourceNotFoundException'}},
                    'GetSecretValue'
                )

        mock_client.get_secret_value.side_effect = get_secret_side_effect
        mock_client.put_secret_value.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        mock_client.create_secret.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}

        # Mock Keeper credentials
        self.cli_mock.client.get_secrets.return_value = [Mock(
            uid='cred_uid',
            get_standard_field_value=Mock(return_value=None),
            get_custom_field_value=Mock(side_effect=lambda field, _: {
                'AWS Access Key ID': 'test_key_id',
                'AWS Secret Access Key': 'test_secret',
                'AWS Region Name': 'us-east-1'
            }.get(field))
        )]

        # Mock _get_secret to return values
        self.sync._get_secret = Mock(side_effect=['plain_value', 'json_value1', 'json_value2'])

        # Capture output
        outputs = []
        original_output = self.sync._output
        self.sync._output = Mock(side_effect=lambda data, hide_data=False: outputs.append(data))

        # Run sync with mixed formats
        map_data = [
            {"mapKey": "plain_key", "mapNotation": "keeper://rec1/field", "srcValue": "plain_value", "dstValue": None},
            {"mapKey": "json_key+field1", "mapNotation": "keeper://rec2/field", "srcValue": "json_value1", "dstValue": None},
            {"mapKey": "json_key+field2", "mapNotation": "keeper://rec3/field", "srcValue": "json_value2", "dstValue": None}
        ]

        # Mock sync_aws_with_client and sync_aws_json_with_client to track calls
        with patch.object(self.sync, 'sync_aws_with_client') as mock_sync_aws, \
             patch.object(self.sync, 'sync_aws_json_with_client') as mock_sync_json:

            # Make the mocked methods call the original output
            def sync_aws_side_effect(secretsmanager, dry_run, preserve_missing, map):
                original_output(map, True)
            def sync_json_side_effect(secretsmanager, dry_run, preserve_missing, map):
                original_output(map, True)

            mock_sync_aws.side_effect = sync_aws_side_effect
            mock_sync_json.side_effect = sync_json_side_effect

            # Need to mock _get_secret for sync_values to work
            self.sync._get_secret = Mock(side_effect=['plain_value', 'json_value1', 'json_value2'])

            self.sync.sync_values(
                type='aws',
                credentials='cred_uid',
                dry_run=False,
                preserve_missing=False,
                map=[
                    ('plain_key', 'keeper://rec1/field'),
                    ('json_key+field1', 'keeper://rec2/field'),
                    ('json_key+field2', 'keeper://rec3/field')
                ]
            )

            # Verify both sync methods were called with appropriate data
            mock_sync_aws.assert_called_once()
            plain_map = mock_sync_aws.call_args[0][3]
            self.assertEqual(len(plain_map), 1)
            self.assertEqual(plain_map[0]["mapKey"], "plain_key")

            mock_sync_json.assert_called_once()
            json_map = mock_sync_json.call_args[0][3]
            self.assertEqual(len(json_map), 2)
            self.assertIn("json_key+field1", [m["mapKey"] for m in json_map])
            self.assertIn("json_key+field2", [m["mapKey"] for m in json_map])


if __name__ == '__main__':
    unittest.main()