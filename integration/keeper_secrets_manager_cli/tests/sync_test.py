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
                sync_type='aws',
                maps=[
                    ('my_key', 'keeper://record1/field/password'),  # Plain format
                    ('my_key+json_key', 'keeper://record2/field/api_key')  # JSON format for same KMS key
                ]
            )
        self.assertIn("Cannot use both plain and JSON format for the same AWS secret name", str(context.exception))

    def test_allow_mixed_formats_different_keys(self):
        """Test that mixing formats with different KMS keys is allowed"""
        # Mock _get_secret to return values
        self.sync._get_secret = Mock(side_effect=['value1', 'value2', 'value3'])

        # This should not raise an exception
        try:
            self.sync.sync_values(
                sync_type='aws',
                maps=[
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
                sync_type='aws',
                maps=[
                    ('kms_key+json_key1', 'keeper://record1/field/password'),
                    ('kms_key+json_key1', 'keeper://record2/field/api_key')
                ]
            )
        self.assertIn("Duplicate keys found (from --map)", str(context.exception))
        self.assertIn("Duplicate JSON keys within same KMS key", str(context.exception))

    def test_validate_duplicate_plain_keys(self):
        """Test that duplicate plain keys raises an error"""
        with self.assertRaises(KsmCliException) as context:
            self.sync.sync_values(
                sync_type='aws',
                maps=[
                    ('plain_key', 'keeper://record1/field/password'),
                    ('plain_key', 'keeper://record2/field/api_key'),
                    ('plain_key', 'keeper://record3/field/token')
                ]
            )
        self.assertIn("Duplicate keys found (from --map)", str(context.exception))
        self.assertIn("Duplicate plain keys", str(context.exception))
        self.assertIn("'plain_key' appears 3 times", str(context.exception))

    def test_validate_all_duplicate_types(self):
        """Test that all types of duplicates are reported together"""
        with self.assertRaises(KsmCliException) as context:
            self.sync.sync_values(
                sync_type='aws',
                maps=[
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
        self.assertIn("Duplicate keys found (from --map)", error_msg)
        self.assertIn("Duplicate plain keys", error_msg)
        self.assertIn("'plain_key1' appears 2 times", error_msg)
        self.assertIn("Duplicate JSON keys within same KMS key", error_msg)
        self.assertIn("Cannot use both plain and JSON format for the same AWS secret name", error_msg)
        self.assertIn("overlap_key", error_msg)

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
            maps=map_data
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
            maps=map_data
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
            maps=map_data
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
            maps=map_data
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
            def sync_aws_side_effect(secretsmanager, dry_run, preserve_missing, maps):
                original_output(maps, True)
            def sync_json_side_effect(secretsmanager, dry_run, preserve_missing, maps):
                original_output(maps, True)

            mock_sync_aws.side_effect = sync_aws_side_effect
            mock_sync_json.side_effect = sync_json_side_effect

            # Need to mock _get_secret for sync_values to work
            self.sync._get_secret = Mock(side_effect=['plain_value', 'json_value1', 'json_value2'])

            self.sync.sync_values(
                sync_type='aws',
                credentials='cred_uid',
                dry_run=False,
                preserve_missing=False,
                maps=[
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

    def test_validate_aws_secret_name(self):
        """Test AWS secret name validation and error aggregation"""
        # Test valid characters (should pass with no errors)
        valid_name = "test-secret_123"
        name, error = self.sync._validate_aws_secret_name(valid_name)
        self.assertEqual(name, valid_name)
        self.assertIsNone(error)

        # Test space replacement only (no errors after conversion)
        name_with_spaces = "test secret name"
        name, error = self.sync._validate_aws_secret_name(name_with_spaces)
        self.assertEqual(name, "test_secret_name")  # Spaces replaced
        self.assertIsNone(error)  # No error after space replacement

        # Test invalid characters (spaces are replaced, # is invalid)
        invalid_name = "test@secret#123 with spaces"
        name, error = self.sync._validate_aws_secret_name(invalid_name)
        self.assertEqual(name, "test@secret#123_with_spaces")  # Spaces replaced with underscores
        self.assertIsNotNone(error)
        self.assertIn("invalid characters", error)
        self.assertIn("'#'", error)
        # Space should NOT be in error list since it's auto-replaced

        # Test empty name
        name, error = self.sync._validate_aws_secret_name("")
        self.assertIsNotNone(error)
        self.assertIn("between 1 and 512 character", error)

        # Test long name
        long_name = "a" * 513
        name, error = self.sync._validate_aws_secret_name(long_name)
        self.assertIsNotNone(error)
        self.assertIn("between 1 and 512 character", error)

        # Test ARN suffix behavior (warning only, not an error)
        arn_suffix_name = "test-key-abc123"
        name, error = self.sync._validate_aws_secret_name(arn_suffix_name)
        self.assertEqual(name, arn_suffix_name)  # Name unchanged
        self.assertIsNone(error)  # ARN suffix is just a warning, not an error

    def test_resolve_records(self):
        """Test record resolution by UID and title"""
        # Mock secrets
        mock_secret1 = Mock()
        mock_secret1.uid = "uid1"
        mock_secret1.title = "Record 1"

        mock_secret2 = Mock()
        mock_secret2.uid = "uid2"
        mock_secret2.title = "Record 2"

        self.cli_mock.client.get_secrets.return_value = [mock_secret1, mock_secret2]

        # Test resolution by UID
        result = self.sync._resolve_records(["uid1"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].uid, "uid1")

        # Test resolution by title
        result = self.sync._resolve_records(["Record 2"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].title, "Record 2")

        # Test duplicate removal
        result = self.sync._resolve_records(["uid1", "uid1"])
        self.assertEqual(len(result), 1)

        # Test no match
        with self.assertRaises(KsmCliException) as context:
            self.sync._resolve_records(["nonexistent"])
        self.assertIn("Record resolution errors:", str(context.exception))
        self.assertIn("No record found matching token: 'nonexistent'", str(context.exception))

        # Test multiple matches
        mock_secret3 = Mock()
        mock_secret3.uid = "uid3"
        mock_secret3.title = "Record 1"  # Same title as secret1
        self.cli_mock.client.get_secrets.return_value = [mock_secret1, mock_secret2, mock_secret3]

        with self.assertRaises(KsmCliException) as context:
            self.sync._resolve_records(["Record 1"])
        self.assertIn("Multiple records found matching 'Record 1'", str(context.exception))

    def test_resolve_records_duplicate_uids_in_vault(self):
        """Test that duplicate UIDs from get_secrets (linked records) are handled"""
        # Mock secrets with duplicate UIDs (linked records/shortcuts)
        mock_secret1 = Mock()
        mock_secret1.uid = "uid1"
        mock_secret1.title = "Original Record"

        mock_secret1_link = Mock()
        mock_secret1_link.uid = "uid1"  # Same UID - this is a link/shortcut
        mock_secret1_link.title = "Link to Original"

        mock_secret2 = Mock()
        mock_secret2.uid = "uid2"
        mock_secret2.title = "Another Record"

        # get_secrets returns duplicates
        self.cli_mock.client.get_secrets.return_value = [mock_secret1, mock_secret1_link, mock_secret2]

        # Should resolve successfully, using the first instance
        result = self.sync._resolve_records(["uid1"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].uid, "uid1")
        self.assertEqual(result[0].title, "Original Record")  # Should get the first one

        # Resolving by different title that maps to same UID should work
        result = self.sync._resolve_records(["Original Record"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].uid, "uid1")

    def test_resolve_records_multiple_errors(self):
        """Test that multiple resolution errors are aggregated"""
        # Mock secrets
        mock_secret1 = Mock()
        mock_secret1.uid = "uid1"
        mock_secret1.title = "Record 1"

        mock_secret2 = Mock()
        mock_secret2.uid = "uid2"
        mock_secret2.title = "Record 1"  # Same title - will cause ambiguity

        self.cli_mock.client.get_secrets.return_value = [mock_secret1, mock_secret2]

        # Try to resolve multiple problematic tokens
        with self.assertRaises(KsmCliException) as context:
            self.sync._resolve_records(["nonexistent", "Record 1", "another_missing"])

        error_msg = str(context.exception)
        # Should have the header
        self.assertIn("Record resolution errors:", error_msg)
        # Should list all errors
        self.assertIn("No record found matching token: 'nonexistent'", error_msg)
        self.assertIn("Multiple records found matching 'Record 1'", error_msg)
        self.assertIn("No record found matching token: 'another_missing'", error_msg)

    def test_generate_record_json_raw(self):
        """Test generating raw JSON from record"""
        # Mock record with fields and custom fields
        mock_record = Mock()
        mock_record.dict = {"uid": "test", "title": "Test Record"}

        result = self.sync._generate_record_json(mock_record, raw_json=True)
        self.assertEqual(result, {"uid": "test", "title": "Test Record"})

    def test_generate_record_json_flattened(self):
        """Test generating flattened JSON from record"""
        # Mock record with dict property
        mock_record = Mock()
        mock_record.dict = {
            'fields': [
                {'type': 'password', 'value': 'secret123'},
                {'type': 'enabled', 'value': True},
                {'type': 'port', 'value': 8080}
            ],
            'custom': [
                {'label': 'API Key', 'value': 'api_key_123'}
            ]
        }

        result = self.sync._generate_record_json(mock_record, raw_json=False)

        # Result should be a dict (not JSON string)
        self.assertIsInstance(result, dict)

        # All values should be strings
        self.assertEqual(result["password"], "secret123")
        self.assertEqual(result["enabled"], "True")  # Boolean converted to string
        self.assertEqual(result["port"], "8080")  # Number converted to string
        self.assertEqual(result["API Key"], "api_key_123")

        # Verify all values are strings
        for key, value in result.items():
            self.assertIsInstance(value, str, f"Value for '{key}' should be a string")

    def test_generate_record_json_array_values(self):
        """Test handling array values in flattened JSON"""
        # Mock record with dict property
        mock_record = Mock()
        mock_record.dict = {
            'fields': [
                {'type': 'tags', 'value': ['tag1', 'tag2']}
            ],
            'custom': []
        }

        result = self.sync._generate_record_json(mock_record, raw_json=False)

        # Result should be a dict
        self.assertIsInstance(result, dict)

        # Array should be JSON stringified (using compact separators)
        self.assertEqual(result["tags"], '["tag1","tag2"]')

    def test_generate_record_json_single_array_value(self):
        """Test handling single item arrays"""
        # Mock record with dict property
        mock_record = Mock()
        mock_record.dict = {
            'fields': [
                {'type': 'username', 'value': ['admin']},
                {'type': 'count', 'value': [42]}
            ],
            'custom': []
        }

        result = self.sync._generate_record_json(mock_record, raw_json=False)

        # Result should be a dict
        self.assertIsInstance(result, dict)

        # Single item arrays should be unwrapped and converted to strings
        self.assertEqual(result["username"], "admin")
        self.assertEqual(result["count"], "42")  # Number converted to string

        # Verify all values are strings
        for key, value in result.items():
            self.assertIsInstance(value, str, f"Value for '{key}' should be a string")

    def test_sync_values_with_record_option(self):
        """Test sync_values with --record option"""
        # Mock resolved records
        mock_record = Mock()
        mock_record.uid = "test_uid"
        mock_record.title = "Test Record"
        mock_record.fields = []
        mock_record.custom = []

        with patch.object(self.sync, '_resolve_records') as mock_resolve, \
             patch.object(self.sync, '_validate_aws_secret_name') as mock_validate, \
             patch.object(self.sync, '_generate_record_json') as mock_generate, \
             patch.object(self.sync, '_get_aws_client') as mock_get_client, \
             patch.object(self.sync, '_output') as mock_output:

            mock_resolve.return_value = [mock_record]
            mock_validate.return_value = ("test-record", None)  # Return tuple (name, error)
            mock_generate.return_value = '{"password":"secret123"}'
            mock_aws_client = Mock()
            mock_get_client.return_value = mock_aws_client

            # Mock the AWS sync methods
            with patch.object(self.sync, 'sync_aws_json_with_client') as mock_sync_json, \
                 patch.object(self.sync, 'sync_aws_with_client') as mock_sync_aws:

                self.sync.sync_values(
                    sync_type='aws',
                    credentials='cred_uid',
                    dry_run=False,
                    preserve_missing=False,
                    maps=None,
                    records=['Test Record'],
                    raw_json=False
                )

                # Verify record was resolved
                mock_resolve.assert_called_once_with(['Test Record'])

                # Verify secret name was validated
                mock_validate.assert_called_once_with("Test Record")

                # Verify JSON was generated
                mock_generate.assert_called_once_with(mock_record, False)

                # Verify sync was called with record data
                mock_sync_json.assert_called_once()
                # Check the secretsmanager client argument
                self.assertEqual(mock_sync_json.call_args[0][0], mock_aws_client)
                # Check the map parameter
                call_args = mock_sync_json.call_args[0][3]  # map parameter
                self.assertEqual(len(call_args), 1)
                self.assertEqual(call_args[0]["mapKey"], "test-record")
                self.assertEqual(call_args[0]["srcValue"], '{"password":"secret123"}')

    def test_sync_values_with_raw_json(self):
        """Test sync_values with --raw-json flag"""
        # Mock resolved records
        mock_record = Mock()
        mock_record.uid = "test_uid"
        mock_record.title = "Test Record"
        mock_record.fields = []
        mock_record.custom = []

        with patch.object(self.sync, '_resolve_records') as mock_resolve, \
             patch.object(self.sync, '_validate_aws_secret_name') as mock_validate, \
             patch.object(self.sync, '_generate_record_json') as mock_generate, \
             patch.object(self.sync, '_get_aws_client') as mock_get_client:

            mock_resolve.return_value = [mock_record]
            mock_validate.return_value = ("test-record", None)  # Return tuple (name, error)
            mock_generate.return_value = '{"full":"json","content":"here"}'
            mock_get_client.return_value = Mock()

            # Mock the AWS sync methods
            with patch.object(self.sync, 'sync_aws_json_with_client') as mock_sync_json:

                self.sync.sync_values(
                    sync_type='aws',
                    credentials='cred_uid',
                    dry_run=False,
                    preserve_missing=False,
                    maps=None,
                    records=['Test Record'],
                    raw_json=True
                )

                # Verify JSON was generated with raw_json=True
                mock_generate.assert_called_once_with(mock_record, True)

    def test_sync_values_duplicate_keys_validation(self):
        """Test validation of duplicate keys between --map and --record"""
        # Mock resolved records
        mock_record = Mock()
        mock_record.uid = "test_uid"
        mock_record.title = "duplicate-key"  # Same as map key
        mock_record.dict = {
            'fields': [],
            'custom': []
        }

        with patch.object(self.sync, '_resolve_records') as mock_resolve, \
             patch.object(self.sync, '_validate_aws_secret_name') as mock_validate:

            mock_resolve.return_value = [mock_record]
            mock_validate.return_value = ("duplicate-key", None)  # Return tuple, same as map key

            with self.assertRaises(KsmCliException) as context:
                self.sync.sync_values(
                    sync_type='aws',
                    credentials='cred_uid',
                    dry_run=False,
                    preserve_missing=False,
                    maps=[('duplicate-key', 'keeper://rec/field')],
                    records=['Test Record'],
                    raw_json=False
                )

            self.assertIn("Duplicate keys found between --map and --record", str(context.exception))

    def test_sync_values_record_only_validation(self):
        """Test that sync_values returns early when no data to sync"""
        # Mock the output to capture messages
        output_called = []
        def capture_output(*args, **kwargs):
            output_called.append(True)

        self.sync._output = capture_output

        # This should return early without processing
        self.sync.sync_values(
            sync_type='aws',
            credentials='cred_uid',
            dry_run=False,
            preserve_missing=False,
            maps=None,
            records=None,
            raw_json=False
        )

        # Verify that _output was not called (sync returned early)
        self.assertEqual(len(output_called), 0, "sync_values should return early when no data provided")

    def test_sync_aws_json_with_client_record_based(self):
        """Test sync_aws_json_with_client with record-based entries"""
        mock_client = Mock()

        # Mock existing JSON value
        existing_json = {"existing": "value"}
        mock_client.get_secret_value.return_value = {
            'SecretString': json.dumps(existing_json)
        }

        # Mock successful update
        mock_client.put_secret_value.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}

        # Test data with record-based entry (no + in key)
        map_data = [
            {
                "mapKey": "test-record",
                "mapNotation": "record:test_uid",
                "srcValue": '{"password":"new_secret"}',
                "dstValue": None
            }
        ]

        # Mock _get_secret_aws and _set_secret_aws
        with patch.object(self.sync, '_get_secret_aws') as mock_get, \
             patch.object(self.sync, '_set_secret_aws') as mock_set:

            mock_get.return_value = {"value": json.dumps(existing_json)}
            mock_set.return_value = {"success": True}

            # Capture output
            outputs = []
            def capture_output(data, hide_data=False):
                outputs.append(data)

            self.sync._output = capture_output

            # Run sync
            self.sync.sync_aws_json_with_client(
                mock_client,
                dry_run=False,
                preserve_missing=False,
                maps=map_data
            )

            # Verify deep comparison was performed
            mock_get.assert_called_once_with(mock_client, "test-record")

            # Verify update was called with new JSON
            mock_set.assert_called_once()
            call_args = mock_set.call_args
            self.assertEqual(call_args[0][1], "test-record")  # key
            written_json = json.loads(call_args[0][2])  # value
            self.assertEqual(written_json["password"], "new_secret")

    def test_sync_aws_json_with_client_deep_comparison_no_changes(self):
        """Test that no update occurs when JSON content is identical"""
        mock_client = Mock()

        # Mock existing JSON value
        existing_json = {"password": "secret123", "username": "admin"}
        mock_client.get_secret_value.return_value = {
            'SecretString': json.dumps(existing_json)
        }

        # Test data with same content
        map_data = [
            {
                "mapKey": "test-record",
                "mapNotation": "record:test_uid",
                "srcValue": json.dumps(existing_json),  # Same content
                "dstValue": None
            }
        ]

        # Mock _get_secret_aws and _set_secret_aws
        with patch.object(self.sync, '_get_secret_aws') as mock_get, \
             patch.object(self.sync, '_set_secret_aws') as mock_set:

            mock_get.return_value = {"value": json.dumps(existing_json)}

            # Capture output
            outputs = []
            def capture_output(data, hide_data=False):
                outputs.append(data)

            self.sync._output = capture_output

            # Run sync
            self.sync.sync_aws_json_with_client(
                mock_client,
                dry_run=False,
                preserve_missing=False,
                maps=map_data
            )

            # Verify no update was called (deep comparison detected no changes)
            mock_set.assert_not_called()


    def test_sync_values_record_duplicate_key_check(self):
        """Test that duplicate keys between --map and --record are detected"""
        # Mock resolved records
        mock_record = Mock()
        mock_record.uid = "test_uid"
        mock_record.title = "test_key"  # Same as map key
        mock_record.dict = {
            'fields': [],
            'custom': []
        }

        with patch.object(self.sync, '_resolve_records') as mock_resolve, \
             patch.object(self.sync, '_validate_aws_secret_name') as mock_validate:

            mock_resolve.return_value = [mock_record]
            mock_validate.return_value = ("test_key", None)  # Return tuple, same name as map key

            # This should raise exception due to duplicate key
            with self.assertRaises(KsmCliException) as context:
                self.sync.sync_values(
                    sync_type='aws',
                    credentials='cred_uid',
                    dry_run=False,
                    preserve_missing=False,
                    maps=[('test_key', 'keeper://record/field')],
                    records=['test_key'],
                    raw_json=False
                )

            self.assertIn("Duplicate keys found between --map and --record", str(context.exception))

    def test_generate_record_json_empty_fields(self):
        """Test that empty fields are properly filtered in flattened JSON"""
        # Mock record with dict property
        mock_record = Mock()
        mock_record.dict = {
            'fields': [
                {'type': 'empty_string', 'value': ''},
                {'type': 'empty_array', 'value': []},
                {'type': 'none_value', 'value': None},
                {'type': 'valid_value', 'value': 'test'}
            ],
            'custom': []
        }

        result = self.sync._generate_record_json(mock_record, raw_json=False)

        # Result should be a dict
        self.assertIsInstance(result, dict)

        # Only valid_value should be present
        self.assertEqual(len(result), 1)
        self.assertEqual(result["valid_value"], "test")
        self.assertNotIn("empty_string", result)
        self.assertNotIn("empty_array", result)
        self.assertNotIn("none_value", result)

    def test_validate_aws_secret_name_unicode(self):
        """Test AWS secret name validation with unicode characters"""
        # Test unicode characters (should report as invalid)
        unicode_name = "café-münchen"
        name, error = self.sync._validate_aws_secret_name(unicode_name)
        self.assertEqual(name, unicode_name)  # Name unchanged
        self.assertIsNotNone(error)
        self.assertIn("invalid characters", error)
        self.assertIn("'é'", error)
        self.assertIn("'ü'", error)

        # Test emoji (should report as invalid)
        emoji_name = "test-🔒-secret"
        name, error = self.sync._validate_aws_secret_name(emoji_name)
        self.assertEqual(name, emoji_name)  # Name unchanged
        self.assertIsNotNone(error)
        self.assertIn("invalid characters", error)
        self.assertIn("'🔒'", error)

    def test_sync_aws_json_preserve_plaintext(self):
        """Test that existing plaintext values are preserved when updating JSON"""
        mock_client = Mock()

        # Mock existing plaintext value
        mock_client.get_secret_value.return_value = {
            'SecretString': 'plain_text_value'
        }

        # Test data with JSON content
        map_data = [
            {
                "mapKey": "test_key+json_field",
                "mapNotation": "keeper://record/field",
                "srcValue": "json_value",
                "dstValue": None
            }
        ]

        # Mock _get_secret_aws and _set_secret_aws
        with patch.object(self.sync, '_get_secret_aws') as mock_get, \
             patch.object(self.sync, '_set_secret_aws') as mock_set:

            mock_get.return_value = {"value": "plain_text_value"}
            mock_set.return_value = {"success": True}

            # Capture output
            self.sync._output = Mock()

            # Run sync
            self.sync.sync_aws_json_with_client(
                mock_client,
                dry_run=False,
                preserve_missing=False,
                maps=map_data
            )

            # Verify set was called with preserved plaintext
            mock_set.assert_called_once()
            call_args = mock_set.call_args[0]
            written_json = json.loads(call_args[2])  # value
            self.assertEqual(written_json["_preserved_plaintext"], "plain_text_value")
            self.assertEqual(written_json["json_field"], "json_value")


    def test_sync_values_record_validation_errors_aggregated(self):
        """Test that all record validation errors are aggregated and displayed together"""
        # Mock multiple records with various validation issues
        mock_record1 = Mock()
        mock_record1.uid = "uid1"
        mock_record1.title = "Valid Name"  # Valid after space replacement
        mock_record1.fields = []
        mock_record1.custom = []

        mock_record2 = Mock()
        mock_record2.uid = "uid2"
        mock_record2.title = "Invalid#Name"  # Has invalid character
        mock_record2.fields = []
        mock_record2.custom = []

        mock_record3 = Mock()
        mock_record3.uid = "uid3"
        mock_record3.title = "a" * 513  # Too long
        mock_record3.fields = []
        mock_record3.custom = []

        with patch.object(self.sync, '_resolve_records') as mock_resolve, \
             patch.object(self.sync, '_generate_record_json') as mock_generate:

            mock_resolve.return_value = [mock_record1, mock_record2, mock_record3]
            mock_generate.return_value = '{"test":"data"}'

            # This should raise exception with aggregated errors
            with self.assertRaises(KsmCliException) as context:
                self.sync.sync_values(
                    sync_type='aws',
                    credentials='cred_uid',
                    dry_run=False,
                    preserve_missing=False,
                    maps=None,
                    records=['Valid Name', 'Invalid#Name', 'LongName'],
                    raw_json=False
                )

            error_msg = str(context.exception)
            # Should have the header
            self.assertIn("AWS KMS secret name validation errors:", error_msg)
            # Should list the invalid character error
            self.assertIn("'Invalid#Name' (UID: uid2):", error_msg)
            self.assertIn("invalid characters", error_msg)
            self.assertIn("'#'", error_msg)
            # Should list the length error
            self.assertIn(f"(UID: uid3):", error_msg)
            self.assertIn("between 1 and 512 character", error_msg)
            # Valid record should not appear in errors
            self.assertNotIn("uid1", error_msg)


if __name__ == '__main__':
    unittest.main()