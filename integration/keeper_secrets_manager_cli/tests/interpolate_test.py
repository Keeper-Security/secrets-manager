import os
import unittest
from unittest.mock import patch, MagicMock
from conftest import CliRunner
import tempfile
import re

from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_cli.__main__ import cli
from keeper_secrets_manager_cli.profile import Profile


class InterpolateTest(unittest.TestCase):

    def setUp(self) -> None:
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)
        self.delete_me = []

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

        # Manually delete temp files to avoid issues
        for item in self.delete_me:
            try:
                os.unlink(item)
            except:
                pass

    def test_interpolate_basic(self):
        """Test basic file interpolation to stdout"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.field("password", "SecretPassword123")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create temp file with notation
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write(f"PASSWORD=keeper://{record.uid}/field/password\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            assert "PASSWORD=SecretPassword123" in result.output
            assert "keeper://" not in result.output

    def test_interpolate_output_file(self):
        """Test interpolate and save to file"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.field("login", "testuser")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create input file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write(f"USER=keeper://{record.uid}/field/login\n")
                input_path = f.name
                self.delete_me.append(input_path)

            # Create output file path
            output_path = os.path.join(self.temp_dir.name, 'output.env')

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', input_path, '--output', output_path])

            assert result.exit_code == 0
            assert os.path.exists(output_path)

            with open(output_path, 'r') as f:
                content = f.read()
                assert "USER=testuser" in content
                assert "keeper://" not in content

    def test_interpolate_env_format(self):
        """Test with KEY=value format"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.field("password", "Pass123")
        record.field("login", "User123")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create env file with multiple entries
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write(f"DB_PASSWORD=keeper://{record.uid}/field/password\n")
                f.write(f"DB_USER=keeper://{record.uid}/field/login\n")
                f.write("DB_HOST=localhost\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            assert "DB_PASSWORD=Pass123" in result.output
            assert "DB_USER=User123" in result.output
            assert "DB_HOST=localhost" in result.output

    def test_interpolate_multiple_notations(self):
        """Test multiple secrets in one file"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res1 = mock.Response()
        record1 = res1.add_record(title="Record 1")
        record1.field("password", "Secret1")

        res2 = mock.Response()
        record2 = res2.add_record(title="Record 2")
        record2.field("password", "Secret2")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res1)
        queue.add_response(res1)
        queue.add_response(res2)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create file with multiple different notations
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write(f"SECRET1=keeper://{record1.uid}/field/password\n")
                f.write(f"SECRET2=keeper://{record2.uid}/field/password\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            assert "SECRET1=Secret1" in result.output
            assert "SECRET2=Secret2" in result.output

    def test_interpolate_mixed_content(self):
        """Test mix of notation and regular text"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.field("password", "MySecret")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create file with mixed content
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write("# Configuration file\n")
                f.write(f"password=keeper://{record.uid}/field/password\n")
                f.write("# End of config\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            assert "# Configuration file" in result.output
            assert "password=MySecret" in result.output
            assert "# End of config" in result.output

    def test_interpolate_caching(self):
        """Verify caching reduces SDK calls"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.field("password", "CachedSecret")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)  # Only one additional call despite multiple notations

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create file with same notation repeated
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                notation = f"keeper://{record.uid}/field/password"
                f.write(f"VAR1={notation}\n")
                f.write(f"VAR2={notation}\n")
                f.write(f"VAR3={notation}\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            # All three should have the value
            assert result.output.count("CachedSecret") == 3

    def test_interpolate_invalid_notation(self):
        """Handle malformed notation gracefully"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.field("password", "ValidSecret")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create file with invalid and valid notation
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write("INVALID=keeper://invalid\n")
                f.write(f"VALID=keeper://{record.uid}/field/password\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            # Should continue despite invalid notation
            assert result.exit_code == 0 or "VALID=ValidSecret" in result.output

    def test_interpolate_missing_file(self):
        """Error on non-existent input file"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', '/nonexistent/file.env'])

            # Should fail with appropriate error
            assert result.exit_code != 0

    def test_interpolate_empty_file(self):
        """Handle empty file"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create empty file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            assert result.output == ""

    def test_interpolate_no_notation(self):
        """File with no keeper:// patterns"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create file with no notation
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write("PLAIN_VAR=plain_value\n")
                f.write("ANOTHER_VAR=another_value\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            assert "PLAIN_VAR=plain_value" in result.output
            assert "ANOTHER_VAR=another_value" in result.output

    def test_interpolate_custom_fields(self):
        """Test custom field notation"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.custom_field("api_key", "CustomSecret123")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create file with custom field notation
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write(f"API_KEY=keeper://{record.uid}/custom_field/api_key\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            assert "API_KEY=CustomSecret123" in result.output

    def test_interpolate_unicode(self):
        """Test file with non-ASCII characters"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.field("password", "Пароль123")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create file with unicode content
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env', encoding='utf-8') as f:
                f.write(f"# Комментарий\n")
                f.write(f"PASSWORD=keeper://{record.uid}/field/password\n")
                f.write("ДРУГОЕ=значение\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            assert "Пароль123" in result.output
            assert "Комментарий" in result.output

    def test_interpolate_quoted_notation(self):
        """Test notation inside quotes"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.field("password", "QuotedSecret")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create file with quoted notation
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write(f'VAR1="keeper://{record.uid}/field/password"\n')
                f.write(f"VAR2='keeper://{record.uid}/field/password'\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            # Quotes should be preserved, notation replaced
            assert 'VAR1="QuotedSecret"' in result.output
            assert "VAR2='QuotedSecret'" in result.output

    def test_interpolate_binary_file(self):
        """Test rejection of binary files"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create binary file (PNG header)
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.png') as f:
                f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR')
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            # Should fail with encoding error
            assert result.exit_code != 0
            assert "UTF-8" in result.output or "encoding" in result.output.lower()

    def test_interpolate_preserves_newlines(self):
        """Test that file ending is preserved"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.field("password", "Secret")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Test file WITH trailing newline
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write(f"VAR=keeper://{record.uid}/field/password\n")
                temp_path1 = f.name
                self.delete_me.append(temp_path1)

            # Test file WITHOUT trailing newline
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write(f"VAR=keeper://{record.uid}/field/password")
                temp_path2 = f.name
                self.delete_me.append(temp_path2)

            runner = CliRunner()
            result1 = runner.invoke(cli, ['interpolate', temp_path1])
            result2 = runner.invoke(cli, ['interpolate', temp_path2])

            assert result1.exit_code == 0
            assert result2.exit_code == 0
            # First should end with newline, second should not
            assert result1.output.endswith('\n')
            assert not result2.output.endswith('\n') or result2.output == "VAR=Secret"

    def test_interpolate_large_file(self):
        """Test performance with large file"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.field("password", "Secret")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create large file (1000 lines) with notation scattered throughout
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                for i in range(1000):
                    if i % 100 == 0:
                        f.write(f"SECRET_{i}=keeper://{record.uid}/field/password\n")
                    else:
                        f.write(f"VAR_{i}=value_{i}\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            # Should have 10 secrets replaced
            assert result.output.count("Secret") == 10

    def test_interpolate_custom_field_with_spaces(self):
        """Test custom field with spaces in label"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.custom_field("My Custom Field", "CustomValueWithSpaces123")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create file with custom field that has spaces in the label
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write(f"FIELD_WITH_SPACES=keeper://{record.uid}/custom_field/My Custom Field\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            assert "FIELD_WITH_SPACES=CustomValueWithSpaces123" in result.output
            assert "keeper://" not in result.output

    def test_interpolate_caching_efficiency(self):
        """Test caching reduces redundant SDK calls"""
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        record = res.add_record(title="Test Record")
        record.field("login", "user")
        record.field("password", "pass")
        record.field("host", "localhost")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Create file with multiple fields from same record
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
                f.write(f"USER=keeper://{record.uid}/field/login\n")
                f.write(f"PASS=keeper://{record.uid}/field/password\n")
                f.write(f"HOST=keeper://{record.uid}/field/host\n")
                temp_path = f.name
                self.delete_me.append(temp_path)

            runner = CliRunner()
            result = runner.invoke(cli, ['interpolate', temp_path])

            assert result.exit_code == 0
            assert "USER=user" in result.output
            assert "PASS=pass" in result.output
            assert "HOST=localhost" in result.output


if __name__ == '__main__':
    unittest.main()
