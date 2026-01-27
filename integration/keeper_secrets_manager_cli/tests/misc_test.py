import os
import unittest
from unittest.mock import patch
from conftest import CliRunner
import tempfile

from keeper_secrets_manager_cli.config import Config
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.utils import get_windows_user_sid_and_name
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_cli.__main__ import cli
from sys import platform
import subprocess


class MiscTest(unittest.TestCase):

    def setUp(self) -> None:
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)
        self.delete_me = []
        os.environ.pop("KSM_CONFIG_SKIP_MODE_WARNING", None)

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

        # Github Action does like how I'm doing temp files. So we manually have to delete them. This is to avoid
        # Cannot execute command: [Errno 26] Text file busy: '/tmp/tmpsp3v5vqb'
        for item in self.delete_me:
            os.unlink(item)
        os.environ.pop("KSM_CONFIG_SKIP_MODE_WARNING", None)

    def test_config_mode_dog_food(self):

        mock_config = MockConfig.make_config()

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        res = mock.Response()

        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")
        one.custom_field("My Custom 1", "custom1")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client, \
             patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available', return_value=False):
            mock_client.return_value = secrets_manager

            # Create a keeper.ini with the default profile
            default_token = "XYZ321"
            runner = CliRunner()

            result = runner.invoke(cli, ['profile', 'init', '-t', default_token], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success for default init")
            self.assertTrue(os.path.exists(Config.default_ini_file), "could not find ini file")

            if platform.lower().startswith("win"):
                sid, user = get_windows_user_sid_and_name()
                sp = subprocess.run(["icacls.exe", Config.default_ini_file], capture_output=True)
                if sp.stderr is not None and sp.stderr.decode() != "":
                    self.fail("Could not icacls.exe {}: {}".format(Config.default_ini_file,sp.stderr.decode()))
                allowed_users = [user.decode().lower(), "Administrators".lower()]
                for line in sp.stdout.decode().split("\n"):
                    parts = line[len(Config.default_ini_file):].split(":")
                    if len(parts) == 2:
                        found_user = parts[0].split("\\").pop()
                        if found_user.lower() not in allowed_users:
                            self.fail("Found user {} access on config file".format(found_user))
            else:
                stat = os.stat(Config.default_ini_file)
                self.assertEqual("600", oct(stat.st_mode)[-3:], "the keeper.ini has the wrong mode")

            result = runner.invoke(cli, ['secrets', 'list'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success for secrets list")
            print(result.output)

            # Make sure no warnings appear about config file
            assert "Access denied" not in result.output
            assert "too open" not in result.output

    def test_config_mode_too_open(self):

        mock_config = MockConfig.make_config()

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        res = mock.Response()

        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")
        one.custom_field("My Custom 1", "custom1")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client, \
             patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available', return_value=False):
            mock_client.return_value = secrets_manager

            # Create a keeper.ini with the default profile
            default_token = "XYZ321"
            runner = CliRunner()

            result = runner.invoke(cli, ['profile', 'init', '-t', default_token], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success for default init")
            self.assertTrue(os.path.exists(Config.default_ini_file), "could not find ini file")

            # Open up the config
            if platform.lower().startswith("win"):
                sp = subprocess.run('icacls.exe "{}" /grant Guest:F'.format(Config.default_ini_file))
                if sp.stderr is not None and sp.stderr.decode() != "":
                    self.fail("Could not icacls.exe {}: {}".format(Config.default_ini_file, sp.stderr.decode()))
                sp = subprocess.run(["icacls.exe", Config.default_ini_file], capture_output=True)
                print(sp.stdout.decode())
            else:
                os.chmod(Config.default_ini_file, 0o0644)

            result = runner.invoke(cli, ['secrets', 'list'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success for secrets list")
            print(result.output)

            # The phrase "too open" should appear in the warning message
            assert "too open" in result.output

    def test_config_mode_access_denied(self):

        mock_config = MockConfig.make_config()

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        res = mock.Response()

        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")
        one.custom_field("My Custom 1", "custom1")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client, \
             patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available', return_value=False):
            mock_client.return_value = secrets_manager

            # Create a keeper.ini with the default profile
            default_token = "XYZ321"
            runner = CliRunner()

            result = runner.invoke(cli, ['profile', 'init', '-t', default_token], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success for default init")
            self.assertTrue(os.path.exists(Config.default_ini_file), "could not find ini file")

            # Remove all rights from the ini file
            if platform.lower().startswith("win"):

                for cmd in ['icacls.exe {} /reset'.format(Config.default_ini_file),
                            'icacls.exe {} /inheritance:r'.format(Config.default_ini_file),
                            'icacls.exe {} /remove Everyone'.format(Config.default_ini_file)]:
                    subprocess.run(cmd, capture_output=True)
            else:
                os.chmod(Config.default_ini_file, 0o0000)

            try:
                result = runner.invoke(cli, ['--log-level', 'DEBUG', 'secrets', 'list'], catch_exceptions=False)
                self.assertEqual(0, result.exit_code, "did not get a success for secrets list")
                self.fail("Should fail due to file mode change")
            except Exception as err:
                assert "Access denied" in str(err)
