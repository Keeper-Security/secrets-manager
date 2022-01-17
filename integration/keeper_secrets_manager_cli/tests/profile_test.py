import base64
import os
import unittest
from unittest.mock import patch
from click.testing import CliRunner
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_cli.profile import Profile
from keeper_secrets_manager_cli.__main__ import cli
import tempfile
import configparser
import json
import re


class ProfileTest(unittest.TestCase):

    def setUp(self) -> None:
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

        # Clear env var from other tests
        os.environ.pop("KSM_CONFIG_BASE64_1", None)
        os.environ.pop("KSM_CONFIG_BASE64_DESC_1", None)
        os.environ.pop("KSM_CONFIG_BASE64_2", None)
        os.environ.pop("KSM_CONFIG_BASE64_DESC_2", None)

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

    def test_the_works(self):

        """ Test initializing the profile
        """

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
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            default_token = "XYZ321"
            runner = CliRunner()
            result = runner.invoke(cli, ['profile', 'init', '-t', default_token], catch_exceptions=False)
            print(result.output)
            self.assertEqual(0, result.exit_code, "did not get a success for default init")
            self.assertTrue(os.path.exists(Profile.default_ini_file), "could not find ini file")

            test_token = "ABC123"
            result = runner.invoke(cli, ['profile', 'init', "-p", "test", '-t',
                                         test_token], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success for test init")
            self.assertTrue(os.path.exists(Profile.default_ini_file), "could not find ini file")

            config = configparser.ConfigParser()
            config.read(Profile.default_ini_file)

            self.assertTrue(Profile.default_profile in config, "Could not find the default profile in the config.")
            self.assertTrue("test" in config, "Could not find the test profile in the config.")

            self.assertEqual(default_token, config[Profile.default_profile]["clientkey"],
                             "could not find default client key")
            self.assertEqual(test_token, config["test"]["clientkey"], "could not find default client key")

            # ------------------------

            result = runner.invoke(cli, ['profile', 'list', '--json'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success on list")
            profiles = json.loads(result.output)

            default_item = next((profile for profile in profiles if profile["name"] == Profile.default_profile), None)
            self.assertIsNotNone(default_item, "could not find default profile in list")
            self.assertTrue(default_item["active"], "default profile is not active")

            test_item = next((profile for profile in profiles if profile["name"] == "test"), None)
            self.assertIsNotNone(test_item, "could not find default profile in list")
            self.assertFalse(test_item["active"], "test profile is active")

            # ------------------------

            result = runner.invoke(cli, ['profile', 'active', 'test'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success on active")

            result = runner.invoke(cli, ['profile', 'list', '--json'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success on list")
            profiles = json.loads(result.output)

            default_item = next((profile for profile in profiles if profile["name"] == Profile.default_profile), None)
            self.assertIsNotNone(default_item, "could not find default profile in list")
            self.assertFalse(default_item["active"], "default profile is active")

            test_item = next((profile for profile in profiles if profile["name"] == "test"), None)
            self.assertIsNotNone(test_item, "could not find default profile in list")
            self.assertTrue(test_item["active"], "test profile is not active")

    def test_config_ini_import_export(self):

        mock_config = MockConfig.make_config()

        ini_config = '''
[_default]
clientkey = D_XXXXX_CK
clientid = D_XXXXX_CI
privatekey = D_XXXXX_PK
appkey = D_XXXX_AK
hostname = {}

[Another]
clientkey = A_XXXXX_CK
clientid = A_XXXXX_CI
privatekey = A_XXXXX_PK
appkey = A_XXXX_AK
hostname = {}

[_config]
active_profile = _default
color = True
        '''.format(mock_config.get("hostname"), mock_config.get("hostname"))

        runner = CliRunner()

        # Test INI import
        base64_config = base64.urlsafe_b64encode(ini_config.encode())
        self.assertFalse(os.path.exists("keeper.ini"), "an ini config file already exists")

        result = runner.invoke(cli, ['profile', 'import', base64_config.decode()], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on list")
        self.assertTrue(os.path.exists("keeper.ini"), "the ini config doesn't exists")
        with open("keeper.ini", "r") as fh:
            file_config = fh.read()
            fh.close()
            self.assertEqual(ini_config, file_config, "config on disk and defined above are not the same.")

        # Test INI export. Get the 'Another' profile

        result = runner.invoke(cli, ['profile', 'export', "Another"], catch_exceptions=False)
        print(result.output)
        self.assertEqual(0, result.exit_code, "did not get a success on list")
        config_data = result.output

        try:
            config = base64.urlsafe_b64decode(config_data).decode()
            self.assertRegex(config, r'A_XXXXX_CK', 'did not find the Another client key')
            self.assertFalse(re.search(r'D_XXXXX_CK', config, re.MULTILINE), 'found the default client key')
        except Exception as err:
            self.fail("Could not base64 decode the config: {}".format(err))

    def test_config_json_import_export(self):

        json_config = MockConfig.make_config()

        runner = CliRunner()

        # Test INI import
        base64_config = base64.urlsafe_b64encode(json.dumps(json_config).encode())

        self.assertFalse(os.path.exists("keeper.ini"), "an ini config file already exists")

        result = runner.invoke(cli, ['profile', 'import', base64_config.decode()], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on list")
        self.assertTrue(os.path.exists("keeper.ini"), "the ini config doesn't exists")
        with open("keeper.ini", "r") as fh:
            file_config = fh.read()
            fh.close()
            assert json_config["clientId"] in file_config, "did not find the client id"
            assert json_config["privateKey"] in file_config, "blah"

        config = configparser.ConfigParser()
        config.read("keeper.ini")
        self.assertEqual(json_config["clientKey"], config["_default"].get("clientkey"),  "client keys match")

        result = runner.invoke(cli, ['profile', 'export', '--file-format=json'],
                               catch_exceptions=False)
        print(result.output)
        self.assertEqual(0, result.exit_code, "did not get a success on list")
        config_data = result.output

        try:
            test_config = base64.urlsafe_b64decode(config_data).decode()
            config = json.loads(test_config)
            self.assertEqual(json_config["hostname"], config["hostname"], "host name is not the same")

        except Exception as err:
            self.fail("Could not base64/json decode the config: {}".format(err))

    def test_auto_config(self):

        json_config = MockConfig.make_config()
        base64_config = base64.urlsafe_b64encode(json.dumps(json_config).encode())

        runner = CliRunner()

        # Create two configs
        os.environ["KSM_CONFIG_BASE64_1"] = base64_config.decode()
        os.environ["KSM_CONFIG_BASE64_DESC_1"] = "App1"
        os.environ["KSM_CONFIG_BASE64_2"] = base64_config.decode()
        os.environ["KSM_CONFIG_BASE64_DESC_2"] = "App2"

        # Using a file output due to cli runner joining stdout and stderr
        with tempfile.NamedTemporaryFile() as tf:
            result = runner.invoke(cli, [
                '-o', tf.name,
                'profile', 'list', '--json'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success on list")
            tf.seek(0)
            profile_data = json.load(tf)
            self.assertEqual("App1", profile_data[0]["name"], "found first app")
            self.assertEqual("App2", profile_data[1]["name"], "found second app")

    def test_import_sdk_json(self):

        mock_config = MockConfig.make_config()
        base64_json = MockConfig.make_base64(config=mock_config)

        runner = CliRunner()

        result = runner.invoke(cli, ['profile', 'import', base64_json], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on list")
        self.assertTrue(os.path.exists("keeper.ini"), "the ini config doesn't exists")

        config = configparser.ConfigParser()
        config.read(Profile.default_ini_file)

        profile = config["_default"]
        self.assertIsNotNone(profile, "could not find the profile")
        self.assertEqual(mock_config.get("appKey"), profile.get("appKey"), "did not get the correct app key")
        self.assertEqual(mock_config.get("hostname"), profile.get("hostname"), "did not get the correct hostname")

    def test_auto_config_sdk_json(self):

        mock_config = MockConfig.make_config()
        base64_json = MockConfig.make_base64(config=mock_config)

        runner = CliRunner()

        # Create two configs
        os.environ["KSM_CONFIG_BASE64_1"] = base64_json
        os.environ["KSM_CONFIG_BASE64_DESC_1"] = "SDK"

        # Using a file output due to cli runner joining stdout and stderr
        with tempfile.NamedTemporaryFile() as tf:
            result = runner.invoke(cli, [
                '-o', tf.name,
                'profile', 'list', '--json'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success on list")
            tf.seek(0)
            profile_data = json.load(tf)
            self.assertEqual("SDK", profile_data[0]["name"], "found first app")

            config = configparser.ConfigParser()
            config.read(Profile.default_ini_file)

            profile = config["SDK"]
            self.assertIsNotNone(profile, "could not find the profile")
            self.assertEqual(mock_config.get("appKey"), profile.get("appKey"), "did not get the correct app key")
            self.assertEqual(mock_config.get("hostname"), profile.get("hostname"), "did not get the correct hostname")


if __name__ == '__main__':
    unittest.main()
