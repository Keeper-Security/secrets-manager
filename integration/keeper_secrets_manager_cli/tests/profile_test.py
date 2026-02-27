import base64
import os
import unittest
from unittest.mock import patch
from conftest import CliRunner
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_cli.profile import Profile
from keeper_secrets_manager_cli.__main__ import cli
from keeper_secrets_manager_cli.config import Config
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
        os.environ.pop("KSM_CONFIG", None)
        os.environ.pop("KSM_CONFIG_BASE64_1", None)
        os.environ.pop("KSM_CONFIG_BASE64_DESC_1", None)
        os.environ.pop("KSM_CONFIG_BASE64_2", None)
        os.environ.pop("KSM_CONFIG_BASE64_DESC_2", None)

        self.delete_me = []

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

        os.environ.pop("KSM_CONFIG", None)
        os.environ.pop("KSM_CONFIG_BASE64_1", None)
        os.environ.pop("KSM_CONFIG_BASE64_DESC_1", None)
        os.environ.pop("KSM_CONFIG_BASE64_2", None)
        os.environ.pop("KSM_CONFIG_BASE64_DESC_2", None)

        for item in self.delete_me:
            if os.path.exists(item) is True:
                os.unlink(item)

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

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client, \
             patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available', return_value=False):
            mock_client.return_value = secrets_manager

            # Create a keeper.ini with the default profile
            default_token = "XYZ321"
            runner = CliRunner()
            result = runner.invoke(cli, ['profile', 'init', '-t', default_token], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success for default init")
            self.assertTrue(os.path.exists(Config.default_ini_file), "could not find ini file")

            # Add to the keeper.ini a new profile
            test_token = "ABC123"
            result = runner.invoke(cli, ['profile', 'init', "-p", "test", '-t',
                                         test_token], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success for test init")
            self.assertTrue(os.path.exists(Config.default_ini_file), "could not find ini file")

            config = configparser.ConfigParser(allow_no_value=True)
            config.read(Config.default_ini_file)

            # We should have two profiles now.
            self.assertTrue(Profile.default_profile in config, "Could not find the default profile in the config.")
            self.assertTrue("test" in config, "Could not find the test profile in the config.")

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
clientid = D_XXXXX_CI
privatekey = D_XXXXX_PK
appkey = D_XXXX_AK
hostname = {}

[Another]
clientid = A_XXXXX_CI
privatekey = A_XXXXX_PK
appkey = A_XXXX_AK
hostname = {}

[_config]
active_profile = _default
color = True
        '''.format(mock_config.get("hostname"), mock_config.get("hostname"))

        runner = CliRunner()

        # Disable keyring to force INI file usage for import/export tests
        with patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available', return_value=False):
            # Test INI import
            base64_config = base64.urlsafe_b64encode(ini_config.encode())
            self.assertFalse(os.path.exists("keeper.ini"), "an ini config file already exists")

            result = runner.invoke(cli, ['profile', 'import', base64_config.decode()], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success on list")
            self.assertTrue(os.path.exists("keeper.ini"), "the ini config doesn't exists")
            with open("keeper.ini", "r") as fh:
                file_config = fh.read()
                fh.close()
                os.chmod("keeper.ini", 0o0600)
                self.assertEqual(ini_config, file_config, "config on disk and defined above are not the same.")

            # Test INI export. Get the 'Another' profile

            result = runner.invoke(cli, ['profile', 'export', "Another"], catch_exceptions=False)
            print(result.output)
            self.assertEqual(0, result.exit_code, "did not get a success on list")
            config_data = result.output

            try:
                config = base64.urlsafe_b64decode(config_data).decode()
                self.assertRegex(config, r'A_XXXXX_CI', 'did not find the Another client id')
                self.assertFalse(re.search(r'D_XXXXX_CI', config, re.MULTILINE), 'found the default client id')
            except Exception as err:
                self.fail("Could not base64 decode the config: {}".format(err))

    def test_config_json_import_export(self):

        json_config = MockConfig.make_config()

        runner = CliRunner()

        # Disable keyring to force INI file usage for import/export tests
        with patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available', return_value=False):
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

            config = configparser.ConfigParser(allow_no_value=True)
            config.read("keeper.ini")
            self.assertEqual(json_config["clientId"], config["_default"].get("clientid"),  "client keys match")

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
        with tempfile.NamedTemporaryFile(delete=True) as tf:
            tf_name = tf.name
            self.delete_me.append(tf_name)
            tf.close()

            with patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available', return_value=False):
                result = runner.invoke(cli, [
                    '-o', tf_name,
                    'profile', 'list', '--json'], catch_exceptions=False)
                self.assertEqual(0, result.exit_code, "did not get a success on list")

            with open(tf_name, "r") as fh:
                profile_data = json.load(fh)
                self.assertEqual("App1", profile_data[0]["name"], "found first app")
                self.assertEqual("App2", profile_data[1]["name"], "found second app")
                fh.close()

    def test_import_sdk_json(self):

        mock_config = MockConfig.make_config()
        base64_json = MockConfig.make_base64(config=mock_config)

        runner = CliRunner()

        result = runner.invoke(cli, ['profile', 'import', base64_json], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on list")
        self.assertTrue(os.path.exists("keeper.ini"), "the ini config doesn't exists")

        config = configparser.ConfigParser(allow_no_value=True)
        config.read(Config.default_ini_file)

        profile = config["_default"]
        self.assertIsNotNone(profile, "could not find the profile")
        self.assertEqual(mock_config.get("appKey"), profile.get("appKey"), "did not get the correct app key")
        self.assertEqual(mock_config.get("hostname"), profile.get("hostname"), "did not get the correct hostname")

    def test_auto_config_sdk_jenkins_json(self):

        """
        Test a multi config via env vars.

        The Jenkins plugin can export multiple configs. This allows the KSM CLI inside of a
        build to use two application. Most likely no one will ever use this, but we need to
        test for it.

        """

        mock_config = MockConfig.make_config()
        base64_json = MockConfig.make_base64(config=mock_config)

        runner = CliRunner()

        # Create two configs
        os.environ["KSM_CONFIG_BASE64_1"] = base64_json
        os.environ["KSM_CONFIG_BASE64_DESC_1"] = "SDK 1"
        os.environ["KSM_CONFIG_BASE64_2"] = base64_json
        os.environ["KSM_CONFIG_BASE64_DESC_2"] = "SDK 2"

        # Using a file output due to cli runner joining stdout and stderr
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf_name = tf.name
            self.delete_me.append(tf_name)
            tf.close()

            # Make sure keeper ini file doesn't exists
            if os.path.exists(Config.default_ini_file) is True:
                os.unlink(Config.default_ini_file)

            with patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available', return_value=False):
                result = runner.invoke(cli, [
                    '-o', tf_name,
                    'profile', 'list', '--json'], catch_exceptions=False)
                self.assertEqual(0, result.exit_code, "did not get a success on list")

            with open(tf_name, "r") as fh:
                profile_data = json.load(fh)
                self.assertEqual("SDK 1", profile_data[0]["name"], "did not find first app")
                self.assertEqual("SDK 2", profile_data[1]["name"], "did not find second app")

                self.assertFalse(os.path.exists(Config.default_ini_file), "keeper.ini exists when it should not")
                fh.close()

    def test_auto_config_sdk_base64_json(self):

        """
        Test a base64 config via env vars.

        Most people will use it this way.

        """

        mock_config = MockConfig.make_config()
        base64_json = MockConfig.make_base64(config=mock_config)

        runner = CliRunner()

        # Create two configs
        os.environ["KSM_CONFIG"] = base64_json

        # Using a file output due to cli runner joining stdout and stderr
        with tempfile.NamedTemporaryFile() as tf:
            tf_name = tf.name
            self.delete_me.append(tf_name)
            tf.close()

            # Make sure keeper ini file doesn't exists
            if os.path.exists(Config.default_ini_file) is True:
                os.unlink(Config.default_ini_file)

            result = runner.invoke(cli, [
                '-o', tf_name,
                'profile', 'list', '--json'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success on list")

            with open(tf_name, "r") as fh:
                profile_data = json.load(fh)
                self.assertEqual(Profile.default_profile, profile_data[0]["name"], "did not find default profile")

                self.assertFalse(os.path.exists(Config.default_ini_file), "keeper.ini exists when it should not")
                fh.close()

    def test_auto_config_sdk_json(self):

        """
        Test JSON in an environmental variable

        A K8S secret may return the Base64 decoded.

        """

        mock_config = MockConfig.make_config()
        json_config = MockConfig.make_json(config=mock_config)

        runner = CliRunner()

        # Create two configs
        os.environ["KSM_CONFIG"] = json_config

        # Using a file output due to cli runner joining stdout and stderr
        with tempfile.NamedTemporaryFile() as tf:
            tf_name = tf.name
            self.delete_me.append(tf_name)
            tf.close()

            # Make sure keeper ini file doesn't exists
            if os.path.exists(Config.default_ini_file) is True:
                os.unlink(Config.default_ini_file)

            result = runner.invoke(cli, [
                '-o', tf_name,
                'profile', 'list', '--json'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "did not get a success on list")

            with open(tf_name, "r") as fh:
                profile_data = json.load(fh)
                self.assertEqual(Profile.default_profile, profile_data[0]["name"], "did not find default profile")

                self.assertFalse(os.path.exists(Config.default_ini_file), "keeper.ini exists when it should not")
                fh.close()


    def test_invalid_profile_name_rejected_before_network_call(self):
        """Invalid --profile-name must be rejected before OTT is consumed."""
        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client, \
             patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available', return_value=False):
            runner = CliRunner()

            mock_config = MockConfig.make_config()
            secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))
            mock_client.return_value = secrets_manager

            for invalid_name, desc in [
                ('my profile', 'space in name'),
                ('a' * 65, '65-char name'),
                ('my\tprofile', 'tab in name'),
            ]:
                result = runner.invoke(
                    cli, ['profile', 'init', '-t', 'XX:YY', '-p', invalid_name],
                    catch_exceptions=False
                )
                self.assertNotEqual(0, result.exit_code, f"expected failure for {desc}")
                self.assertIn("Profile name must be", result.output,
                              f"expected validation error message for {desc}")

            # Valid name — validation passes and execution proceeds to the network call
            res = mock.Response()
            queue = mock.ResponseQueue(client=secrets_manager)
            queue.add_response(res)

            result = runner.invoke(
                cli, ['profile', 'init', '-t', 'XX:YY', '-p', 'valid-name'],
                catch_exceptions=False
            )
            self.assertEqual(0, result.exit_code, "expected success for valid name")

    def test_delete_command_clears_active_profile(self):
        """Test that 'ksm profile delete' removes the profile and clears active_profile."""

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        res = mock.Response()
        res.add_record(title="My Record 1")
        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client, \
             patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available',
                   return_value=False):
            mock_client.return_value = secrets_manager

            runner = CliRunner()

            # Init the default profile (INI storage)
            result = runner.invoke(cli, ['profile', 'init', '-t', 'TOKEN123'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "profile init failed")
            self.assertTrue(os.path.exists(Config.default_ini_file), "keeper.ini not created")

            # Verify _default profile exists and is active
            result = runner.invoke(cli, ['profile', 'list', '--json'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code)
            profiles = json.loads(result.output)
            default_item = next((p for p in profiles if p["name"] == "_default"), None)
            self.assertIsNotNone(default_item, "_default profile not found after init")
            self.assertTrue(default_item["active"], "_default is not active after init")

            # Delete the active profile
            result = runner.invoke(cli, ['profile', 'delete', '_default'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "profile delete failed: " + str(result.output))

            # Profile must be gone from storage
            config = Config(ini_file=Config.default_ini_file)
            config.load()
            self.assertNotIn("_default", config.profile_list(), "_default still in profiles after delete")

            # active_profile must be cleared
            self.assertIsNone(
                config.config.active_profile,
                "active_profile was not cleared after deleting the active profile"
            )

    def test_ini_file_flag_respected_by_profile_list(self):
        """Regression test for KSM-814: --ini-file flag must be respected by profile subcommands.

        Before the fix, profile_list_command created a fresh Profile() ignoring the --ini-file
        value, so it fell back to default discovery (finding no profiles in the temp cwd).
        After the fix, it reuses ctx.obj["cli"].profile which was initialised with the custom
        INI file, so the custom profile name appears in the output.
        """

        custom_profile_name = "ini-file-regression-profile"
        ini_content = (
            "[{profile}]\n"
            "clientid = DUMMY_CLIENT_ID\n"
            "privatekey = DUMMY_PRIVATE_KEY\n"
            "appkey = DUMMY_APP_KEY\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[_config]\n"
            "active_profile = {profile}\n"
        ).format(profile=custom_profile_name)

        # Write the INI file under a non-default name so default discovery won't find it.
        ini_path = os.path.join(self.temp_dir.name, "custom_ksm_814.ini")
        with open(ini_path, "w") as fh:
            fh.write(ini_content)
        os.chmod(ini_path, 0o600)

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            runner = CliRunner()
            result = runner.invoke(
                cli,
                ['--ini-file', ini_path, 'profile', 'list', '--json'],
                catch_exceptions=False,
            )

            self.assertEqual(0, result.exit_code,
                             "--ini-file profile list failed: " + result.output)

            profiles = json.loads(result.output)
            profile_names = [p["name"] for p in profiles]
            self.assertIn(custom_profile_name, profile_names,
                          "--ini-file was ignored by 'profile list' (KSM-814 regression)")


    def test_ini_file_flag_respected_by_profile_init(self):
        """Regression test: global --ini-file must route 'profile init' to the ini file.

        Before the fix, profile_init_command forwarded only the subcommand-level --ini-file
        to Profile.init(). When only the global --ini-file was set (no subcommand flag),
        Profile.init() received ini_file=None and use_config_file=False, causing it to
        silently fall through to keychain (if available) or the default keeper.ini instead
        of the explicitly specified file.

        The ini file must already exist (e.g., created by a previous 'profile init' with
        the subcommand --ini-file) so the global --ini-file load in cli() succeeds.
        """
        existing_profile = "existing-profile"
        ini_content = (
            "[{profile}]\n"
            "clientid = EXISTING_CI\n"
            "privatekey = EXISTING_PK\n"
            "appkey = EXISTING_AK\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[_config]\n"
            "active_profile = {profile}\n"
        ).format(profile=existing_profile)

        ini_path = os.path.join(self.temp_dir.name, "custom_global_init.ini")
        with open(ini_path, "w") as fh:
            fh.write(ini_content)
        os.chmod(ini_path, 0o600)

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        res = mock.Response()
        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client, \
             patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available',
                   return_value=False):
            mock_client.return_value = secrets_manager

            runner = CliRunner()
            result = runner.invoke(
                cli,
                # Use only the global --ini-file; no subcommand-level --ini-file flag.
                ['--ini-file', ini_path, 'profile', 'init', '-t', 'US:TOKEN123', '-p', 'ini-global-profile'],
                catch_exceptions=False,
            )

            self.assertEqual(0, result.exit_code,
                             "global --ini-file profile init failed: " + str(result.output))

            config = configparser.ConfigParser(allow_no_value=True)
            config.read(ini_path)
            self.assertIn('ini-global-profile', config.sections(),
                          "global --ini-file was ignored by 'profile init'; "
                          "new profile was routed to default keeper.ini instead (KSM-814 regression)")
            # The existing profile must still be present — we're adding, not overwriting.
            self.assertIn(existing_profile, config.sections(),
                          "existing ini file profile was lost after profile init")

    def test_ini_file_flag_respected_by_profile_export(self):
        """Regression test: global --ini-file must route 'profile export' to the ini file.

        export_config() must call _reload_config() (as list_profiles and set_active do) so
        that it reads from the storage indicated by --ini-file rather than from a stale or
        keychain-sourced config object.
        """
        export_profile_name = "export-ini-profile"
        unique_client_id = "UNIQUE_INI_FILE_CLIENT_ID_XYZ"
        ini_content = (
            "[{profile}]\n"
            "clientid = {cid}\n"
            "privatekey = DUMMY_PRIVATE_KEY\n"
            "appkey = DUMMY_APP_KEY\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[_config]\n"
            "active_profile = {profile}\n"
        ).format(profile=export_profile_name, cid=unique_client_id)

        ini_path = os.path.join(self.temp_dir.name, "custom_global_export.ini")
        with open(ini_path, "w") as fh:
            fh.write(ini_content)
        os.chmod(ini_path, 0o600)

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client, \
             patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available',
                   return_value=False):
            mock_client.return_value = secrets_manager

            runner = CliRunner()
            result = runner.invoke(
                cli,
                ['--ini-file', ini_path, 'profile', 'export', '--plain', export_profile_name],
                catch_exceptions=False,
            )

            self.assertEqual(0, result.exit_code,
                             "global --ini-file profile export failed: " + str(result.output))
            self.assertIn(unique_client_id, result.output,
                          "global --ini-file was ignored by 'profile export'; "
                          "exported credentials do not match the ini file profile (KSM-814 regression)")


    def test_ini_file_flag_respected_by_profile_setup(self):
        """Regression test: global --ini-file must be forwarded to profile_setup_command.

        Before the fix, profile_setup_command noted a conflict when both global and
        subcommand --ini-file were set, but never fell back to the global flag when
        only the global flag was provided. So from_aws_ec2instance received ini_file=None.
        """
        existing_profile = "setup-existing-profile"
        ini_content = (
            "[{profile}]\n"
            "clientid = EXISTING_CI\n"
            "privatekey = EXISTING_PK\n"
            "appkey = EXISTING_AK\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[_config]\n"
            "active_profile = {profile}\n"
        ).format(profile=existing_profile)

        ini_path = os.path.join(self.temp_dir.name, "custom_global_setup.ini")
        with open(ini_path, "w") as fh:
            fh.write(ini_content)
        os.chmod(ini_path, 0o600)

        with patch('keeper_secrets_manager_cli.profile.Profile.from_aws_ec2instance') as mock_setup, \
             patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available',
                   return_value=False):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ['--ini-file', ini_path, 'profile', 'setup', '--type', 'aws'],
                catch_exceptions=False,
            )

            self.assertEqual(0, result.exit_code,
                             "global --ini-file profile setup failed: " + str(result.output))
            mock_setup.assert_called_once()
            _, kwargs = mock_setup.call_args
            self.assertEqual(ini_path, kwargs.get('ini_file'),
                             "global --ini-file was not forwarded to 'profile setup' "
                             "(ini_file=None would fall through to default storage)")

    def test_ini_file_flag_respected_by_config_show(self):
        """Coverage: global --ini-file must be used by 'config show'.

        Verifies that show_config() reads from the correct storage path
        after calling _reload_config().
        """
        custom_profile = "config-show-profile"
        ini_content = (
            "[{profile}]\n"
            "clientid = SHOW_CI\n"
            "privatekey = SHOW_PK\n"
            "appkey = SHOW_AK\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[_config]\n"
            "active_profile = {profile}\n"
        ).format(profile=custom_profile)

        ini_path = os.path.join(self.temp_dir.name, "custom_config_show.ini")
        with open(ini_path, "w") as fh:
            fh.write(ini_content)
        os.chmod(ini_path, 0o600)

        with patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available',
                   return_value=False):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ['--ini-file', ini_path, 'config', 'show'],
                catch_exceptions=False,
            )

            self.assertEqual(0, result.exit_code,
                             "config show failed: " + str(result.output))
            self.assertIn(custom_profile, result.output,
                          "global --ini-file was ignored by 'config show'; "
                          "active profile not found in output")

    def test_ini_file_flag_respected_by_config_color(self):
        """Coverage: global --ini-file must be used by 'config color'.

        Verifies that set_color() writes to the correct ini file and does not
        create a default keeper.ini in the working directory.
        """
        custom_profile = "config-color-profile"
        ini_content = (
            "[{profile}]\n"
            "clientid = COLOR_CI\n"
            "privatekey = COLOR_PK\n"
            "appkey = COLOR_AK\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[_config]\n"
            "active_profile = {profile}\n"
            "color = False\n"
        ).format(profile=custom_profile)

        ini_path = os.path.join(self.temp_dir.name, "custom_config_color.ini")
        with open(ini_path, "w") as fh:
            fh.write(ini_content)
        os.chmod(ini_path, 0o600)

        with patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available',
                   return_value=False):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ['--ini-file', ini_path, 'config', 'color', '--enable'],
                catch_exceptions=False,
            )

            self.assertEqual(0, result.exit_code,
                             "config color --enable failed: " + str(result.output))

            config = configparser.ConfigParser(allow_no_value=True)
            config.read(ini_path)
            self.assertEqual('True', config['_config'].get('color'),
                             "global --ini-file was ignored by 'config color'; "
                             "color setting not updated in the custom ini file")
            # The default keeper.ini must NOT have been created.
            self.assertFalse(os.path.exists(Config.default_ini_file),
                             "'config color' created default keeper.ini instead of using --ini-file")

    def test_ini_file_flag_respected_by_config_cache(self):
        """Coverage: global --ini-file must be used by 'config cache'.

        Verifies that set_cache() writes to the correct ini file.
        """
        custom_profile = "config-cache-profile"
        ini_content = (
            "[{profile}]\n"
            "clientid = CACHE_CI\n"
            "privatekey = CACHE_PK\n"
            "appkey = CACHE_AK\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[_config]\n"
            "active_profile = {profile}\n"
            "cache = False\n"
        ).format(profile=custom_profile)

        ini_path = os.path.join(self.temp_dir.name, "custom_config_cache.ini")
        with open(ini_path, "w") as fh:
            fh.write(ini_content)
        os.chmod(ini_path, 0o600)

        with patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available',
                   return_value=False):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ['--ini-file', ini_path, 'config', 'cache', '--enable'],
                catch_exceptions=False,
            )

            self.assertEqual(0, result.exit_code,
                             "config cache --enable failed: " + str(result.output))

            config = configparser.ConfigParser(allow_no_value=True)
            config.read(ini_path)
            self.assertEqual('True', config['_config'].get('cache'),
                             "global --ini-file was ignored by 'config cache'; "
                             "cache setting not updated in the custom ini file")
            self.assertFalse(os.path.exists(Config.default_ini_file),
                             "'config cache' created default keeper.ini instead of using --ini-file")

    def test_ini_file_flag_respected_by_profile_active(self):
        """Coverage: global --ini-file must be used by 'profile active'.

        Verifies that set_active() persists the active profile change to the
        correct ini file path when only the global --ini-file flag is set.
        """
        profile1 = "active-profile-one"
        profile2 = "active-profile-two"
        ini_content = (
            "[{p1}]\n"
            "clientid = P1_CI\nprivatekey = P1_PK\nappkey = P1_AK\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[{p2}]\n"
            "clientid = P2_CI\nprivatekey = P2_PK\nappkey = P2_AK\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[_config]\n"
            "active_profile = {p1}\n"
        ).format(p1=profile1, p2=profile2)

        ini_path = os.path.join(self.temp_dir.name, "custom_profile_active.ini")
        with open(ini_path, "w") as fh:
            fh.write(ini_content)
        os.chmod(ini_path, 0o600)

        with patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available',
                   return_value=False):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ['--ini-file', ini_path, 'profile', 'active', profile2],
                catch_exceptions=False,
            )

            self.assertEqual(0, result.exit_code,
                             "profile active failed: " + str(result.output))

            config = configparser.ConfigParser(allow_no_value=True)
            config.read(ini_path)
            self.assertEqual(profile2, config['_config'].get('active_profile'),
                             "global --ini-file was ignored by 'profile active'; "
                             "active_profile not updated in the custom ini file")

    def test_ini_file_flag_respected_by_profile_delete(self):
        """Coverage: global --ini-file must be used by 'profile delete'.

        Verifies that delete() removes the profile from the correct ini file.
        """
        profile1 = "delete-profile-one"
        profile2 = "delete-profile-two"
        ini_content = (
            "[{p1}]\n"
            "clientid = D1_CI\nprivatekey = D1_PK\nappkey = D1_AK\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[{p2}]\n"
            "clientid = D2_CI\nprivatekey = D2_PK\nappkey = D2_AK\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[_config]\n"
            "active_profile = {p1}\n"
        ).format(p1=profile1, p2=profile2)

        ini_path = os.path.join(self.temp_dir.name, "custom_profile_delete.ini")
        with open(ini_path, "w") as fh:
            fh.write(ini_content)
        os.chmod(ini_path, 0o600)

        with patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available',
                   return_value=False):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ['--ini-file', ini_path, 'profile', 'delete', profile2],
                catch_exceptions=False,
            )

            self.assertEqual(0, result.exit_code,
                             "profile delete failed: " + str(result.output))

            config = configparser.ConfigParser(allow_no_value=True)
            config.read(ini_path)
            self.assertNotIn(profile2, config.sections(),
                             "global --ini-file was ignored by 'profile delete'; "
                             "profile still exists in the custom ini file")
            self.assertIn(profile1, config.sections(),
                          "unrelated profile was deleted from the custom ini file")

    def test_ini_file_flag_respected_by_profile_import(self):
        """Coverage: global --ini-file must be used as output_file by 'profile import'.

        When --output-file is omitted, profile_import_command falls back to ctx.obj["ini_file"]
        (the global --ini-file). This verifies the imported profile lands in the correct file.
        """
        existing_profile = "import-existing-profile"
        ini_content = (
            "[{profile}]\n"
            "clientid = IMPORT_CI\n"
            "privatekey = IMPORT_PK\n"
            "appkey = IMPORT_AK\n"
            "hostname = https://keepersecurity.com\n"
            "\n"
            "[_config]\n"
            "active_profile = {profile}\n"
        ).format(profile=existing_profile)

        ini_path = os.path.join(self.temp_dir.name, "custom_profile_import.ini")
        with open(ini_path, "w") as fh:
            fh.write(ini_content)
        os.chmod(ini_path, 0o600)

        # Build a minimal JSON config and base64-encode it (Profile.import_config JSON path).
        imported_profile = "imported-new-profile"
        json_config = {
            "clientId": "IMPORT_NEW_CI",
            "privateKey": "IMPORT_NEW_PK",
            "appKey": "IMPORT_NEW_AK",
            "hostname": "https://keepersecurity.com",
        }
        config_base64 = base64.urlsafe_b64encode(json.dumps(json_config).encode()).decode()

        with patch('keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available',
                   return_value=False):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ['--ini-file', ini_path, 'profile', 'import',
                 '-p', imported_profile, config_base64],
                catch_exceptions=False,
            )

            self.assertEqual(0, result.exit_code,
                             "profile import failed: " + str(result.output))

            config = configparser.ConfigParser(allow_no_value=True)
            config.read(ini_path)
            self.assertIn(imported_profile, config.sections(),
                          "global --ini-file was ignored by 'profile import'; "
                          "imported profile not found in the custom ini file")
            self.assertFalse(os.path.exists(Config.default_ini_file),
                             "'profile import' created default keeper.ini instead of using --ini-file")


if __name__ == '__main__':
    unittest.main()
