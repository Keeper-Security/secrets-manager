import os
import unittest
from unittest.mock import patch
from click.testing import CliRunner
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from integration.keeper_secrets_manager_cli.keeper_secrets_manager_cli.profile import Profile
from integration.keeper_secrets_manager_cli.keeper_secrets_manager_cli.__main__ import cli
import tempfile
import configparser
import json


class ExecTest(unittest.TestCase):

    def setUp(self) -> None:
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

    def test_the_works(self):

        """ Test initializing the profile
        """

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage({
            "hostname": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        res = mock.Response()

        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")
        one.custom_field("My Custom 1", "custom1")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        with patch('integration.keeper_secrets_manager_cli.keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
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


if __name__ == '__main__':
    unittest.main()
