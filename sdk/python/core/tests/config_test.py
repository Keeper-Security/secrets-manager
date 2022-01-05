import unittest
import os
import tempfile
import json

from keeper_secrets_manager_core.storage import FileKeyValueStorage, InMemoryKeyValueStorage
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.mock import MockConfig


class ConfigTest(unittest.TestCase):

    def setUp(self):

        self.orig_working_dir = os.getcwd()

        # Make the the config is not set in the env var. Will screw up certain tests.
        os.environ.pop("KSM_CONFIG", None)

    def tearDown(self):

        os.chdir(self.orig_working_dir)
        os.environ.pop("KSM_CONFIG", None)

    def test_missing_config(self):

        """ Attempt to load a missing config file.
        """

        # Attempt get instance without config file. This should fail since the directory will not contain
        # any config file and there are no env vars to use.

        with tempfile.TemporaryDirectory() as temp_dir_name:
            os.chdir(temp_dir_name)
            try:
                SecretsManager()
                self.fail("Found config file, should be missing.")
            except Exception as err:
                self.assertRegex(str(err), r'Cannot locate One Time Token.', "did not get correct exception message.")
            os.chdir('..')

    def test_default_load_from_json(self):

        """ Load config from default location and name.
        """

        default_config_name = FileKeyValueStorage.default_config_file_location

        # Make instance using default config file. Create a JSON config file and store under the default file
        # name. This will pass because the JSON file exists.

        mock_config = MockConfig.make_config()

        with tempfile.TemporaryDirectory() as temp_dir_name:
            os.chdir(temp_dir_name)
            with open(default_config_name, "w") as fh:
                fh.write(json.dumps(mock_config))
                fh.close()

            c = SecretsManager()
            self.assertEqual(c.config.get(ConfigKeys.KEY_HOSTNAME), mock_config.get("hostname"),
                             "did not get correct server")
            self.assertEqual(c.config.get(ConfigKeys.KEY_APP_KEY), mock_config.get("appKey"),
                             "did not get correct server")
            os.chdir('..')

    def test_overwrite_via_args(self):

        """ Load config from default location and name, but overwrite the client key and server
        """

        default_config_name = FileKeyValueStorage.default_config_file_location

        # Make instance using default config file. Create a JSON config file and store under the default file
        # name. This will pass because the JSON file exists.

        mock_config = MockConfig.make_config()

        with tempfile.TemporaryDirectory() as temp_dir_name:
            os.chdir(temp_dir_name)
            with open(default_config_name, "w") as fh:
                fh.write(json.dumps(mock_config))
                fh.close()

            # Pass in the client key and server
            secrets_manager = SecretsManager(token="ABC123", hostname='localhost')

            self.assertEqual(secrets_manager.config.get(ConfigKeys.KEY_HOSTNAME), "localhost",
                             "did not get correct server")
            self.assertIsNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_KEY), "Client key is not present")
            os.chdir('..')

    def test_onetime_token_formats_abbrev(self):

        mock_config = MockConfig.make_config(skip_list=["clientKey"])
        b64config_str = MockConfig.make_base64(config=mock_config)

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(b64config_str), token="US:ABC123",
                                         hostname='localhost')

        self.assertEqual(secrets_manager.hostname, "keepersecurity.com", "did not get correct server")
        self.assertEqual(secrets_manager.token, 'ABC123', "One time token/Client key don't match")

        self.assertEqual(secrets_manager.config.get(ConfigKeys.KEY_HOSTNAME), "keepersecurity.com",
                         "did not get correct server")
        self.assertIsNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_KEY), "Client key is not present")

    def test_onetime_token_formats_hostname(self):

        mock_config = MockConfig.make_config(skip_list=["clientKey"])
        b64config_str = MockConfig.make_base64(config=mock_config)

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(b64config_str),
                                         token="fake.keepersecurity.com:ABC123", hostname='localhost')

        self.assertEqual(secrets_manager.hostname, "fake.keepersecurity.com", "did not get correct server")
        self.assertEqual(secrets_manager.token, 'ABC123', "One time token/Client key don't match")

        self.assertEqual(secrets_manager.config.get(ConfigKeys.KEY_HOSTNAME), "fake.keepersecurity.com",
                         "did not get correct server")
        self.assertIsNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_KEY), "Client key is not present")

    def test_pass_in_config(self):

        default_config_name = FileKeyValueStorage.default_config_file_location

        # Make instance using default config file. Create a JSON config file and store under the default file
        # name. This will pass because the JSON file exists.

        with tempfile.TemporaryDirectory() as temp_dir_name:
            os.chdir(temp_dir_name)

            config = FileKeyValueStorage()
            config.set(ConfigKeys.KEY_CLIENT_KEY, "MY CLIENT KEY")
            config.set(ConfigKeys.KEY_CLIENT_ID, "MY CLIENT ID")
            config.set(ConfigKeys.KEY_APP_KEY, "MY APP KEY")
            config.set(ConfigKeys.KEY_PRIVATE_KEY, "MY PRIVATE KEY")

            self.assertTrue(os.path.isfile(default_config_name), "config file is missing.")

            dict_config = config.read_storage()

            self.assertEqual("MY CLIENT KEY", dict_config.get(ConfigKeys.KEY_CLIENT_KEY.value),
                             "got correct client key")
            self.assertEqual("MY CLIENT ID", dict_config.get(ConfigKeys.KEY_CLIENT_ID.value),
                             "got correct client id")
            self.assertEqual("MY APP KEY", dict_config.get(ConfigKeys.KEY_APP_KEY.value),
                             "got correct app key")
            self.assertEqual("MY PRIVATE KEY", dict_config.get(ConfigKeys.KEY_PRIVATE_KEY.value),
                             "got correct private key")

            # Pass in the config
            secrets_manager = SecretsManager(config=config)

            # Is not bound, client id and private key will be generated and overwrite existing
            self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_ID), "got a client id")
            self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_PRIVATE_KEY), "got a private key")

            # App key should be removed.
            self.assertIsNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_KEY),
                              "client key (one time token) was removed successfully")
            os.chdir('..')

    def test_in_memory_config(self):

        config = InMemoryKeyValueStorage()
        config.set(ConfigKeys.KEY_CLIENT_KEY, "MY CLIENT KEY")
        config.set(ConfigKeys.KEY_CLIENT_ID, "MY CLIENT ID")
        config.set(ConfigKeys.KEY_APP_KEY, "MY APP KEY")
        config.set(ConfigKeys.KEY_PRIVATE_KEY, "MY PRIVATE KEY")

        dict_config = config.read_storage()

        self.assertEqual("MY CLIENT KEY", dict_config.get(ConfigKeys.KEY_CLIENT_KEY.value),
                         "got correct client key")
        self.assertEqual("MY CLIENT ID", dict_config.get(ConfigKeys.KEY_CLIENT_ID.value),
                         "got correct client id")
        self.assertEqual("MY APP KEY", dict_config.get(ConfigKeys.KEY_APP_KEY.value),
                         "got correct app key")
        self.assertEqual("MY PRIVATE KEY", dict_config.get(ConfigKeys.KEY_PRIVATE_KEY.value),
                         "got correct private key")

        # Pass in the config
        secrets_manager = SecretsManager(config=config)

        # Is not bound, client id and private key will be generated and overwrite existing
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_ID), "got a client id")
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_PRIVATE_KEY), "got a private key")

        # App key should be removed.
        self.assertIsNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_KEY),
                          "client key (one time token) was removed successfully")

    def test_public_key_id(self):

        config = InMemoryKeyValueStorage()
        config.set(ConfigKeys.KEY_CLIENT_KEY, "MY CLIENT KEY")
        config.set(ConfigKeys.KEY_CLIENT_ID, "MY CLIENT ID")
        config.set(ConfigKeys.KEY_APP_KEY, "MY APP KEY")
        config.set(ConfigKeys.KEY_PRIVATE_KEY, "MY PRIVATE KEY")

        # Test the default setting of the key id if missing
        secrets_manager = SecretsManager(config=config)
        self.assertEqual(
            SecretsManager.default_key_id,
            secrets_manager.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID),
            "the public key is not set the default"
        )

        # Test if the config is edited and a bad key is entered that we go back to the default.
        config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, 1_000_000)
        secrets_manager = SecretsManager(config=config)
        self.assertEqual(
            SecretsManager.default_key_id,
            secrets_manager.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID),
            "the public key is not set the default after bad key id"
        )

    def test_in_memory_base64_config(self):

        mock_config = MockConfig.make_config(skip_list=["clientKey"])
        b64config_str = MockConfig.make_base64(config=mock_config)

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(b64config_str))
        dict_config = secrets_manager.config.read_storage()

        self.assertEqual(mock_config.get("appKey"), dict_config.get(ConfigKeys.KEY_APP_KEY.value),
                         "got correct app key")
        self.assertEqual(mock_config.get("clientId"), dict_config.get(ConfigKeys.KEY_CLIENT_ID.value),
                         "got correct client id")
        self.assertEqual(mock_config.get("hostname"), dict_config.get(ConfigKeys.KEY_HOSTNAME.value),
                         "got correct hostname")
        self.assertEqual(mock_config.get("privateKey"), dict_config.get(ConfigKeys.KEY_PRIVATE_KEY.value),
                         "got correct private key")
        self.assertEqual(mock_config.get("serverPublicKeyId"),
                         dict_config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID.value),
                         "got correct server public key id")
        # Pass in the config
        secrets_manager = SecretsManager(config=secrets_manager.config)

        # Is not bound, client id and private key will be generated and overwrite existing
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_ID), "got a client id")
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_PRIVATE_KEY), "got a private key")
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_APP_KEY), "got an app key")
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_HOSTNAME), "got a hostname")
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), "got a public key id")

        # App key should be removed.
        self.assertIsNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_KEY),
                          "client key (one time token) was removed successfully")

    def test_in_memory_base64_config_via_env(self):

        mock_config = MockConfig.make_config(skip_list=["clientKey"])
        b64config_str = MockConfig.make_base64(config=mock_config)

        # Put the config into an
        os.environ["KSM_CONFIG"] = b64config_str

        secrets_manager = SecretsManager()
        dict_config = secrets_manager.config.read_storage()

        self.assertEqual(mock_config.get("appKey"), dict_config.get(ConfigKeys.KEY_APP_KEY.value),
                         "got correct app key")
        self.assertEqual(mock_config.get("clientId"), dict_config.get(ConfigKeys.KEY_CLIENT_ID.value),
                         "got correct client id")
        self.assertEqual(mock_config.get("hostname"), dict_config.get(ConfigKeys.KEY_HOSTNAME.value),
                         "got correct hostname")
        self.assertEqual(mock_config.get("privateKey"), dict_config.get(ConfigKeys.KEY_PRIVATE_KEY.value),
                         "got correct private key")
        self.assertEqual(mock_config.get("serverPublicKeyId"),
                         dict_config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID.value),
                         "got correct server public key id")

        # Pass in the config
        secrets_manager = SecretsManager(config=secrets_manager.config)

        # Is not bound, client id and private key will be generated and overwrite existing
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_ID), "got a client id")
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_PRIVATE_KEY), "got a private key")
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_APP_KEY), "got an app key")
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_HOSTNAME), "got a hostname")
        self.assertIsNotNone(secrets_manager.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), "got a public key id")

        # App key should be removed.
        self.assertIsNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_KEY),
                          "client key (one time token) was removed successfully")
