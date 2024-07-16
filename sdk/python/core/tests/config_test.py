import unittest
import os
import tempfile
import json
import codecs

from keeper_secrets_manager_core.storage import FileKeyValueStorage, InMemoryKeyValueStorage, SecureOSStorage
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.mock import MockConfig
import io
from contextlib import redirect_stderr
from sys import platform
import subprocess


class ConfigTest(unittest.TestCase):

    def setUp(self):

        self.orig_working_dir = os.getcwd()

        # Make the the config is not set in the env var. Will screw up certain tests.
        os.environ.pop("KSM_CONFIG", None)

    def tearDown(self):

        os.chdir(self.orig_working_dir)
        os.environ.pop("KSM_CONFIG", None)

    @staticmethod
    def _save_config(default_config_name, mock_config):
        with open(default_config_name, "w") as fh:
            fh.write(json.dumps(mock_config))
            fh.close()
            os.chmod(default_config_name, 0o600)

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
            ConfigTest._save_config(default_config_name, mock_config)

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

        mock_config = MockConfig.make_config(token="localhost:ABC123")

        with tempfile.TemporaryDirectory() as temp_dir_name:
            os.chdir(temp_dir_name)
            ConfigTest._save_config(default_config_name, mock_config)

            # Pass in the client key and server
            secrets_manager = SecretsManager(token="ABC123", hostname='localhost')

            self.assertEqual(secrets_manager.config.get(ConfigKeys.KEY_HOSTNAME), "localhost",
                             "did not get correct server")
            self.assertIsNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_KEY), "Client key is not present")
            os.chdir('..')

    def test_onetime_token_formats_abbrev(self):

        mock_config = MockConfig.make_config(skip_list=["clientKey"], token="US:ABC123")
        b64config_str = MockConfig.make_base64(config=mock_config)

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(b64config_str), token="US:ABC123",
                                         hostname='localhost')

        self.assertEqual(secrets_manager.hostname, "keepersecurity.com", "did not get correct server")
        self.assertEqual(secrets_manager.token, 'ABC123', "One time token/Client key don't match")

        self.assertEqual(secrets_manager.config.get(ConfigKeys.KEY_HOSTNAME), "keepersecurity.com",
                         "did not get correct server")
        self.assertIsNone(secrets_manager.config.get(ConfigKeys.KEY_CLIENT_KEY), "Client key is not present")

    def test_onetime_token_formats_hostname(self):

        mock_config = MockConfig.make_config(skip_list=["clientKey"], token="fake.keepersecurity.com:ABC123")
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

    def test_encoding(self):

        mock_config = MockConfig.make_config()
        json_config = MockConfig.make_json(config=mock_config)

        with tempfile.TemporaryDirectory() as temp_dir_name:
            os.chdir(temp_dir_name)

            # This one causes a JSON that looks OK (Python will print it), however the json.loads won't decode it.
            with codecs.open("client-config.json", "w", 'utf-16-be') as fh:
                fh.write(json_config)
                fh.close()
                os.chmod("client-config.json", 0o600)

            config = FileKeyValueStorage()

            try:
                config.read_storage()
                self.fail("Should have gotten an exception")
            except Exception as err:
                print("EXPECTED ERROR", err)

            # This one causes "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
            with codecs.open("client-config.json", "wb") as fh:
                fh.write(json_config.encode("utf-16"))
                fh.close()
                os.chmod("client-config.json", 0o600)

            config = FileKeyValueStorage()

            try:
                config.read_storage()
                self.fail("Should have gotten an exception")
            except Exception as err:
                print("EXPECTED ERROR", err)

            os.chdir(self.orig_working_dir)

    def test_config_file_mode(self):

        file = FileKeyValueStorage.default_config_file_location
        mock_config = MockConfig.make_config()

        # Dog food
        with tempfile.TemporaryDirectory() as temp_dir_name:
            os.chdir(temp_dir_name)

            config = FileKeyValueStorage()
            config.set(ConfigKeys.KEY_CLIENT_ID, mock_config.get("clientId"))
            config.set(ConfigKeys.KEY_APP_KEY, mock_config.get("appKey"))
            config.set(ConfigKeys.KEY_PRIVATE_KEY, mock_config.get("privateKey"))

            assert os.path.exists(file)

            if platform.lower().startswith("win") is True:
                pass
            else:
                self.assertEqual("0600", oct(os.stat(file).st_mode)[-4:],
                                 "config file mode is not correct")

            with io.StringIO() as buf, redirect_stderr(buf):
                new_config = FileKeyValueStorage()
                self.assertEqual(mock_config.get("clientId"), new_config.get(ConfigKeys.KEY_CLIENT_ID))

                stderr = buf.getvalue()
                assert "too open" not in stderr

            # Open up the file
            if platform.lower().startswith("win") is True:
                subprocess.run('icacls.exe "{}" /grant Guest:F'.format(file))
            else:
                os.chmod(file, 0o644)
            with open(file, "w") as fh:
                fh.write("{}")
                fh.close()

                with io.StringIO() as buf, redirect_stderr(buf):
                    too_open = FileKeyValueStorage()
                    too_open.read_storage()

                    stderr = buf.getvalue()
                    assert "too open" in stderr

            # Lock down the file too much
            if platform.lower().startswith("win") is True:
                for cmd in ['icacls.exe {} /reset'.format(file),
                            'icacls.exe {} /inheritance:r'.format(file),
                            'icacls.exe {} /remove Everyone'.format(file)]:
                    subprocess.run(cmd)
            else:
                os.chmod(file, 0o000)
            try:
                no_access = FileKeyValueStorage()
                no_access.read_storage()
                self.fail("Should not have access to config file")
            except PermissionError as err:
                assert "Access denied" in str(err)
            except Exception as err:
                self.fail("Got the wrong exceptions for access defined: {}".format(err))

            # Windows won't delete the temp directory it does not have permissions.
            if platform.lower().startswith("win") is True:
                subprocess.run('icacls.exe "{}" /grant Everyone:F'.format(file))
            os.unlink(file)
            os.chdir(self.orig_working_dir)

    def test_secure_os_storage(self):
        mock_config = MockConfig.make_config()
        storage = SecureOSStorage(app_name="TEST", exec_path="test.exe")

        # test set() and get()
        storage.set(ConfigKeys.KEY_CLIENT_ID, mock_config.get("clientId"))
        storage.set(ConfigKeys.KEY_APP_KEY, mock_config.get("appKey"))
        storage.set(ConfigKeys.KEY_PRIVATE_KEY, mock_config.get("privateKey"))
        self.assertEqual(mock_config.get("clientId"), storage.get(ConfigKeys.KEY_CLIENT_ID))
        self.assertEqual(mock_config.get("appKey"), storage.get(ConfigKeys.KEY_APP_KEY))
        self.assertEqual(mock_config.get("privateKey"), storage.get(ConfigKeys.KEY_PRIVATE_KEY))

        # test contains()
        self.assertTrue(storage.contains(ConfigKeys.KEY_CLIENT_ID))

        # test delete()
        storage.delete(ConfigKeys.KEY_CLIENT_ID)
        self.assertIsNone(storage.get(ConfigKeys.KEY_CLIENT_ID))

        # test delete_all()
        storage.delete_all()
        self.assertIsNone(storage.get(ConfigKeys.KEY_APP_KEY))
