import unittest
import os
import tempfile
import json

from keepercommandersm.storage import FileKeyValueStorage, InMemoryKeyValueStorage
from keepercommandersm import Commander
from keepercommandersm.configkeys import ConfigKeys


class ConfigTest(unittest.TestCase):

    def setUp(self):

        self.orig_working_dir = os.getcwd()

    def tearDown(self):

        os.chdir(self.orig_working_dir)

    def test_missing_config(self):

        """ Attempt to load a missing config file.
        """

        # Attempt get instance without config file. This should fail since the directory will not contain
        # any config file and there are no env vars to use.

        with tempfile.TemporaryDirectory() as temp_dir_name:
            os.chdir(temp_dir_name)
            try:
                c = Commander()
                self.fail("Found config file, should be missing.")
            except Exception as err:
                self.assertRegex(str(err), r'Cannot find the client key', "did not get correct exception message.")

    def test_default_load_from_json(self):

        """ Load config from default location and name.
        """

        default_config_name = FileKeyValueStorage.default_config_file_location

        # Make instance using default config file. Create a JSON config file and store under the default file
        # name. This will pass because the JSON file exists.

        with tempfile.TemporaryDirectory() as temp_dir_name:
            os.chdir(temp_dir_name)
            with open(default_config_name, "w") as fh:
                fh.write(
                    json.dumps({
                        "server": "fake.keepersecurity.com",
                        "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
                        "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpG"
                                    "ILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
                        "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
                        "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOt"
                                      "x9djH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0U"
                                      "BFTrbET6joq0xCjhKMhHQFaHYI"
                    })
                )
                fh.close()

            c = Commander()
            self.assertEqual(c.config.get(ConfigKeys.KEY_SERVER), "fake.keepersecurity.com",
                             "did not get correct server")
            self.assertEqual(c.config.get(ConfigKeys.KEY_APP_KEY), "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
                             "did not get correct server")

    def test_overwrite_via_args(self):

        """ Load config from default location and name, but overwrite the client key and server
        """

        default_config_name = FileKeyValueStorage.default_config_file_location

        # Make instance using default config file. Create a JSON config file and store under the default file
        # name. This will pass because the JSON file exists.

        with tempfile.TemporaryDirectory() as temp_dir_name:
            os.chdir(temp_dir_name)
            with open(default_config_name, "w") as fh:
                fh.write(
                    json.dumps({
                        "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
                        "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpG"
                                    "ILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
                        "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
                        "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOt"
                                      "x9djH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0U"
                                      "BFTrbET6joq0xCjhKMhHQFaHYI"
                    })
                )
                fh.close()

            # Pass in the client key and server
            c = Commander(client_key="ABC123", server='localhost')

            self.assertEqual(c.config.get(ConfigKeys.KEY_SERVER), "localhost", "did not get correct server")
            self.assertEqual(c.config.get(ConfigKeys.KEY_CLIENT_KEY), "ABC123", "did not get correct client key")

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
            c = Commander(config=config)

            self.assertEqual("MY CLIENT KEY", c.config.get(ConfigKeys.KEY_CLIENT_KEY), "got correct client key")

            # Is not bound, client id and private key will be generated and overwrite existing
            self.assertIsNotNone(c.config.get(ConfigKeys.KEY_CLIENT_ID), "got a client id")
            self.assertIsNotNone(c.config.get(ConfigKeys.KEY_PRIVATE_KEY), "got a private key")

            # App key should be removed.
            self.assertIsNone(c.config.get(ConfigKeys.KEY_APP_KEY), "found the app key")

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
        c = Commander(config=config)

        self.assertEqual("MY CLIENT KEY", c.config.get(ConfigKeys.KEY_CLIENT_KEY), "got correct client key")

        # Is not bound, client id and private key will be generated and overwrite existing
        self.assertIsNotNone(c.config.get(ConfigKeys.KEY_CLIENT_ID), "got a client id")
        self.assertIsNotNone(c.config.get(ConfigKeys.KEY_PRIVATE_KEY), "got a private key")

        # App key should be removed.
        self.assertIsNone(c.config.get(ConfigKeys.KEY_APP_KEY), "found the app key")
