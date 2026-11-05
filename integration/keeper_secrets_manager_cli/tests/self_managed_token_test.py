import os
import tempfile
import unittest
from unittest.mock import patch

from keeper_secrets_manager_cli.config import Config
from keeper_secrets_manager_cli.profile import Profile
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.keeper_globals import keeper_public_keys


class SelfManagedTokenTest(unittest.TestCase):
    """Profile.init keeps the server identity of a four-part one-time token."""

    KEY_ID = "70"
    CLIENT_KEY = "fakeClientKey123456789012345"

    def _init(self, token, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "keeper.ini")
            # No network: the bind request is replaced by a no-op.
            with patch.object(SecretsManager, "get_secrets", return_value=[]):
                Profile.init(token=token, ini_file=ini, profile_name="p", use_config_file=True, **kwargs)
            config = Config(ini_file=ini)
            config.load()
            return config.get_profile("p")

    def test_four_part_token_stores_server_identity(self):
        key = keeper_public_keys["7"]
        profile = self._init("smk.example.com:{}:{}:{}".format(self.CLIENT_KEY, self.KEY_ID, key))
        self.assertEqual(profile.hostname, "smk.example.com")
        self.assertEqual(profile.server_public_key_id, self.KEY_ID)
        self.assertEqual(profile.server_public_key, key)

    def test_two_part_cloud_token_stores_no_server_key(self):
        profile = self._init("US:" + self.CLIENT_KEY)
        self.assertEqual(profile.hostname, "US")
        self.assertIsNone(profile.server_public_key)

    def test_runtime_client_receives_server_identity(self):
        from keeper_secrets_manager_cli import KeeperCli
        key = keeper_public_keys["7"]
        with tempfile.TemporaryDirectory() as tmp:
            ini = os.path.join(tmp, "keeper.ini")
            with patch.object(SecretsManager, "get_secrets", return_value=[]):
                Profile.init(token="smk.example.com:{}:{}:{}".format(self.CLIENT_KEY, self.KEY_ID, key),
                             ini_file=ini, profile_name="p", use_config_file=True)
            with patch.object(KeeperCli, "get_client") as get_client:
                KeeperCli(ini_file=ini, profile_name="p")
            storage = get_client.call_args.kwargs["config"]
            self.assertEqual(storage.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY), key)
            self.assertEqual(storage.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), self.KEY_ID)
