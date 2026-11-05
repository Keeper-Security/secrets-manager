import os
import tempfile
import unittest
from unittest.mock import patch

from keeper_secrets_manager_cli.config import Config
from keeper_secrets_manager_cli.profile import Profile
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.keeper_globals import keeper_public_keys
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage


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

    def test_malformed_key_fails_before_any_network_call(self):
        with patch.object(SecretsManager, "get_secrets") as get_secrets:
            with self.assertRaises(ValueError):
                self._init("smk.example.com:{}:{}:AAAA".format(self.CLIENT_KEY, self.KEY_ID))
            get_secrets.assert_not_called()

    def test_cloud_region_with_key_material_is_rejected(self):
        key = keeper_public_keys["7"]
        with self.assertRaises(ValueError):
            self._init("US:{}:{}:{}".format(self.CLIENT_KEY, self.KEY_ID, key))

    def test_bare_token_without_hostname_stores_no_hostname(self):
        profile = self._init(self.CLIENT_KEY)
        self.assertIsNone(profile.hostname)

    def test_keyring_round_trip_keeps_server_identity(self):
        from tests.keyring_test import _mock_keyring
        key = keeper_public_keys["7"]
        _mock_keyring.clear()
        with patch.dict("sys.modules", {"keyring": _mock_keyring}):
            with patch.object(SecretsManager, "get_secrets", return_value=[]):
                Profile.init(token="smk.example.com:{}:{}:{}".format(self.CLIENT_KEY, self.KEY_ID, key),
                             profile_name="p")
            from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage
            data = KeyringConfigStorage().load_profile("p")
        self.assertEqual(data["serverPublicKey"], key)
        self.assertEqual(data["serverPublicKeyId"], self.KEY_ID)
        self.assertEqual(data["hostname"], "smk.example.com")
        _mock_keyring.clear()

    def test_env_hostname_does_not_override_self_managed_host(self):
        from keeper_secrets_manager_core import helpers
        key = keeper_public_keys["7"]
        profile = self._init("smk.example.com:{}:{}:{}".format(self.CLIENT_KEY, self.KEY_ID, key))
        storage = InMemoryKeyValueStorage()
        storage.set(ConfigKeys.KEY_HOSTNAME, profile.hostname)
        storage.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY, profile.server_public_key)
        with patch.dict(os.environ, {"KSM_HOSTNAME": "evil.example.net"}):
            self.assertEqual(helpers.get_server(None, storage), "smk.example.com")

    def test_two_part_cloud_token_stores_no_server_key(self):
        profile = self._init("US:" + self.CLIENT_KEY)
        self.assertEqual(profile.hostname, "US")
        self.assertIsNone(profile.server_public_key)

    def test_il5_token_keeps_region_code_and_stores_no_server_key(self):
        key = keeper_public_keys["7"]
        profile = self._init("IL5:{}:{}:{}".format(self.CLIENT_KEY, self.KEY_ID, key))
        self.assertEqual(profile.hostname, "IL5")
        self.assertIsNone(profile.server_public_key)
        self.assertEqual(profile.server_public_key_id, "10")

    def test_three_part_cloud_token_fails_closed(self):
        with self.assertRaises(ValueError):
            self._init("US:{}:{}".format(self.CLIENT_KEY, self.KEY_ID))

    def test_profile_ini_matches_origin_master(self):
        """The INI profile of a cloud token or a bare token equals the one written by origin/master."""
        ref_dir = self._master_tree()
        script = (
            "import os, sys, tempfile\n"
            "from unittest.mock import patch\n"
            "from keeper_secrets_manager_cli.config import Config\n"
            "from keeper_secrets_manager_cli.profile import Profile\n"
            "from keeper_secrets_manager_core.core import SecretsManager\n"
            "token, server = sys.argv[1], (sys.argv[2] or None)\n"
            "with tempfile.TemporaryDirectory() as tmp:\n"
            "    ini = os.path.join(tmp, 'keeper.ini')\n"
            "    with patch.object(SecretsManager, 'get_secrets', return_value=[]):\n"
            "        Profile.init(token=token, server=server, ini_file=ini, profile_name='p', use_config_file=True)\n"
            "    import configparser\n"
            "    cp = configparser.RawConfigParser(allow_no_value=True); cp.read(ini)\n"
            "    print(sorted((k, v) for k, v in cp['p'].items() if k not in ('privatekey', 'appkey')))\n"
        )
        cases = [("US:" + self.CLIENT_KEY, ""), ("EU:" + self.CLIENT_KEY, ""), (self.CLIENT_KEY, ""),
                 (self.CLIENT_KEY, "EU"), (self.CLIENT_KEY, "smk.example.com")]
        for token, server in cases:
            expected = self._run(ref_dir, script, token, server)
            actual = self._run(None, script, token, server)
            self.assertEqual(actual, expected, (token, server))

    @staticmethod
    def _run(ref_dir, script, *args):
        import subprocess
        import sys
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        base = ref_dir or root
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join([
            os.path.join(base, "sdk", "python", "core"),
            os.path.join(base, "integration", "keeper_secrets_manager_cli")])
        env.pop("KSM_HOSTNAME", None)
        # The working directory leads sys.path with "-c", so run from a neutral directory.
        out = subprocess.run([sys.executable, "-c", script] + list(args), env=env, cwd=tempfile.gettempdir(), capture_output=True,
                             text=True, timeout=120)
        if out.returncode != 0:
            raise AssertionError(out.stderr)
        return out.stdout.strip()

    def _master_tree(self):
        import subprocess
        import atexit
        import shutil
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        tmp = tempfile.mkdtemp()
        atexit.register(shutil.rmtree, tmp, True)
        archive = subprocess.run(
            ["git", "-C", root, "archive", "origin/master", "sdk/python/core/keeper_secrets_manager_core",
             "integration/keeper_secrets_manager_cli/keeper_secrets_manager_cli"],
            capture_output=True, timeout=120)
        if archive.returncode != 0:
            self.skipTest("origin/master is not available")
        subprocess.run(["tar", "-x", "-C", tmp], input=archive.stdout, check=True, timeout=120)
        return tmp

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
