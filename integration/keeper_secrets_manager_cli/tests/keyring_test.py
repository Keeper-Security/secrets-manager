import io
import json
import os
import unittest
from unittest.mock import patch, MagicMock
import tempfile

from conftest import CliRunner
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_cli.__main__ import cli
from keeper_secrets_manager_cli.exception import KsmCliException, KsmCliIntegrityException


class MockKeyring:
    """Simple mock for keyring module."""
    
    def __init__(self):
        self._storage = {}
        self.errors = MagicMock()
        self.errors.PasswordDeleteError = Exception
    
    def get_password(self, service, username):
        return self._storage.get(f"{service}:{username}")
    
    def set_password(self, service, username, password):
        self._storage[f"{service}:{username}"] = password
    
    def delete_password(self, service, username):
        key = f"{service}:{username}"
        if key in self._storage:
            del self._storage[key]
    
    def get_keyring(self):
        mock_backend = MagicMock()
        mock_backend.__class__.__module__ = 'keyring.backends.SecretService'
        return mock_backend
    
    def clear(self):
        self._storage.clear()


# Global mock keyring instance for all tests
_mock_keyring = MockKeyring()


class KeyringConfigStorageTest(unittest.TestCase):
    """Tests for KeyringConfigStorage class."""

    def setUp(self):
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)
        
        _mock_keyring.clear()
        self.patcher = patch.dict('sys.modules', {'keyring': _mock_keyring})
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        os.chdir(self.orig_dir)

    def test_save_and_load_profile(self):
        """Test saving and loading a profile."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage
        
        storage = KeyringConfigStorage()
        profile_data = {"clientId": "test-id", "hostname": "keepersecurity.com"}
        
        storage.save_profile("test_profile", profile_data)
        loaded = storage.load_profile("test_profile")
        
        self.assertEqual(profile_data["clientId"], loaded["clientId"])
        self.assertEqual(profile_data["hostname"], loaded["hostname"])

    def test_save_and_load_common_config(self):
        """Test saving and loading common configuration."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage
        
        storage = KeyringConfigStorage()
        common = {"active_profile": "_default", "color": True}
        
        storage.save_common_config(common)
        loaded = storage.load_common_config()
        
        self.assertEqual(common["active_profile"], loaded["active_profile"])

    def test_list_profiles(self):
        """Test listing profiles."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage
        
        storage = KeyringConfigStorage()
        
        storage.save_profile("profile1", {"key": "value1"})
        storage.add_profile_to_list("profile1")
        storage.save_profile("profile2", {"key": "value2"})
        storage.add_profile_to_list("profile2")
        
        profiles = storage.list_profiles()
        
        self.assertIn("profile1", profiles)
        self.assertIn("profile2", profiles)

    def test_delete_profile(self):
        """Test deleting a profile."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage

        storage = KeyringConfigStorage()

        storage.save_profile("to_delete", {"key": "value"})
        storage.add_profile_to_list("to_delete")

        # Simulate: to_delete is the active profile
        common = storage.load_common_config() or {}
        common["active_profile"] = "to_delete"
        storage.save_common_config(common)

        self.assertIn("to_delete", storage.list_profiles())

        storage.delete_profile("to_delete")

        self.assertNotIn("to_delete", storage.list_profiles())

        # active_profile must be cleared when the active profile is deleted
        common = storage.load_common_config()
        self.assertIsNone(
            common.get("active_profile"),
            "active_profile was not cleared after deleting the active profile"
        )

    def test_invalid_profile_name(self):
        """Test that invalid profile names are rejected."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage
        
        storage = KeyringConfigStorage()
        
        with self.assertRaises(KsmCliException):
            storage.save_profile("invalid/name", {"key": "value"})
        
        with self.assertRaises(KsmCliException):
            storage.save_profile("", {"key": "value"})

    def test_is_available(self):
        """Test keyring availability check."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage
        
        self.assertTrue(KeyringConfigStorage.is_available())


class KeyringProfileInitTest(unittest.TestCase):
    """Tests for profile init with keyring storage."""

    def setUp(self):
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)
        
        os.environ.pop("KSM_CONFIG", None)
        os.environ.pop("KSM_TOKEN", None)
        
        _mock_keyring.clear()
        self.patcher = patch.dict('sys.modules', {'keyring': _mock_keyring})
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        os.environ.pop("KSM_CONFIG", None)
        os.environ.pop("KSM_TOKEN", None)
        os.chdir(self.orig_dir)

    def test_init_uses_keyring_by_default(self):
        """Test that profile init uses keyring when no --ini-file specified."""
        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))
        
        res = mock.Response()
        res.add_record(title="My Record 1")
        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager

            runner = CliRunner()
            result = runner.invoke(cli, ['profile', 'init', '-t', 'TEST_TOKEN'], catch_exceptions=False)
            
            self.assertEqual(0, result.exit_code)
            # No keeper.ini should be created
            self.assertFalse(os.path.exists("keeper.ini"))

    def test_init_with_ini_file_creates_file(self):
        """Test that profile init with --ini-file creates the file."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage
        
        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))
        
        res = mock.Response()
        res.add_record(title="My Record 1")
        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)

        # Disable keyring to force file usage
        with patch.object(KeyringConfigStorage, 'is_available', return_value=False):
            with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
                mock_client.return_value = secrets_manager

                runner = CliRunner()
                result = runner.invoke(cli, ['profile', 'init', '--ini-file', 'keeper.ini', '-t', 'TEST_TOKEN'], 
                                       catch_exceptions=False)
                
                self.assertEqual(0, result.exit_code)
                self.assertTrue(os.path.exists("keeper.ini"))


class KeyringProfileListTest(unittest.TestCase):
    """Tests for profile list with keyring storage."""

    def setUp(self):
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)
        
        os.environ.pop("KSM_CONFIG", None)
        
        _mock_keyring.clear()
        self.patcher = patch.dict('sys.modules', {'keyring': _mock_keyring})
        self.patcher.start()
        
        # Setup profiles in keyring
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage
        storage = KeyringConfigStorage()
        for name in ["production", "staging"]:
            storage.save_profile(name, {"clientId": f"{name}-id", "privateKey": "pk", 
                                        "appKey": "ak", "hostname": "test.com"})
            storage.add_profile_to_list(name)
        storage.save_common_config({"active_profile": "production", "profiles": ["production", "staging"]})

    def tearDown(self):
        self.patcher.stop()
        os.environ.pop("KSM_CONFIG", None)
        os.chdir(self.orig_dir)

    def test_list_profiles_from_keyring(self):
        """Test listing profiles stored in keyring."""
        runner = CliRunner()
        result = runner.invoke(cli, ['profile', 'list', '--json'], catch_exceptions=False)
        
        self.assertEqual(0, result.exit_code)
        
        profiles = json.loads(result.output)
        names = [p["name"] for p in profiles]
        
        self.assertIn("production", names)
        self.assertIn("staging", names)

    def test_list_shows_active_profile(self):
        """Test that list shows the active profile."""
        runner = CliRunner()
        result = runner.invoke(cli, ['profile', 'list', '--json'], catch_exceptions=False)
        
        profiles = json.loads(result.output)
        production = next((p for p in profiles if p["name"] == "production"), None)
        
        self.assertTrue(production["active"])


class KeyringProfileActiveTest(unittest.TestCase):
    """Tests for profile active with keyring storage."""

    def setUp(self):
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)
        
        os.environ.pop("KSM_CONFIG", None)
        
        _mock_keyring.clear()
        self.patcher = patch.dict('sys.modules', {'keyring': _mock_keyring})
        self.patcher.start()
        
        # Setup profiles in keyring
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage
        storage = KeyringConfigStorage()
        for name in ["profile1", "profile2"]:
            storage.save_profile(name, {"clientId": f"{name}-id", "privateKey": "pk", 
                                        "appKey": "ak", "hostname": "test.com"})
            storage.add_profile_to_list(name)
        storage.save_common_config({"active_profile": "profile1", "profiles": ["profile1", "profile2"]})

    def tearDown(self):
        self.patcher.stop()
        os.environ.pop("KSM_CONFIG", None)
        os.chdir(self.orig_dir)

    def test_set_active_profile(self):
        """Test setting the active profile."""
        runner = CliRunner()
        result = runner.invoke(cli, ['profile', 'active', 'profile2'], catch_exceptions=False)
        
        self.assertEqual(0, result.exit_code)
        self.assertIn("profile2 is now the active profile", result.output)

    def test_set_nonexistent_profile_fails(self):
        """Test that setting a nonexistent profile fails."""
        runner = CliRunner()
        result = runner.invoke(cli, ['profile', 'active', 'nonexistent'], catch_exceptions=False)
        
        self.assertNotEqual(0, result.exit_code)


class KeyringStoragePriorityTest(unittest.TestCase):
    """Tests for storage priority order."""

    def setUp(self):
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)
        
        os.environ.pop("KSM_CONFIG", None)
        os.environ.pop("KSM_TOKEN", None)
        
        _mock_keyring.clear()
        self.patcher = patch.dict('sys.modules', {'keyring': _mock_keyring})
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        os.environ.pop("KSM_CONFIG", None)
        os.environ.pop("KSM_TOKEN", None)
        os.chdir(self.orig_dir)

    def test_keyring_takes_priority_over_ini_file(self):
        """Test that keyring takes priority over keeper.ini when keyring is available."""
        from keeper_secrets_manager_cli.profile import Profile
        
        # Create keeper.ini with required _config section
        ini_content = """[_default]
clientid = file-id
privatekey = pk
appkey = ak
hostname = test.com

[_config]
active_profile = _default
"""
        with open("keeper.ini", "w") as f:
            f.write(ini_content)
        os.chmod("keeper.ini", 0o600)
        
        mock_cli = MagicMock()
        mock_cli.use_color = False
        
        profile = Profile(cli=mock_cli)
        
        # Keyring should take priority when available (INI file is for export purposes)
        self.assertTrue(profile.use_keyring)

    def test_keyring_used_when_no_ini_file(self):
        """Test that keyring is used when no keeper.ini exists."""
        from keeper_secrets_manager_cli.profile import Profile

        mock_cli = MagicMock()
        mock_cli.use_color = False

        profile = Profile(cli=mock_cli)

        # Should use keyring
        self.assertTrue(profile.use_keyring)

    def test_warn_when_keyring_empty_and_cwd_ini_exists(self):
        """Upgrade path: warn on stderr when keyring is active but empty and a keeper.ini exists."""
        from keeper_secrets_manager_cli.profile import Profile

        ini_content = """[_default]
clientid = file-id
privatekey = pk
appkey = ak
hostname = test.com

[_config]
active_profile = _default
"""
        with open("keeper.ini", "w") as f:
            f.write(ini_content)
        os.chmod("keeper.ini", 0o600)

        mock_cli = MagicMock()
        mock_cli.use_color = False

        # Keyring is available (mock in place) but empty (no profiles added)
        with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
            profile = Profile(cli=mock_cli)
            stderr_output = mock_stderr.getvalue()

        # Warning referencing keeper.ini must appear on stderr
        self.assertIn("keeper.ini", stderr_output)
        # Keyring priority must be unchanged
        self.assertTrue(profile.use_keyring)

    def test_no_warn_when_keyring_has_profiles_and_ini_exists(self):
        """No spurious warning when keyring already has profiles, even if keeper.ini also exists."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage
        from keeper_secrets_manager_cli.profile import Profile

        ini_content = """[_default]
clientid = file-id
privatekey = pk
appkey = ak
hostname = test.com

[_config]
active_profile = _default
"""
        with open("keeper.ini", "w") as f:
            f.write(ini_content)
        os.chmod("keeper.ini", 0o600)

        # Populate keyring mock with a profile so it is non-empty
        storage = KeyringConfigStorage()
        storage.save_profile("_default", {
            "clientId": "keyring-id", "privateKey": "pk",
            "appKey": "ak", "hostname": "test.com"
        })
        storage.add_profile_to_list("_default")
        storage.save_common_config({"active_profile": "_default", "profiles": ["_default"]})

        mock_cli = MagicMock()
        mock_cli.use_color = False

        with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
            profile = Profile(cli=mock_cli)
            stderr_output = mock_stderr.getvalue()

        # No warning about keeper.ini should appear (keyring is populated)
        self.assertNotIn("keeper.ini", stderr_output)
        self.assertTrue(profile.use_keyring)


class KeyringIntegrityTest(unittest.TestCase):
    """Tests for SHA-256 cross-session integrity verification (KSM-805)."""

    def setUp(self):
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

        _mock_keyring.clear()
        self.patcher = patch.dict('sys.modules', {'keyring': _mock_keyring})
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        os.chdir(self.orig_dir)

    def test_integrity_hash_stored_on_save(self):
        """After save_profile(), the integrity key exists in the keyring."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage

        storage = KeyringConfigStorage()
        storage.save_profile("_default", {"clientId": "test-id", "hostname": "keepersecurity.com"})

        integrity_key = "KSM-cli:ksm-cli-profile-_default-integrity"
        self.assertIn(integrity_key, _mock_keyring._storage)
        self.assertTrue(_mock_keyring._storage[integrity_key])

    def test_integrity_check_passes_on_valid_load(self):
        """Save then load_profile() succeeds with no exception when entry is unmodified."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage

        storage = KeyringConfigStorage()
        storage.save_profile("_default", {"clientId": "test-id", "hostname": "keepersecurity.com"})

        # Should not raise
        loaded = storage.load_profile("_default")
        self.assertIsNotNone(loaded)

    def test_integrity_check_fails_on_tampered_entry(self):
        """Directly altering the keyring entry causes load_profile() to raise KsmCliIntegrityException."""
        import json as _json
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage

        storage = KeyringConfigStorage()
        profile_data = {"clientId": "test-id", "hostname": "keepersecurity.com"}
        storage.save_profile("_default", profile_data)

        # Tamper with the stored config (simulate external modification)
        config_key = "KSM-cli:ksm-cli-profile-_default"
        original = _mock_keyring._storage[config_key]
        tampered = _json.loads(original)
        tampered["data"] = _json.dumps({"clientId": "hacked", "hostname": "evil.com"})
        _mock_keyring._storage[config_key] = _json.dumps(tampered)

        with self.assertRaises(KsmCliIntegrityException):
            storage.load_profile("_default")

    def test_integrity_check_skipped_when_no_hash_stored(self):
        """Pre-KSM-805 entries (no integrity key) load silently without raising."""
        import json as _json
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage, KeyringUtilityStorage

        # Write config directly to mock keyring, bypassing KeyringUtilityStorage
        # (simulates an entry created before KSM-805 — no integrity key present)
        profile_data = {"clientId": "legacy-id", "hostname": "keepersecurity.com"}
        inner_payload = _json.dumps({"data": _json.dumps(profile_data)}, indent=4, sort_keys=True)
        _mock_keyring._storage["KSM-cli:ksm-cli-profile-_default"] = inner_payload
        # Deliberately omit "KSM-cli:ksm-cli-profile-_default-integrity"

        storage = KeyringConfigStorage()
        # Should succeed silently (backward-compatible)
        loaded = storage.load_profile("_default")
        self.assertIsNotNone(loaded)

    def test_integrity_hash_deleted_on_profile_delete(self):
        """After delete_profile(), the integrity key is absent from the keyring."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage

        storage = KeyringConfigStorage()
        storage.save_profile("_default", {"clientId": "test-id", "hostname": "keepersecurity.com"})
        storage.add_profile_to_list("_default")

        # Confirm integrity key was written
        integrity_key = "KSM-cli:ksm-cli-profile-_default-integrity"
        self.assertIn(integrity_key, _mock_keyring._storage)

        storage.delete_profile("_default")

        self.assertNotIn(integrity_key, _mock_keyring._storage)


if __name__ == '__main__':
    unittest.main()

