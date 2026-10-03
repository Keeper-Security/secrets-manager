import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.core import KSMCache
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from keeper_secrets_manager_ansible import KeeperAnsible


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _unload_ansible():
    # Importing a plugin loads the Ansible plugin loader with its default paths. Playbook tests need a fresh one.
    for module in list(sys.modules):
        if module.startswith("ansible"):
            sys.modules.pop(module, None)


class KeeperFileModeTest(unittest.TestCase):
    """Files that hold Keeper keys must be readable only by their owner, whatever the umask is."""

    def setUp(self):
        from ansible.errors import AnsibleError
        error_patch = patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError)
        error_patch.start()
        self.addCleanup(error_patch.stop)
        old_umask = os.umask(0o022)
        self.addCleanup(os.umask, old_umask)

    def test_config_file_from_ansible_variables_is_private(self):
        # The plugin writes the file only when it does not exist. An existing file is the SDK's to read and save.
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            os.environ.pop("KSM_TOKEN", None)
            path = Path(directory) / "keeper.json"
            with patch.object(KeeperAnsible, "get_client"):
                KeeperAnsible(task_vars={"keeper_config_file": str(path), "keeper_token": "UNUSED_TOKEN"},
                              action_module=SimpleNamespace(_task=SimpleNamespace(args={}, check_mode=False)))
            self.assertEqual(_mode(path), 0o600)
            self.assertEqual(json.loads(path.read_text()), {"clientKey": "UNUSED_TOKEN"})

    def test_keeper_init_config_files_are_private(self):
        self.addCleanup(_unload_ansible)
        from keeper_secrets_manager_ansible.plugins.action.keeper_init import ActionModule
        config = InMemoryKeyValueStorage(mock.MockConfig.make_base64())
        for name in ("keeper.json", "keeper.yml"):
            for existing in (False, True):
                with self.subTest(name=name, existing=existing), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / name
                    if existing:
                        path.write_text("old")
                        os.chmod(path, 0o644)
                    ActionModule.make_config(config, str(path))
                    self.assertEqual(_mode(path), 0o600)
                    text = path.read_text()
                    values = json.loads(text) if name.endswith("json") else yaml.safe_load(text)
                    self.assertTrue(values)

    def test_dr_cache_file_is_private(self):
        response = SimpleNamespace(status_code=200, data=b"server response")
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as directory, \
                    patch.dict(os.environ, {"KSM_CACHE_DIR": directory}), \
                    patch.object(KSMCache, "kms_cache_file_name", os.path.join(directory, "ksm_cache.bin")), \
                    patch.object(SecretsManager, "post_function", return_value=response):
                path = Path(directory) / "ksm_cache.bin"
                if existing:
                    path.write_bytes(b"old cache")
                    os.chmod(path, 0o644)
                transmission_key = SimpleNamespace(key=b"k" * 32)
                result = KeeperAnsible._caching_post_function("https://unused.test", transmission_key, "payload")
                self.assertIs(result, response)
                self.assertEqual(_mode(path), 0o600)
                self.assertEqual(path.read_bytes(), b"k" * 32 + b"server response")
                # The umask of the process is back to its value.
                current = os.umask(0o022)
                self.assertEqual(current, 0o022)
