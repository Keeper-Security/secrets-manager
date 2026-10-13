import importlib
import sys
import types
import unittest
from unittest.mock import patch

from keeper_secrets_manager_ansible import KeeperAnsible

UID = "RECORD_UID"


def tearDownModule():
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)


def _run_action(plugin_name, args, method, **method_kwargs):
    """Run the action with the vault call mocked. Return the display.warning mock."""
    plugin = importlib.import_module("keeper_secrets_manager_ansible.plugins.action." + plugin_name)
    task = types.SimpleNamespace(
        args=dict(args), check_mode=False, async_val=0, action=plugin_name, module_defaults=None)
    connection = types.SimpleNamespace(_shell=types.SimpleNamespace(tmpdir="/nonexistent"))
    context = types.SimpleNamespace(check_mode=False)
    action = plugin.ActionModule(task, connection, context, None, None, None)
    with patch.object(KeeperAnsible, "__init__", return_value=None), \
            patch.object(KeeperAnsible, "get_field_type_enum_and_key", create=True, return_value=(None, "login")), \
            patch.object(KeeperAnsible, method, **method_kwargs) as vault_call, \
            patch("keeper_secrets_manager_ansible.display.warning") as warning:
        action.run(task_vars={})
    vault_call.assert_called_once()
    return warning


class CacheIgnoredWarningTest(unittest.TestCase):
    """A task that passes cache to a plugin that reads only the live vault must be told the option has no effect."""

    def _assert_warns_that_cache_is_ignored(self, warning, plugin_name):
        warning.assert_called_once()
        text = warning.call_args[0][0]
        self.assertIn(plugin_name, text)
        self.assertIn("cache", text)
        self.assertIn("no effect", text)

    def test_keeper_set_warns_that_cache_has_no_effect(self):
        warning = _run_action(
            "keeper_set", {"uid": UID, "field": "login", "value": "x", "cache": "REGISTERED_CACHE"},
            "set_value", return_value=False)
        self._assert_warns_that_cache_is_ignored(warning, "keeper_set")

    def test_keeper_remove_warns_that_cache_has_no_effect(self):
        warning = _run_action(
            "keeper_remove", {"uid": UID, "cache": "REGISTERED_CACHE"},
            "remove_record", return_value={"changed": False})
        self._assert_warns_that_cache_is_ignored(warning, "keeper_remove")

    def test_no_warning_when_cache_is_not_set(self):
        # Guards the conditional, so the warning call cannot become unconditional and fire on every task.
        for plugin_name, args, method, result in (
            ("keeper_set", {"uid": UID, "field": "login", "value": "x"}, "set_value", False),
            ("keeper_remove", {"uid": UID}, "remove_record", {"changed": False}),
        ):
            with self.subTest(plugin=plugin_name):
                warning = _run_action(plugin_name, args, method, return_value=result)
                texts = [call[0][0] for call in warning.call_args_list]
                self.assertFalse([t for t in texts if "cache option" in t or "no effect" in t], texts)
