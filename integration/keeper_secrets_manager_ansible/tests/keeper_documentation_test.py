import ast
import sys
import unittest
import types
from pathlib import Path
from unittest.mock import patch

import yaml

import keeper_secrets_manager_ansible.plugins
from keeper_secrets_manager_ansible import KeeperAnsible

PLUGIN_DIR = Path(keeper_secrets_manager_ansible.plugins.__file__).parent
MODULES = sorted(path.stem for path in PLUGIN_DIR.glob("modules/keeper_*.py"))


def _unload_ansible():
    # Importing a plugin loads the Ansible plugin loader with its default paths. Playbook tests need a fresh one.
    for module in list(sys.modules):
        if module.startswith("ansible"):
            sys.modules.pop(module, None)


def _blocks(path):
    blocks = {}
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ("DOCUMENTATION", "EXAMPLES", "RETURN"):
                    blocks[target.id] = node.value.value
    return blocks


def _description_items(value, where=""):
    # Every item of a description list must be text. An empty item, or an item that YAML reads as a mapping because
    # of ": ", breaks ansible-doc.
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "description" and isinstance(item, list):
                found += ["{}description[{}]".format(where, i) for i, text in enumerate(item) if not isinstance(text, str)]
            found += _description_items(item, "{}{}.".format(where, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found += _description_items(item, "{}[{}].".format(where, index))
    return found


class KeeperDocumentationFormatTest(unittest.TestCase):

    def test_every_description_item_is_text(self):
        paths = [PLUGIN_DIR / "action" / (name + ".py") for name in MODULES] + \
            [PLUGIN_DIR / "modules" / (name + ".py") for name in MODULES] + [PLUGIN_DIR / "lookup" / "keeper.py"]
        for path in paths:
            for block in ("DOCUMENTATION", "RETURN"):
                text = _blocks(path).get(block)
                if text is None:
                    continue
                with self.subTest(path="{}/{}".format(path.parent.name, path.name), block=block):
                    self.assertEqual(_description_items(yaml.safe_load(text)), [])

    def test_module_and_action_documentation_match(self):
        # ansible-doc reads only plugins/modules, and the action plugin has its own copy.
        for name in MODULES:
            module, action = _blocks(PLUGIN_DIR / "modules" / (name + ".py")), _blocks(PLUGIN_DIR / "action" / (name + ".py"))
            for block in ("DOCUMENTATION", "RETURN"):
                with self.subTest(module=name, block=block):
                    self.assertEqual(yaml.safe_load(module.get(block, "")), yaml.safe_load(action.get(block, "")))

    def test_examples_are_yaml(self):
        for path in sorted(PLUGIN_DIR.glob("modules/keeper_*.py")) + [PLUGIN_DIR / "lookup" / "keeper.py"]:
            text = _blocks(path).get("EXAMPLES")
            if text:
                with self.subTest(path="{}/{}".format(path.parent.name, path.name)):
                    self.assertIsInstance(yaml.safe_load(text), list)

    def test_lookup_documents_its_name(self):
        documentation = yaml.safe_load(_blocks(PLUGIN_DIR / "lookup" / "keeper.py")["DOCUMENTATION"])
        self.assertEqual(documentation.get("name"), "keeper")
        self.assertNotIn("module", documentation)


class _Task(object):
    def __init__(self, args, action):
        self.args = args
        self.check_mode = False
        self.async_val = 0
        self.action = action
        self.module_defaults = None


class KeeperMessageTest(unittest.TestCase):

    def setUp(self):
        self.addCleanup(_unload_ansible)
        # The tests reload Ansible, but not this package, so refresh the exception class that it raises.
        from ansible.errors import AnsibleError
        error_patch = patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError)
        error_patch.start()
        self.addCleanup(error_patch.stop)

    @staticmethod
    def _fresh_import(name):
        # A plugin module that an earlier test imported holds the AnsibleError class of an Ansible that is unloaded
        # now, and str() of that class recurses. Import the plugin again, against the current Ansible.
        sys.modules.pop(name, None)
        return __import__(name, fromlist=["*"])

    def _action(self, name, args):
        plugin = self._fresh_import("keeper_secrets_manager_ansible.plugins.action." + name)
        connection = types.SimpleNamespace(_shell=types.SimpleNamespace(tmpdir="/nonexistent"))
        return plugin.ActionModule(_Task(args, name), connection, types.SimpleNamespace(check_mode=False),
                                   None, None, None)

    def test_the_lookup_names_itself(self):
        LookupModule = self._fresh_import("keeper_secrets_manager_ansible.plugins.lookup.keeper").LookupModule
        with patch.object(KeeperAnsible, "__init__", return_value=None):
            for kwargs, message in (({}, "The uid and title are blank. The keeper lookup requires one to be set."),
                                    ({"uid": "UID", "title": "Title"}, "The keeper lookup requires one to be set, "
                                                                      "but not both.")):
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(Exception) as context:
                        LookupModule().run([], variables={}, **kwargs)
                    self.assertIn(message, str(context.exception))

    def test_the_field_message_names_no_single_module(self):
        with self.assertRaises(Exception) as context:
            KeeperAnsible.get_field_type_enum_and_key(args={})
        self.assertEqual(str(context.exception),
                         "Either field, custom_field, file, or notes needs to be set to a non-blank value.")

    def test_keeper_init_rejects_a_token_with_more_parts(self):
        with patch.object(KeeperAnsible, "__init__", side_effect=AssertionError("KeeperAnsible was created")) as init:
            for token, parts in (("IL5:CLIENT_KEY:KEY_ID:SERVER_KEY", 4), ("US:A:B", 3)):
                with self.subTest(token=token):
                    with self.assertRaises(Exception) as context:
                        self._action("keeper_init", {"token": token}).run(task_vars={})
                    self.assertIn("The token has {} parts separated by colons.".format(parts), str(context.exception))
                    self.assertIn("keeper_config_file or keeper_config", str(context.exception))
            init.assert_not_called()
