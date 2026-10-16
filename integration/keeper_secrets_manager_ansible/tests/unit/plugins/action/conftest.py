"""
Fixtures for tests of the folder action plugins. They drive the plugin's run() with a fake SDK client, so the
option checks, the plugin wiring, and the KeeperAnsible method are covered by the same test.
"""
import importlib
import sys
import threading
import types
from unittest.mock import MagicMock, create_autospec, patch

import pytest
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.dto.dtos import KeeperFolder

from keeper_secrets_manager_ansible import KeeperAnsible

def bounded(call):
    # A parent-chain walk that does not detect a cycle loops forever. A thread turns that into a failed test.
    outcome = {}

    def target():
        try:
            outcome["result"] = call()
        except Exception as err:
            outcome["error"] = err

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(30)
    assert not thread.is_alive(), "the call did not end; a loop in the code under test has no guard"
    return outcome


GROUP = "group/keepersecurity.keeper_secrets_manager.keeper_secrets_manager"


@pytest.fixture(scope="module", autouse=True)
def _unload_ansible_after_module():
    # Importing a plugin loads ansible.plugins.loader with the default plugin path. A loader that is loaded before
    # AnsibleTestFramework sets the keeper action path cannot find the keeper actions, so the next playbook test
    # would fail with "couldn't resolve module/action". tests/conftest.py does the same after collection.
    yield
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)


@pytest.fixture
def folder():
    return lambda uid, parent_uid, name: KeeperFolder(b"k" * 32, uid, parent_uid, name)


@pytest.fixture
def record():
    def make(uid, folder_uid, inner_folder_uid=None):
        # A plain object: a MagicMock has a truthy inner_folder_uid, so every record would look like it is in a
        # subfolder and the top-level record rules would never run.
        return types.SimpleNamespace(uid=uid, title=uid, folder_uid=folder_uid, inner_folder_uid=inner_folder_uid)
    return make


_DEFAULT_RESPONSE = object()


class FakeSdk(object):
    """
    A fake SDK client. get_folders returns `folders` until delete_folder is called, then the tree without
    `deleted_uids` (or `folders_after`), like the server: a deleted folder is not in the next response.
    """

    def __init__(self, folders, records=None, delete_response=_DEFAULT_RESPONSE, folders_after=None,
                 deleted_uids=None, init_error=None, autospec=False):
        # An autospec client fails a call that does not fit the real SDK signature, such as a misspelled keyword.
        self.client = create_autospec(SecretsManager, instance=True) if autospec else MagicMock()
        self.inits = 0
        self.action_modules = []
        self.init_error = init_error
        before = list(folders)
        after = list(before if folders_after is None else folders_after)
        if folders_after is None:
            after = [f for f in before if f.folder_uid not in (deleted_uids or [])]
        self.client.get_folders.side_effect = lambda: list(after if self.client.delete_folder.called else before)
        self.client.get_secrets.return_value = list(records or [])
        if delete_response is _DEFAULT_RESPONSE:
            delete_response = lambda uids, force_deletion=False: [{"folderUid": u, "responseCode": "ok"} for u in uids]
        if callable(delete_response):
            self.client.delete_folder.side_effect = delete_response
        else:
            self.client.delete_folder.return_value = delete_response

    def keeper(self):
        keeper = object.__new__(KeeperAnsible)
        keeper.client = self.client
        return keeper

    def init(self):
        sdk = self

        def __init__(keeper, task_vars, action_module=None, task_attributes=None, force_in_memory=False):
            sdk.inits += 1
            sdk.action_modules.append(action_module)
            if sdk.init_error is not None:
                raise sdk.init_error
            keeper.client = sdk.client
        return __init__


@pytest.fixture
def make_sdk():
    """A delete_response of None is a real response value, so the default is a function that answers ok."""
    return lambda folders, **kwargs: FakeSdk(folders, **kwargs)


@pytest.fixture
def plugin_name(request):
    """The module under test: the PLUGIN constant of the test file, keeper_delete_folder if it has none."""
    return getattr(request.module, "PLUGIN", "keeper_delete_folder")


@pytest.fixture
def plugin_module(plugin_name):
    # Imported inside the fixture, not at the top of a test file: see _unload_ansible_after_module.
    return importlib.import_module("keeper_secrets_manager_ansible.plugins.action." + plugin_name)


@pytest.fixture
def run_plugin(plugin_module, plugin_name):
    def run(sdk, task_args, check_mode=False, module_defaults=None, templar=None):
        task = types.SimpleNamespace(args=dict(task_args), check_mode=check_mode, async_val=0,
                                     action=plugin_name, module_defaults=module_defaults)
        connection = types.SimpleNamespace(_shell=types.SimpleNamespace(tmpdir="/nonexistent"))
        action = plugin_module.ActionModule(task, connection, types.SimpleNamespace(), None, templar, None)
        with patch.object(KeeperAnsible, "__init__", sdk.init()):
            return action.run(task_vars={})
    return run


@pytest.fixture
def tree(folder):
    """
    Infrastructure (SHARED_UID, a shared folder, parent "" as the SDK returns it)
      Staging (EMPTY_UID), Databases (DB_UID) > Production (PROD_UID) > Archive (ARCHIVE_UID), Web (WEB_UID)
    Operations (OPS_UID), a shared folder with no subfolders.
    """
    return [
        folder("SHARED_UID", "", "Infrastructure"),
        folder("OPS_UID", "", "Operations"),
        folder("EMPTY_UID", "SHARED_UID", "Staging"),
        folder("DB_UID", "SHARED_UID", "Databases"),
        folder("PROD_UID", "DB_UID", "Production"),
        folder("ARCHIVE_UID", "PROD_UID", "Archive"),
        folder("WEB_UID", "SHARED_UID", "Web"),
    ]
