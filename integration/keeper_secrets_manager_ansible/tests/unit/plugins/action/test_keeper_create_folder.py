from importlib import import_module
from unittest.mock import ANY

import pytest
import yaml
from keeper_secrets_manager_core.dto.dtos import KeeperFolder

PLUGIN = "keeper_create_folder"

SHARED, OPS, DB, PROD, WEB = "SHARED_UID", "OPS_UID", "DB_UID", "PROD_UID", "WEB_UID"


SHARED_KEY = b"s" * 32


@pytest.fixture
def sdk_for(make_sdk, tree, folder):
    """sdk_for(extra=[(uid, parent_uid, name)]): the shared tree plus extra folders; create_folder returns NEW_UID."""
    def make(extra=()):
        # The shared folder has its own key, so a check that takes the key of another folder fails.
        folders = [KeeperFolder(SHARED_KEY, f.folder_uid, f.parent_uid, f.name) if f.folder_uid == SHARED else f
                   for f in tree]
        sdk = make_sdk(folders + [folder(*spec) for spec in extra])
        sdk.client.create_folder.return_value = "NEW_UID"
        return sdk
    return make


def created(sdk):
    # The one create_folder call: (folder_uid, subfolder_uid of the options, name, the folder list passed on).
    sdk.client.create_folder.assert_called_once()
    options, name = sdk.client.create_folder.call_args.args
    return options.folder_uid, options.subfolder_uid, name, sdk.client.create_folder.call_args.kwargs["folders"]


@pytest.mark.parametrize("task_args, parent", [
    ({"shared_folder_uid": SHARED, "folder_name": "New"}, (SHARED, None)),
    ({"shared_folder_uid": SHARED, "subfolder_uid": DB, "folder_name": "New"}, (SHARED, DB)),
    ({"shared_folder_uid": SHARED, "subfolder_uid": PROD, "folder_name": "New"}, (SHARED, PROD)),
    ({"shared_folder_uid": OPS, "folder_name": "New"}, (OPS, None)),
], ids=["in_a_shared_folder", "in_a_subfolder", "in_a_deep_subfolder", "in_another_shared_folder"])
def test_create_sends_the_parent_and_the_folder_list_of_the_one_read(sdk_for, run_plugin, task_args, parent):
    sdk = sdk_for()
    assert run_plugin(sdk, task_args) == {"changed": True, "folder_uid": "NEW_UID"}
    assert len(sdk.action_modules) == 1 and sdk.action_modules[0] is not None
    sdk.client.get_folders.assert_called_once_with()
    shared, subfolder, name, folders = created(sdk)
    assert (shared, subfolder) == parent
    assert name == "New"
    assert [f.folder_uid for f in folders] == [f.folder_uid for f in sdk.client.get_folders()]
    sdk.client.prepare_create_folder_payload.assert_not_called()


# (id, task args, uid of the folder that exists). The folder exists under the target parent, so nothing is created.
EXISTING = [
    ("in_a_shared_folder", {"shared_folder_uid": SHARED, "folder_name": "Staging"}, "EMPTY_UID"),
    ("in_a_subfolder", {"shared_folder_uid": SHARED, "subfolder_uid": DB, "folder_name": "Production"}, PROD),
    ("in_a_deep_subfolder", {"shared_folder_uid": SHARED, "subfolder_uid": PROD, "folder_name": "Archive"},
     "ARCHIVE_UID"),
    ("empty_subfolder_uid_means_the_shared_folder", {"shared_folder_uid": SHARED, "subfolder_uid": "",
                                                     "folder_name": "Staging"}, "EMPTY_UID"),
    ("null_subfolder_uid_means_the_shared_folder", {"shared_folder_uid": SHARED, "subfolder_uid": None,
                                                    "folder_name": "Staging"}, "EMPTY_UID"),
]


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("case", EXISTING, ids=[c[0] for c in EXISTING])
def test_existing_folder_is_returned_and_nothing_is_created(sdk_for, run_plugin, case, check_mode):
    _, task_args, uid = case
    sdk = sdk_for()
    assert run_plugin(sdk, task_args, check_mode=check_mode) == {"changed": False, "folder_uid": uid}
    sdk.client.create_folder.assert_not_called()
    sdk.client.prepare_create_folder_payload.assert_not_called()


# (id, task args): a folder with that name exists, but not under the target parent, or not with exactly that name.
CREATES_ANYWAY = [
    ("same_name_in_another_parent", {"shared_folder_uid": SHARED, "folder_name": "Production"}),
    ("same_name_in_a_deeper_folder", {"shared_folder_uid": SHARED, "subfolder_uid": DB, "folder_name": "Archive"}),
    ("same_name_in_the_shared_folder", {"shared_folder_uid": SHARED, "subfolder_uid": DB, "folder_name": "Staging"}),
    ("name_of_a_shared_folder", {"shared_folder_uid": SHARED, "folder_name": "Operations"}),
    ("different_case", {"shared_folder_uid": SHARED, "folder_name": "staging"}),
    ("start_of_an_existing_name", {"shared_folder_uid": SHARED, "folder_name": "Stag"}),
    ("same_name_below_a_parent_uid_that_starts_like_the_target", {"shared_folder_uid": SHARED, "subfolder_uid": DB,
                                                                  "folder_name": "Child"}),
]
EXTRA_FOLDERS = {"same_name_below_a_parent_uid_that_starts_like_the_target": [("DB_UID_2", SHARED, "Other"),
                                                                              ("CHILD_UID", "DB_UID_2", "Child")]}


@pytest.mark.parametrize("case", CREATES_ANYWAY, ids=[c[0] for c in CREATES_ANYWAY])
def test_a_folder_that_is_not_under_the_target_parent_with_exactly_that_name_is_created(sdk_for, run_plugin, case):
    name, task_args = case
    sdk = sdk_for(EXTRA_FOLDERS.get(name, ()))
    assert run_plugin(sdk, task_args) == {"changed": True, "folder_uid": "NEW_UID"}
    assert created(sdk)[2] == task_args["folder_name"]


def test_the_first_of_two_existing_folders_is_returned(sdk_for, run_plugin):
    sdk = sdk_for([("TWIN_1", SHARED, "Twin"), ("TWIN_2", SHARED, "Twin")])
    result = run_plugin(sdk, {"shared_folder_uid": SHARED, "folder_name": "Twin"})
    assert result == {"changed": False, "folder_uid": "TWIN_1"}


@pytest.mark.parametrize("subfolder", [None, DB])
def test_check_mode_prepares_the_payload_and_creates_nothing(sdk_for, run_plugin, subfolder):
    sdk = sdk_for()
    task_args = {"shared_folder_uid": SHARED, "folder_name": "New"}
    if subfolder:
        task_args["subfolder_uid"] = subfolder
    assert run_plugin(sdk, task_args, check_mode=True) == {"changed": True, "folder_uid": None}
    sdk.client.create_folder.assert_not_called()
    sdk.client.prepare_create_folder_payload.assert_called_once_with(sdk.client.config, ANY, "New", SHARED_KEY)
    options = sdk.client.prepare_create_folder_payload.call_args.args[1]
    assert (options.folder_uid, options.subfolder_uid) == (SHARED, subfolder)


def test_check_mode_checks_that_the_shared_folder_has_a_key(sdk_for, run_plugin):
    sdk = sdk_for()
    with pytest.raises(Exception) as caught:
        run_plugin(sdk, {"shared_folder_uid": "NO_SUCH_UID", "folder_name": "New"}, check_mode=True)
    assert str(caught.value) == ("Could not create folder: Cannot create folder: Unable to create folder - folder "
                                 "key for NO_SUCH_UID not found")
    sdk.client.prepare_create_folder_payload.assert_not_called()


def test_check_mode_reports_a_payload_error(sdk_for, run_plugin):
    sdk = sdk_for()
    sdk.client.prepare_create_folder_payload.side_effect = ValueError("bad payload")
    with pytest.raises(Exception) as caught:
        run_plugin(sdk, {"shared_folder_uid": SHARED, "folder_name": "New"}, check_mode=True)
    assert str(caught.value) == "Could not create folder: Cannot create folder: bad payload"


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("task_args, message", [
    ({"folder_name": "New"}, "missing required arguments: shared_folder_uid"),
    ({"shared_folder_uid": SHARED}, "missing required arguments: folder_name"),
    ({"shared_folder_uid": None, "folder_name": "New"},
     "The shared_folder_uid option is null. Give it a value, or leave the option out of the task."),
])
def test_missing_options_fail_before_client_initialization(sdk_for, run_plugin, task_args, message, check_mode):
    sdk = sdk_for()
    assert run_plugin(sdk, task_args, check_mode=check_mode) == {"failed": True, "changed": False, "msg": message}
    assert sdk.inits == 0
    assert sdk.client.mock_calls == []


def test_get_folders_error(sdk_for, run_plugin):
    sdk = sdk_for()
    sdk.client.get_folders.side_effect = Exception("network is down")
    with pytest.raises(Exception) as caught:
        run_plugin(sdk, {"shared_folder_uid": SHARED, "folder_name": "New"})
    assert str(caught.value) == "Could not create folder: Cannot get existing folders: network is down"
    sdk.client.create_folder.assert_not_called()


def test_create_error_is_not_retried(sdk_for, run_plugin, plugin_module):
    sdk = sdk_for()
    sdk.client.create_folder.side_effect = Exception("access denied")
    with pytest.raises(plugin_module.AnsibleError) as caught:
        run_plugin(sdk, {"shared_folder_uid": SHARED, "folder_name": "New"})
    assert str(caught.value) == "Could not create folder: Cannot create folder: access denied"
    sdk.client.create_folder.assert_called_once()


def test_documented_options_and_return_values(sdk_for, run_plugin, plugin_module):
    documentation = yaml.safe_load(plugin_module.DOCUMENTATION)
    module_stub = import_module("keeper_secrets_manager_ansible.plugins.modules." + PLUGIN)
    assert yaml.safe_load(module_stub.DOCUMENTATION) == documentation
    options = documentation["options"]
    assert {n: bool(o.get("required", False)) for n, o in options.items()} == {
        "shared_folder_uid": True, "subfolder_uid": False, "folder_name": True}
    spec = plugin_module.ActionModule.ARGUMENT_SPEC
    assert set(spec) == set(options)
    for name, option in options.items():
        assert spec[name]["type"] == option["type"]
        assert spec[name].get("required", False) == bool(option.get("required", False))
    result = run_plugin(sdk_for(), {"shared_folder_uid": SHARED, "folder_name": "New"})
    assert set(yaml.safe_load(plugin_module.RETURN)) == set(result)
