import copy
import importlib
import json
import traceback
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import keeper_secrets_manager_ansible as keeper_module


ACTIONS = (
    "keeper_create", "keeper_create_folder", "keeper_get_folder",
    "keeper_update_folder", "keeper_delete_folder",
)
CANARY = "SYNTHETIC_DETAIL_5934"
RENAMED = (
    "The folder_uid parameter for keeper_create has been renamed to subfolder_uid. "
    "Please update your playbook.")
BASE_ARGS = {
    "keeper_create": {
        "shared_folder_uid": "SHARED_UID", "record_type": "login", "title": "Synthetic record",
        "fields": [{"type": "login", "value": "synthetic-user"}],
    },
    "keeper_create_folder": {"shared_folder_uid": "SHARED_UID", "folder_name": "New folder"},
    "keeper_get_folder": {"shared_folder_uid": "SHARED_UID"},
    "keeper_update_folder": {"folder_uid": "EMPTY_UID", "new_folder_name": "Renamed"},
    "keeper_delete_folder": {"folder_uid": "EMPTY_UID"},
}


def args_for(action_name, updates=None, omit=()):
    args = copy.deepcopy(BASE_ARGS[action_name])
    args.update(updates or {})
    for name in omit:
        args.pop(name, None)
    return args


def null_message(name):
    return "The {} option is null. Give it a value, or leave the option out of the task.".format(name)


def failed_action(run_plugin, sdk, action_name, args, no_log, check_mode, task_vars=None, templar=None):
    try:
        result = run_plugin(
            sdk, args, action_name=action_name, no_log=no_log, check_mode=check_mode,
            task_vars=task_vars, templar=templar)
    except Exception as error:
        if no_log:
            assert type(error) is keeper_module.KeeperFolderError
            assert error.__cause__ is None
            assert error.__context__ is None
        return None, error, str(error)
    assert type(result) is dict
    assert result == {"failed": True, "changed": False, "msg": result["msg"]}
    assert not hasattr(result, "_keeper_safe_diagnostic")
    return result, None, result["msg"]


def diagnostic_operation(error, no_log, returned=False, prefix=""):
    @keeper_module._private_folder_diagnostics
    def operation(owner):
        if returned:
            return keeper_module._folder_failure(error, prefix)
        raise error
    return operation(SimpleNamespace(_task=SimpleNamespace(no_log=no_log)))


@pytest.mark.parametrize("no_log", [False, True])
@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("old_uid", ["DB_UID", ""], ids=["populated", "empty"])
def test_renamed_parameter_retains_exact_guidance(make_sdk, tree, run_plugin, no_log, check_mode, old_uid):
    sdk = make_sdk(tree)
    _, error, message = failed_action(
        run_plugin, sdk, "keeper_create", args_for("keeper_create", {"folder_uid": old_uid}), no_log, check_mode)
    assert error is not None
    assert message == RENAMED
    if not no_log:
        plugin = importlib.import_module("keeper_secrets_manager_ansible.plugins.action.keeper_create")
        assert type(error) is plugin.AnsibleError
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("action_name,args,message", [
    pytest.param("keeper_create", args_for("keeper_create", omit=["shared_folder_uid"]),
                 "The shared_folder_uid is blank. keeper_create requires this value to be set.",
                 id="record-missing-shared"),
    pytest.param("keeper_create", args_for("keeper_create", omit=["record_type"]),
                 "The record_type is blank. keeper_create requires this value to be set.",
                 id="record-missing-type"),
    pytest.param("keeper_create", args_for("keeper_create", omit=["title"]),
                 "The title is blank. keeper_create requires this value to be set.", id="record-missing-title"),
    pytest.param("keeper_create_folder", args_for("keeper_create_folder", omit=["shared_folder_uid"]),
                 "missing required arguments: shared_folder_uid", id="creation-missing-shared"),
    pytest.param("keeper_create_folder", args_for("keeper_create_folder", omit=["folder_name"]),
                 "missing required arguments: folder_name", id="creation-missing-name"),
    pytest.param("keeper_create_folder", args_for("keeper_create_folder", {"shared_folder_uid": None}),
                 null_message("shared_folder_uid"), id="creation-null-shared"),
    pytest.param("keeper_create_folder", args_for("keeper_create_folder", {"folder_name": None}),
                 null_message("folder_name"), id="creation-null-name"),
    pytest.param("keeper_create_folder", args_for("keeper_create_folder", {"folder_name": ""}),
                 "The folder_name is blank. keeper_create_folder requires this value to be set.",
                 id="creation-blank-name"),
    pytest.param("keeper_create_folder", args_for("keeper_create_folder", {"folder_name": "   "}),
                 "The folder_name is blank. keeper_create_folder requires this value to be set.",
                 id="creation-whitespace-name"),
    pytest.param("keeper_get_folder", {}, "Could not look up folder: There is nothing to look up. "
                 "Set shared_folder_uid, subfolder_uid, folder_name, or folder_path.", id="lookup-no-selector"),
    pytest.param("keeper_get_folder", args_for("keeper_get_folder", {"shared_folder_uid": None}),
                 null_message("shared_folder_uid"), id="lookup-null-shared"),
    pytest.param("keeper_get_folder", args_for("keeper_get_folder", {"include_subfolders": None}),
                 null_message("include_subfolders"), id="lookup-null-include"),
    pytest.param("keeper_get_folder", args_for("keeper_get_folder", {"folder_name": "Name", "folder_path": "Path"}),
                 "parameters are mutually exclusive: folder_name|folder_path", id="lookup-conflict"),
    pytest.param("keeper_get_folder", args_for("keeper_get_folder", {"folder_name": ""}),
                 "Could not look up folder: The folder_name is set but blank. "
                 "Set it to a folder name, or remove it.", id="lookup-blank-name"),
    pytest.param("keeper_get_folder", args_for("keeper_get_folder", {"folder_path": 17}),
                 "Could not look up folder: The folder_path must be a string or a list of folder names.",
                 id="lookup-path-container"),
    pytest.param("keeper_get_folder", args_for("keeper_get_folder", {"subfolder_uid": ""}),
                 "Could not look up folder: The subfolder_uid is set but blank. "
                 "Set it to a folder UID, or remove it.", id="lookup-blank-subfolder"),
    pytest.param("keeper_update_folder", args_for("keeper_update_folder", omit=["folder_uid"]),
                 "missing required arguments: folder_uid", id="rename-missing-uid"),
    pytest.param("keeper_update_folder", args_for("keeper_update_folder", omit=["new_folder_name"]),
                 "missing required arguments: new_folder_name", id="rename-missing-name"),
    pytest.param("keeper_update_folder", args_for("keeper_update_folder", {"new_folder_name": None}),
                 null_message("new_folder_name"), id="rename-null-name"),
    pytest.param("keeper_update_folder", args_for("keeper_update_folder", {"folder_uid": ""}),
                 "Could not update folder: The folder_uid is blank.", id="rename-blank-uid"),
    pytest.param("keeper_update_folder", args_for("keeper_update_folder", {"new_folder_name": ""}),
                 "Could not update folder: The new_folder_name is blank.", id="rename-blank-name"),
    pytest.param("keeper_delete_folder", {}, "missing required arguments: folder_uid", id="delete-missing-uid"),
    pytest.param("keeper_delete_folder", {"folder_uid": None}, null_message("folder_uid"), id="delete-null-uid"),
    pytest.param("keeper_delete_folder", args_for("keeper_delete_folder", {"force_deletion": None}),
                 null_message("force_deletion"), id="delete-null-force"),
    pytest.param("keeper_delete_folder", {"folder_uid": ""},
                 "Could not delete folder: The folder_uid is blank.", id="delete-blank-uid"),
])
@pytest.mark.parametrize("no_log", [False, True])
@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
def test_static_validation_messages_survive_the_action_boundary(
        make_sdk, tree, run_plugin, action_name, args, message, no_log, check_mode):
    sdk = make_sdk(tree)
    result, error, observed = failed_action(run_plugin, sdk, action_name, args, no_log, check_mode)
    assert observed == message
    assert (error is not None) is (action_name == "keeper_create")
    if result is not None:
        assert CANARY not in json.dumps(result)
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("no_log", [False, True])
@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
def test_record_type_container_guidance_is_static(make_sdk, tree, run_plugin, no_log, check_mode):
    sdk = make_sdk(tree)
    _, error, message = failed_action(
        run_plugin, sdk, "keeper_create", args_for("keeper_create"), no_log, check_mode,
        task_vars={"keeper_record_types": CANARY})
    assert error is not None
    assert message == "The Keeper record types is not a list."
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("action_name,args", [
    pytest.param("keeper_create", args_for("keeper_create", {"record_type": CANARY}), id="record-type"),
    pytest.param("keeper_create_folder", args_for("keeper_create_folder", {"folder_name": " " + CANARY}),
                 id="creation-name"),
    pytest.param("keeper_get_folder", args_for("keeper_get_folder", {"shared_folder_uid": " " + CANARY}),
                 id="lookup-uid"),
    pytest.param("keeper_get_folder", args_for("keeper_get_folder", {"folder_path": [CANARY, None]}),
                 id="lookup-path"),
    pytest.param("keeper_get_folder", args_for("keeper_get_folder", {"include_subfolders": CANARY}),
                 id="lookup-boolean"),
    pytest.param("keeper_update_folder", args_for("keeper_update_folder", {"new_folder_name": " " + CANARY}),
                 id="rename-name"),
    pytest.param("keeper_delete_folder", args_for("keeper_delete_folder", {"force_deletion": CANARY}),
                 id="delete-boolean"),
    pytest.param("keeper_delete_folder", {"force_deletion": CANARY}, id="required-and-value-error"),
    pytest.param("keeper_create_folder", {"folder_name": "New folder", CANARY: "unknown"},
                 id="required-and-unknown"),
    pytest.param("keeper_create_folder", {"shared_folder_uid": None, "folder_name": 5934},
                 id="null-and-value-error"),
    pytest.param("keeper_delete_folder", {"folder_uid": None, CANARY: "unknown"}, id="null-and-unknown"),
])
@pytest.mark.parametrize("no_log", [False, True])
@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
def test_dynamic_and_mixed_diagnostics_stay_private(
        make_sdk, tree, run_plugin, action_name, args, no_log, check_mode):
    sdk = make_sdk(tree)
    _, _, message = failed_action(run_plugin, sdk, action_name, args, no_log, check_mode)
    if no_log:
        assert message == keeper_module._PRIVATE_FOLDER_MESSAGE
        assert CANARY not in message
    else:
        assert message != keeper_module._PRIVATE_FOLDER_MESSAGE
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("no_log", [False, True])
@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
def test_known_null_messages_can_be_aggregated(make_sdk, tree, run_plugin, no_log, check_mode):
    sdk = make_sdk(tree)
    _, _, message = failed_action(
        run_plugin, sdk, "keeper_update_folder", {"folder_uid": None, "new_folder_name": None}, no_log, check_mode)
    assert message == null_message("folder_uid") + " " + null_message("new_folder_name")
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("error_type", [
    ValueError, RuntimeError, keeper_module.KeeperArgumentError, keeper_module.KeeperFolderError,
])
def test_safe_error_factory_preserves_the_original_error_type(error_type):
    error = keeper_module._safe_diagnostic_error(error_type, CANARY, public_message=RENAMED)
    assert type(error) is error_type
    assert str(error) == CANARY
    assert type(error._keeper_safe_diagnostic) is keeper_module._SafeDiagnostic
    assert str(error._keeper_safe_diagnostic) == RENAMED


@pytest.mark.parametrize("action_name", ACTIONS)
@pytest.mark.parametrize("error_kind", ["runtime", "argument", "folder", "ansible"])
@pytest.mark.parametrize("no_log", [False, True])
@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
def test_unclassified_errors_are_not_approved_by_class_or_message(
        make_sdk, tree, run_plugin, action_name, error_kind, no_log, check_mode):
    ansible_error = importlib.import_module("ansible.errors").AnsibleError
    error_type = {"runtime": RuntimeError, "argument": keeper_module.KeeperArgumentError,
                  "folder": keeper_module.KeeperFolderError, "ansible": ansible_error}[error_kind]
    original = error_type(RENAMED)
    sdk = make_sdk(tree, init_error=original)
    _, error, message = failed_action(
        run_plugin, sdk, action_name, args_for(action_name), no_log, check_mode)
    assert error is not None
    assert message == (keeper_module._PRIVATE_FOLDER_MESSAGE if no_log else RENAMED)
    if not no_log:
        assert error is original
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("action_name", ACTIONS)
@pytest.mark.parametrize("no_log", [False, True])
@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
def test_real_constructor_retains_missing_config_guidance(
        make_sdk, tree, run_plugin, monkeypatch, tmp_path, action_name, no_log, check_mode):
    monkeypatch.delenv("KSM_TOKEN", raising=False)
    monkeypatch.setattr(keeper_module, "AnsibleError", importlib.import_module("ansible.errors").AnsibleError)
    sdk = make_sdk(tree)
    original_init = keeper_module.KeeperAnsible.__init__
    monkeypatch.setattr(sdk, "init", lambda: original_init)
    get_client = MagicMock(side_effect=AssertionError("no SDK client should be constructed"))
    monkeypatch.setattr(keeper_module.KeeperAnsible, "get_client", get_client)
    _, error, message = failed_action(
        run_plugin, sdk, action_name, args_for(action_name), no_log, check_mode,
        task_vars={"keeper_config_file": str(tmp_path / "missing.json")},
        templar=SimpleNamespace(template=lambda value: value))
    assert error is not None
    assert message == (
        "Keeper Ansible error: There is no config file and the Ansible variable contain no config keys."
        " Will not be able to connect to the Keeper server.")
    get_client.assert_not_called()
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("no_log", [False, True])
@pytest.mark.parametrize("returned", [False, True], ids=["exception", "returned-failure"])
def test_public_guidance_is_separate_from_the_original_message(no_log, returned):
    error = keeper_module._safe_diagnostic_error(ValueError, CANARY, public_message=RENAMED)
    if returned:
        result = diagnostic_operation(error, no_log, returned=True, prefix="Could not complete operation: ")
        assert type(result) is dict
        assert result == {"failed": True, "changed": False,
                          "msg": "Could not complete operation: " + (RENAMED if no_log else CANARY)}
        assert not hasattr(result, "_keeper_safe_diagnostic")
    else:
        with pytest.raises(Exception) as caught:
            diagnostic_operation(error, no_log)
        assert str(caught.value) == (RENAMED if no_log else CANARY)
        assert type(caught.value) is (keeper_module.KeeperFolderError if no_log else ValueError)
        assert (caught.value is error) is (not no_log)


@pytest.mark.parametrize("marked", [False, True], ids=["unclassified", "classified"])
@pytest.mark.parametrize("no_log", [False, True])
def test_private_exceptions_clear_cause_and_context(marked, no_log):
    error = keeper_module._safe_diagnostic_error(ValueError, CANARY, RENAMED) if marked else ValueError(CANARY)

    @keeper_module._private_folder_diagnostics
    def operation(owner):
        try:
            raise RuntimeError(CANARY)
        except RuntimeError as cause:
            raise error from cause

    with pytest.raises(Exception) as caught:
        operation(SimpleNamespace(_task=SimpleNamespace(no_log=no_log)))
    observed = caught.value
    rendered = "".join(traceback.format_exception(type(observed), observed, observed.__traceback__))
    if no_log:
        assert type(observed) is keeper_module.KeeperFolderError
        assert observed is not error
        assert observed.__cause__ is None
        assert observed.__context__ is None
        assert CANARY not in rendered
        assert str(observed) == (RENAMED if marked else keeper_module._PRIVATE_FOLDER_MESSAGE)
    else:
        assert observed is error
        assert observed.__cause__ is not None
        assert observed.__context__ is not None
        assert CANARY in rendered


@pytest.mark.parametrize("returned", [False, True], ids=["exception", "returned-failure"])
@pytest.mark.parametrize("marker_kind", ["string", "subclass", "unreadable"])
def test_untrusted_classification_attributes_are_ignored(returned, marker_kind):
    class OtherDiagnostic(keeper_module._SafeDiagnostic):
        pass

    class UnreadableError(ValueError):
        @property
        def _keeper_safe_diagnostic(self):
            raise RuntimeError(CANARY)

    error = UnreadableError(RENAMED) if marker_kind == "unreadable" else ValueError(RENAMED)
    if marker_kind != "unreadable":
        error._keeper_safe_diagnostic = RENAMED if marker_kind == "string" else OtherDiagnostic(RENAMED)
    if returned:
        result = diagnostic_operation(error, True, returned=True)
        assert result == {"failed": True, "changed": False, "msg": keeper_module._PRIVATE_FOLDER_MESSAGE}
        assert type(result) is dict
    else:
        with pytest.raises(keeper_module.KeeperFolderError) as caught:
            diagnostic_operation(error, True)
        assert str(caught.value) == keeper_module._PRIVATE_FOLDER_MESSAGE


@pytest.mark.parametrize("classified", [False, True])
def test_private_failure_results_drop_nonpublic_metadata(classified):
    error = keeper_module._safe_diagnostic_error(ValueError, CANARY, RENAMED) if classified else ValueError(RENAMED)
    internal = keeper_module._folder_failure(error)
    internal.update(changed=True, exception=CANARY, invocation={"module_args": {"folder_uid": CANARY}})

    @keeper_module._private_folder_diagnostics
    def operation(owner):
        return internal

    result = operation(SimpleNamespace(_task=SimpleNamespace(no_log=True)))
    assert type(result) is dict
    assert result == {"failed": True, "changed": False,
                      "msg": RENAMED if classified else keeper_module._PRIVATE_FOLDER_MESSAGE}
    assert not hasattr(result, "_keeper_safe_diagnostic")
    assert CANARY not in json.dumps(result)


def test_arbitrary_dict_subclasses_cannot_mark_results_safe():
    class OtherResult(dict):
        pass

    internal = OtherResult(failed=True, changed=True, msg=RENAMED, exception=CANARY)
    internal._keeper_safe_diagnostic = keeper_module._SafeDiagnostic(RENAMED)

    @keeper_module._private_folder_diagnostics
    def operation(owner):
        return internal

    result = operation(SimpleNamespace(_task=SimpleNamespace(no_log=True)))
    assert type(result) is dict
    assert result == {"failed": True, "changed": False, "msg": keeper_module._PRIVATE_FOLDER_MESSAGE}


@pytest.mark.parametrize("no_log", [False, True])
@pytest.mark.parametrize("error_kind", ["required", "exclusive", "unsupported"])
def test_validator_guidance_is_rebuilt_from_the_canonical_schema(
        make_sdk, tree, run_plugin, monkeypatch, no_log, error_kind):
    if error_kind == "exclusive":
        action_name = "keeper_get_folder"
        args = {"folder_name": "Name", "folder_path": "Path"}
        error = keeper_module.MutuallyExclusiveError(CANARY)
        public_message = "parameters are mutually exclusive: folder_name|folder_path"
    else:
        action_name = "keeper_delete_folder"
        args = {} if error_kind == "required" else {"folder_uid": "EMPTY_UID"}
        error_type = keeper_module.RequiredError if error_kind == "required" else keeper_module.UnsupportedError
        error = error_type(CANARY)
        public_message = "missing required arguments: folder_uid"
    validator = MagicMock()
    validator.validate.return_value = SimpleNamespace(
        error_messages=[CANARY], errors=SimpleNamespace(errors=[error]))
    monkeypatch.setattr(keeper_module, "ArgumentSpecValidator", MagicMock(return_value=validator))
    sdk = make_sdk(tree)
    _, _, message = failed_action(run_plugin, sdk, action_name, args, no_log, False)
    if no_log:
        expected = keeper_module._PRIVATE_FOLDER_MESSAGE if error_kind == "unsupported" else public_message
        assert message == expected
        assert CANARY not in message
    else:
        assert CANARY in message
    assert sdk.client.mock_calls == []
