import importlib

import pytest

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFolderError

from .conftest import GROUP

EMPTY, DB, PROD, WEB, OPS, SHARED = "EMPTY_UID", "DB_UID", "PROD_UID", "WEB_UID", "OPS_UID", "SHARED_UID"
EMPTY_LABEL = '"Infrastructure/Staging" (UID EMPTY_UID)'
DB_LABEL = '"Infrastructure/Databases" (UID DB_UID)'
LABELS = {EMPTY: EMPTY_LABEL, DB: DB_LABEL, PROD: '"Infrastructure/Databases/Production" (UID PROD_UID)',
          OPS: '"Operations" (UID OPS_UID)', SHARED: '"Infrastructure" (UID SHARED_UID)'}
SUPPORTED = {"folder_uid", "force_deletion"}
NULL_MESSAGE = "The {} option is null. Give it a value, or leave the option out of the task."
NOT_A_STRING = ("The folder_uid option must be a string, but it is {}. Put quotes around the value, or use the "
                "string filter.")
NOT_EMPTY = ("The folder {} is not empty. It contains {} record(s) and {} subfolder(s). Set force_deletion to true "
             "to delete the folder and everything in it.")


def assert_failure(result, msg):
    # The plugin returns a failure, so failed_when, rescue, and ignore_errors work on it. "is" because
    # {"failed": 1} == {"failed": True}.
    assert sorted(result) == ["changed", "failed", "msg"]
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["msg"] == msg


def delete_failure(msg):
    return "Could not delete folder: " + msg


def assert_unsupported(result, *options):
    # The supported names are compared as a set: ansible-core before 2.15 did not always sort them.
    assert result["failed"] is True and result["changed"] is False
    before, marker, after = result["msg"].partition("Supported parameters include: ")
    assert before == "Unsupported parameters for (keeper_delete_folder) module: {}. ".format(
        ", ".join(sorted(options)))
    assert marker and after.endswith(".")
    assert set(after[:-1].split(", ")) == SUPPORTED


def not_found(uid):
    return {"changed": False, "folder_uid": uid, "folder_name": None,
            "msg": "The folder {} was not found, or it is not shared to this KSM application. Nothing was "
                   "deleted.".format(uid)}


def changed(uid, name):
    return {"changed": True, "folder_uid": uid, "folder_name": name}


def records_of(record, specs):
    return [record(*spec) for spec in specs]


# --- Happy path and the force / check mode dimensions ---

@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("force", [False, True])
def test_empty_folder_is_deleted(make_sdk, run_plugin, tree, force, check_mode):
    sdk = make_sdk(tree, deleted_uids=[EMPTY])
    result = run_plugin(sdk, {"folder_uid": EMPTY, "force_deletion": force}, check_mode=check_mode)

    assert result == changed(EMPTY, "Staging")
    if check_mode:
        sdk.client.delete_folder.assert_not_called()
    else:
        sdk.client.delete_folder.assert_called_once_with([EMPTY], force_deletion=force)
        assert sdk.client.delete_folder.call_args.kwargs["force_deletion"] is force
    # Force skips the records check. Check mode still runs it.
    assert sdk.client.get_secrets.called is (not force)


@pytest.mark.parametrize("check_mode", [False, True])
def test_force_deletes_a_folder_with_its_contents(make_sdk, run_plugin, tree, record, check_mode):
    sdk = make_sdk(tree, records=[record("R1", SHARED, DB)], deleted_uids=[DB, PROD, "ARCHIVE_UID"])
    result = run_plugin(sdk, {"folder_uid": DB, "force_deletion": True}, check_mode=check_mode)

    assert result == changed(DB, "Databases")
    sdk.client.get_secrets.assert_not_called()
    assert sdk.client.delete_folder.called is (not check_mode)


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("force", [False, True])
def test_missing_folder_is_not_changed(make_sdk, run_plugin, tree, force, check_mode):
    sdk = make_sdk(tree)
    result = run_plugin(sdk, {"folder_uid": "MISSING_UID", "force_deletion": force}, check_mode=check_mode)

    assert result == not_found("MISSING_UID")
    sdk.client.get_secrets.assert_not_called()
    sdk.client.delete_folder.assert_not_called()


def test_get_folders_returning_none_means_not_found(make_sdk, run_plugin, tree):
    sdk = make_sdk(tree)
    sdk.client.get_folders.side_effect = None
    sdk.client.get_folders.return_value = None
    assert run_plugin(sdk, {"folder_uid": EMPTY}) == not_found(EMPTY)
    sdk.client.delete_folder.assert_not_called()


def test_uid_is_matched_exactly(make_sdk, run_plugin, tree):
    assert run_plugin(make_sdk(tree), {"folder_uid": EMPTY.lower()}) == not_found(EMPTY.lower())


# --- Emptiness rules: only DIRECT content counts ---

# (id, folder, [(record uid, folder_uid, inner_folder_uid)], records, subfolders)
NOT_EMPTY_CASES = [
    ("subfolder_only", PROD, [], 0, 1),
    ("record_in_subfolder", EMPTY, [("R1", SHARED, EMPTY)], 1, 0),
    ("top_level_record", OPS, [("R1", OPS, None)], 1, 0),
    ("empty_string_inner_uid_is_top_level", OPS, [("R1", OPS, "")], 1, 0),
    ("inner_uid_equal_to_shared_folder", OPS, [("R1", OPS, OPS)], 1, 0),
    ("counts_are_exact", DB, [("R1", SHARED, DB), ("R2", SHARED, DB), ("R3", SHARED, WEB)], 2, 1),
    ("record_in_subfolder_is_not_direct_in_shared", SHARED, [("R1", SHARED, EMPTY)], 0, 3),
    ("grandchild_record_is_not_direct", DB, [("R1", SHARED, PROD), ("R2", SHARED, "ARCHIVE_UID")], 0, 1),
    ("grandchild_folder_is_not_direct", DB, [], 0, 1),
]

# Content that is not in the folder: the folder is deleted.
NOT_COUNTED_CASES = [
    ("record_in_sibling_subfolder", EMPTY, [("R1", SHARED, WEB)]),
    ("top_level_record_of_the_shared_folder", EMPTY, [("R1", SHARED, None), ("R2", SHARED, "")]),
    ("record_in_another_shared_folder", EMPTY, [("R1", OPS, None)]),
    ("record_shared_directly_to_the_app", OPS, [("R1", "", None)]),
]


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("case", NOT_EMPTY_CASES, ids=[c[0] for c in NOT_EMPTY_CASES])
def test_folder_with_direct_content_fails_without_force(make_sdk, run_plugin, tree, record, case, check_mode):
    _, uid, specs, record_count, subfolder_count = case
    sdk = make_sdk(tree, records=records_of(record, specs))
    result = run_plugin(sdk, {"folder_uid": uid}, check_mode=check_mode)

    label = LABELS[uid]
    assert_failure(result, delete_failure(NOT_EMPTY.format(label, record_count, subfolder_count)))
    sdk.client.get_secrets.assert_called_once_with()
    sdk.client.delete_folder.assert_not_called()


@pytest.mark.parametrize("case", NOT_COUNTED_CASES, ids=[c[0] for c in NOT_COUNTED_CASES])
def test_content_outside_the_folder_does_not_block_the_delete(make_sdk, run_plugin, tree, record, case):
    _, uid, specs = case
    sdk = make_sdk(tree, records=records_of(record, specs), deleted_uids=[uid])
    assert run_plugin(sdk, {"folder_uid": uid})["changed"] is True
    sdk.client.delete_folder.assert_called_once_with([uid], force_deletion=False)


# --- force_deletion: only the value True forces ---

@pytest.mark.parametrize("value", ["true", "True", "yes", "false", "1", 1, 1.0, [True], (True,), {"force": True},
                                   object(), False, None, 0, "", "no"])
def test_value_that_is_not_true_never_forces(make_sdk, tree, record, value):
    # Straight to the method: the plugin's argument spec turns "yes" into True before the method sees it.
    sdk = make_sdk(tree, records=[record("R1", SHARED, WEB)])
    with pytest.raises(KeeperFolderError, match="is not empty"):
        sdk.keeper().delete_folder(WEB, force=value)
    sdk.client.delete_folder.assert_not_called()

    sdk = make_sdk(tree, deleted_uids=[EMPTY])
    sdk.keeper().delete_folder(EMPTY, force=value)
    assert sdk.client.delete_folder.call_args.kwargs["force_deletion"] is False


@pytest.mark.parametrize("value, forced", [("yes", True), ("true", True), (True, True), ("false", False),
                                           ("no", False), (False, False)])
def test_force_deletion_option_is_converted_before_it_reaches_the_sdk(make_sdk, run_plugin, tree, record, value,
                                                                       forced):
    sdk = make_sdk(tree, records=[record("R1", SHARED, DB)], deleted_uids=[DB, PROD, "ARCHIVE_UID"])
    result = run_plugin(sdk, {"folder_uid": DB, "force_deletion": value})
    if forced:
        assert result == changed(DB, "Databases")
        sdk.client.delete_folder.assert_called_once_with([DB], force_deletion=True)
    else:
        assert_failure(result, delete_failure(NOT_EMPTY.format(DB_LABEL, 1, 1)))
        sdk.client.delete_folder.assert_not_called()


@pytest.mark.parametrize("raw", ["yes", "true", 1, None])
def test_plugin_passes_a_real_bool_even_if_validation_returns_a_raw_value(make_sdk, run_plugin, tree, raw, monkeypatch):
    monkeypatch.setattr(KeeperAnsible, "validate_task_args",
                        staticmethod(lambda *a, **k: {"folder_uid": EMPTY, "force_deletion": raw}))
    sdk = make_sdk(tree, deleted_uids=[EMPTY])
    run_plugin(sdk, {"folder_uid": EMPTY})
    assert sdk.client.delete_folder.call_args.kwargs["force_deletion"] is False


# --- Server status: the server does not raise when it refuses a delete ---

OK = {"folderUid": EMPTY, "responseCode": "ok"}
DENIED_MSG = "User does not have permission to delete this folder"
DENIED = {"folderUid": EMPTY, "responseCode": "access_denied", "errorMessage": DENIED_MSG}
OTHER_OK = {"folderUid": WEB, "responseCode": "ok"}
OTHER_DENIED = {"folderUid": WEB, "responseCode": "access_denied", "errorMessage": "No"}
REFUSED = "The Keeper server did not delete the folder " + EMPTY_LABEL + ". It returned {}."
UNCONFIRMED = ("The Keeper server did not confirm the delete of the folder " + EMPTY_LABEL +
               ", and the folder still exists.")

# (id, response, folder is gone afterwards, failure message or None, get_folders calls)
STATUS_CASES = [
    ("ok", [OK], True, None, 1),
    ("ok_in_a_dict", {"folders": [OK]}, True, None, 1),
    ("junk_before_the_status", ["junk", None, OK], True, None, 1),
    ("ok_for_this_folder_after_a_denial_of_another", [OTHER_DENIED, OK], True, None, 1),
    ("access_denied", [DENIED], False, REFUSED.format("access_denied: " + DENIED_MSG), 1),
    ("access_denied_in_a_dict", {"folders": [DENIED]}, True, REFUSED.format("access_denied: " + DENIED_MSG), 1),
    ("denial_after_an_ok_of_another", [OTHER_OK, DENIED], False, REFUSED.format("access_denied: " + DENIED_MSG), 1),
    ("denial_after_junk", ["junk", DENIED], False, REFUSED.format("access_denied: " + DENIED_MSG), 1),
    ("code_without_message", [{"folderUid": EMPTY, "responseCode": "folder_not_empty"}], False,
     REFUSED.format("folder_not_empty"), 1),
    ("blank_message", [{"folderUid": EMPTY, "responseCode": "folder_not_empty", "errorMessage": ""}], False,
     REFUSED.format("folder_not_empty"), 1),
    ("none_message", [{"folderUid": EMPTY, "responseCode": "folder_not_empty", "errorMessage": None}], False,
     REFUSED.format("folder_not_empty"), 1),
    ("missing_code", [{"folderUid": EMPTY}], True, REFUSED.format("no response code"), 1),
    ("none_code", [{"folderUid": EMPTY, "responseCode": None}], True, REFUSED.format("no response code"), 1),
    ("empty_code", [{"folderUid": EMPTY, "responseCode": ""}], True, REFUSED.format("no response code"), 1),
    ("missing_code_keeps_the_message", [{"folderUid": EMPTY, "errorMessage": "Something went wrong"}], True,
     REFUSED.format("no response code: Something went wrong"), 1),
    ("near_miss_OK", [{"folderUid": EMPTY, "responseCode": "OK"}], True, REFUSED.format("OK"), 1),
    ("near_miss_padded_ok", [{"folderUid": EMPTY, "responseCode": "ok "}], True, REFUSED.format("ok "), 1),
    ("near_miss_true", [{"folderUid": EMPTY, "responseCode": True}], True, REFUSED.format("True"), 1),
    ("ok_without_folder_uid_while_the_folder_exists", [{"responseCode": "ok"}], False, UNCONFIRMED, 2),
    ("status_for_another_folder_only_and_folder_exists", [OTHER_OK], False, UNCONFIRMED, 2),
    ("status_for_another_folder_only_and_folder_gone", [OTHER_OK], True, None, 2),
]
# Responses with no status for the folder: SDK 17.3.0 returns {} or None, later SDKs return a list.
NO_STATUS = [[], {}, None, "garbage", 42, b"bytes", {"folders": None}, {"folders": []}, {"something": "else"},
             [None, "EMPTY_UID", 5, ["folderUid", "EMPTY_UID"]], ({"folderUid": "EMPTY_UID", "responseCode": "ok"},)]
STATUS_CASES += [("no_status_{}_folder_gone".format(i), r, True, None, 2) for i, r in enumerate(NO_STATUS)]
STATUS_CASES += [("no_status_{}_folder_exists".format(i), r, False, UNCONFIRMED, 2) for i, r in enumerate(NO_STATUS)]


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("case", STATUS_CASES, ids=[c[0] for c in STATUS_CASES])
def test_delete_status_decides_the_result(make_sdk, run_plugin, tree, case, force):
    _, response, gone, message, reads = case
    uid = EMPTY
    sdk = make_sdk(tree, delete_response=response, deleted_uids=[uid] if gone else [])
    result = run_plugin(sdk, {"folder_uid": uid, "force_deletion": force})

    if message is None:
        assert result == changed(EMPTY, "Staging")
    else:
        assert_failure(result, delete_failure(message))
    assert sdk.client.get_folders.call_count == reads


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("response", [[], None, [OTHER_OK]])
def test_failed_folder_check_after_a_delete_does_not_report_success(make_sdk, run_plugin, tree, response, force):
    sdk = make_sdk(tree, delete_response=response)
    sdk.client.get_folders.side_effect = [tree, Exception("connection reset")]
    result = run_plugin(sdk, {"folder_uid": EMPTY, "force_deletion": force})

    assert_failure(result, delete_failure(
        "The Keeper server sent no result for the delete of the folder " + EMPTY_LABEL + ", and the check of the "
        "folder list after it failed, so the folder can still exist. Cannot get folders: connection reset"))
    sdk.client.delete_folder.assert_called_once_with([EMPTY], force_deletion=force)


def test_fallback_compares_the_exact_folder_uid(make_sdk, run_plugin, tree, folder):
    sdk = make_sdk(tree + [folder("EMPTY_UID_2", SHARED, "Staging")], delete_response=[], deleted_uids=[EMPTY])
    assert run_plugin(sdk, {"folder_uid": EMPTY})["changed"] is True


# --- SDK errors name the step that failed ---

def test_get_folders_error(make_sdk, run_plugin, tree):
    sdk = make_sdk(tree)
    sdk.client.get_folders.side_effect = Exception("network is down")
    assert_failure(run_plugin(sdk, {"folder_uid": EMPTY}), delete_failure("Cannot get folders: network is down"))
    sdk.client.get_secrets.assert_not_called()
    sdk.client.delete_folder.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_get_secrets_error(make_sdk, run_plugin, tree, check_mode):
    sdk = make_sdk(tree)
    sdk.client.get_secrets.side_effect = Exception("records unavailable")
    assert_failure(run_plugin(sdk, {"folder_uid": EMPTY}, check_mode=check_mode), delete_failure(
        "Cannot get records to check if the folder " + EMPTY_LABEL + " is empty: records unavailable"))
    sdk.client.delete_folder.assert_not_called()


@pytest.mark.parametrize("uid, label, force", [(EMPTY, EMPTY_LABEL, False), (DB, DB_LABEL, True)])
def test_delete_error(make_sdk, run_plugin, tree, uid, label, force):
    sdk = make_sdk(tree)
    sdk.client.delete_folder.side_effect = Exception("access denied by policy")
    assert_failure(run_plugin(sdk, {"folder_uid": uid, "force_deletion": force}),
                   delete_failure("Cannot delete the folder {}: access denied by policy".format(label)))


@pytest.mark.parametrize("error", [KeeperFolderError("The folder_uid is blank."), RuntimeError("unexpected"),
                                   AttributeError("'NoneType' object has no attribute 'folder_uid'")])
def test_any_exception_from_the_method_is_returned_not_raised(make_sdk, run_plugin, tree, monkeypatch, error):
    def raise_error(*args, **kwargs):
        raise error
    monkeypatch.setattr(KeeperAnsible, "delete_folder", raise_error)
    assert_failure(run_plugin(make_sdk(tree), {"folder_uid": EMPTY}), delete_failure(str(error)))


def test_config_error_from_keeper_ansible_is_raised(make_sdk, run_plugin, tree):
    sdk = make_sdk(tree, init_error=ValueError("Keeper Ansible error: no config"))
    with pytest.raises(ValueError):
        run_plugin(sdk, {"folder_uid": EMPTY})


# --- folder_uid ---

@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("value", ["", " ", "\t", "\n", " \r\n "])
def test_blank_uid_fails(make_sdk, run_plugin, tree, value, force):
    sdk = make_sdk(tree)
    assert_failure(run_plugin(sdk, {"folder_uid": value, "force_deletion": force}),
                   delete_failure("The folder_uid is blank."))
    sdk.client.get_folders.assert_not_called()


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("value", [" " + EMPTY, EMPTY + " ", EMPTY + "\n", "\t" + EMPTY, EMPTY + "\r\n",
                                   " MISSING_UID", "MISSING_UID\n"])
def test_padded_uid_fails_instead_of_reporting_not_found(make_sdk, run_plugin, tree, value, force):
    sdk = make_sdk(tree)
    assert_failure(run_plugin(sdk, {"folder_uid": value, "force_deletion": force}, check_mode=force), delete_failure(
        "The folder_uid {!r} has leading or trailing whitespace.".format(value)))
    sdk.client.get_secrets.assert_not_called()
    sdk.client.delete_folder.assert_not_called()


@pytest.mark.parametrize("uid", ["0012", "12345", "1_000"])
def test_all_digit_uid_reaches_the_sdk_as_a_string(make_sdk, run_plugin, tree, folder, uid):
    # int("0012") is 12, a different folder.
    sdk = make_sdk(tree + [folder(uid, SHARED, "Numbered")], deleted_uids=[uid])
    assert run_plugin(sdk, {"folder_uid": uid}) == changed(uid, "Numbered")
    sdk.client.delete_folder.assert_called_once_with([uid], force_deletion=False)


# --- Options: only that delete_folder's spec is wired. tests/keeper_folder_args_test.py owns the generic checks. ---

# (id, task args, message)
OPTION_CASES = [
    ("missing_folder_uid", {"force_deletion": True}, "missing required arguments: folder_uid"),
    ("null_folder_uid", {"folder_uid": None}, NULL_MESSAGE.format("folder_uid")),
    ("null_force_deletion", {"folder_uid": EMPTY, "force_deletion": None}, NULL_MESSAGE.format("force_deletion")),
    ("list_folder_uid", {"folder_uid": [EMPTY]}, NOT_A_STRING.format("a list")),
    ("number_folder_uid", {"folder_uid": 10}, NOT_A_STRING.format("a number (10)")),
]


@pytest.mark.parametrize("case", OPTION_CASES, ids=[c[0] for c in OPTION_CASES])
def test_bad_options_fail_before_the_sdk_is_used(make_sdk, run_plugin, tree, case):
    _, task_args, message = case
    sdk = make_sdk(tree)
    assert_failure(run_plugin(sdk, task_args), message)
    assert sdk.inits == 0
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("option", ["force", "force_delete", "folder_name"])
def test_unsupported_option_fails_and_deletes_nothing(make_sdk, run_plugin, tree, option):
    # force is the old name of force_deletion. If it were ignored, the task would run without force.
    sdk = make_sdk(tree)
    assert_unsupported(run_plugin(sdk, {"folder_uid": DB, option: True}), option)
    assert sdk.inits == 0
    assert sdk.client.mock_calls == []


def test_force_deletion_that_is_not_a_boolean_fails(make_sdk, run_plugin, tree):
    sdk = make_sdk(tree)
    result = run_plugin(sdk, {"folder_uid": EMPTY, "force_deletion": "maybe"})
    assert result["failed"] is True and result["changed"] is False
    assert result["msg"].startswith("argument 'force_deletion' is of type ")
    assert "unable to convert to bool" in result["msg"]
    assert sdk.inits == 0


# --- module_defaults for the action group of this collection ---

@pytest.mark.parametrize("uid, task_args, defaults, forced", [
    pytest.param(EMPTY, {"folder_uid": EMPTY, "force": True}, {"force": True}, False, id="group_force_is_ignored"),
    pytest.param(DB, {"folder_uid": DB, "force_deletion": True}, {"force_deletion": True}, True,
                 id="group_force_deletion_applies"),
])
def test_group_defaults(make_sdk, run_plugin, tree, record, uid, task_args, defaults, forced):
    sdk = make_sdk(tree, records=[record("R1", SHARED, DB)], deleted_uids=[uid, PROD, "ARCHIVE_UID"])
    result = run_plugin(sdk, task_args, module_defaults=[{GROUP: defaults}])
    assert result["changed"] is True
    assert sdk.client.delete_folder.call_args.kwargs["force_deletion"] is forced


def test_group_force_does_not_delete_a_folder_that_is_not_empty(make_sdk, run_plugin, tree):
    sdk = make_sdk(tree)
    result = run_plugin(sdk, {"folder_uid": DB, "force": True}, module_defaults=[{GROUP: {"force": True}}])
    assert_failure(result, delete_failure(NOT_EMPTY.format(DB_LABEL, 0, 1)))
    sdk.client.delete_folder.assert_not_called()


@pytest.mark.parametrize("task_args, defaults, options", [
    pytest.param({"folder_uid": DB, "force": True}, {"group/community.general.example": {"force": True}}, ["force"],
                 id="group_of_another_collection"),
    pytest.param({"folder_uid": EMPTY, "shared_folder_uid": "S", "force_delete": True},
                 {GROUP: {"shared_folder_uid": "S"}}, ["force_delete"], id="typo_next_to_a_group_default"),
])
def test_unsupported_option_still_fails_with_group_defaults(make_sdk, run_plugin, tree, task_args, defaults, options):
    sdk = make_sdk(tree)
    assert_unsupported(run_plugin(sdk, task_args, module_defaults=[defaults]), *options)
    assert sdk.inits == 0


# --- Folder names in messages are JSON-quoted, so a stray character stays visible ---

QUOTED_CASES = [
    ("quote_in_not_empty", "QUOTE_UID", [], [],
     r'The folder "Infrastructure/Data\"bases" (UID QUOTE_UID) is not empty. It contains 0 record(s) and 1 '
     r'subfolder(s). Set force_deletion to true to delete the folder and everything in it.'),
    ("quote_in_shared_folder_name", "UNDER_QUOTED_UID", [("R1", "QUOTED_SHARED_UID", "UNDER_QUOTED_UID")], [],
     r'The folder "Infra\"structure/Staging" (UID UNDER_QUOTED_UID) is not empty. It contains 1 record(s) and 0 '
     r'subfolder(s). Set force_deletion to true to delete the folder and everything in it.'),
    ("newline_in_refused", "NEWLINE_UID", [], [{"folderUid": "NEWLINE_UID", "responseCode": "access_denied",
                                                "errorMessage": "No"}],
     r'The Keeper server did not delete the folder "Infrastructure/Staging\n" (UID NEWLINE_UID). It returned '
     r'access_denied: No.'),
    ("tab_and_backslash_in_unconfirmed", "TAB_UID", [], [],
     r'The Keeper server did not confirm the delete of the folder "Infrastructure/Tab\tBack\\slash" (UID TAB_UID), '
     r'and the folder still exists.'),
    ("non_ascii_is_not_escaped", "ACCENT_UID", [], [{"folderUid": "ACCENT_UID", "responseCode": "access_denied",
                                                     "errorMessage": "No"}],
     'The Keeper server did not delete the folder "Infrastructure/Données" (UID ACCENT_UID). It returned '
     'access_denied: No.'),
]


@pytest.mark.parametrize("case", QUOTED_CASES, ids=[c[0] for c in QUOTED_CASES])
def test_folder_names_are_escaped_in_messages(make_sdk, run_plugin, folder, record, case):
    _, uid, specs, response, message = case
    folders = [
        folder(SHARED, "", "Infrastructure"),
        folder("QUOTE_UID", SHARED, 'Data"bases'),
        folder("QUOTE_CHILD_UID", "QUOTE_UID", "Child"),
        folder("NEWLINE_UID", SHARED, "Staging\n"),
        folder("TAB_UID", SHARED, "Tab\tBack\\slash"),
        folder("ACCENT_UID", SHARED, "Données"),
        folder("QUOTED_SHARED_UID", "", 'Infra"structure'),
        folder("UNDER_QUOTED_UID", "QUOTED_SHARED_UID", "Staging"),
    ]
    sdk = make_sdk(folders, records=records_of(record, specs), delete_response=response or [])
    assert_failure(run_plugin(sdk, {"folder_uid": uid}), delete_failure(message))


# --- Documentation ---

def test_docs_stub_matches_the_action_plugin_docs(plugin_module):
    stub = importlib.import_module("keeper_secrets_manager_ansible.plugins.modules.keeper_delete_folder")
    for name in ["DOCUMENTATION", "EXAMPLES", "RETURN"]:
        assert getattr(stub, name) == getattr(plugin_module, name), name


def test_documented_options_match_the_argument_spec(plugin_module):
    import yaml
    options = yaml.safe_load(plugin_module.DOCUMENTATION)["options"]
    spec = plugin_module.ActionModule.ARGUMENT_SPEC
    assert set(options) == set(spec) == SUPPORTED
    for name, doc in options.items():
        assert doc["type"] == spec[name]["type"], name
        assert bool(doc.get("required", False)) == spec[name].get("required", False), name
    assert options["force_deletion"]["default"] is spec["force_deletion"]["default"] is False


def test_return_documents_the_not_found_message(make_sdk, run_plugin, plugin_module, tree):
    import yaml
    returned = yaml.safe_load(plugin_module.RETURN)
    assert set(returned) == {"folder_uid", "folder_name", "msg"}
    assert returned["msg"]["returned"] == "when the folder was not found"
    assert returned["msg"]["sample"] == run_plugin(make_sdk(tree), {"folder_uid": "XXXX"})["msg"]
