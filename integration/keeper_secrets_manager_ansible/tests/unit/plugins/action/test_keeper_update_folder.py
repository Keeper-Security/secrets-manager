import importlib
import threading
from unittest.mock import patch

import pytest
import yaml

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFolderError

from .conftest import GROUP

PLUGIN = "keeper_update_folder"

EMPTY, DB, PROD, WEB, OPS, SHARED, ARCHIVE = ("EMPTY_UID", "DB_UID", "PROD_UID", "WEB_UID", "OPS_UID", "SHARED_UID",
                                              "ARCHIVE_UID")
LABELS = {
    EMPTY: '"Infrastructure/Staging" (UID EMPTY_UID)',
    DB: '"Infrastructure/Databases" (UID DB_UID)',
    OPS: '"Operations" (UID OPS_UID)',
    SHARED: '"Infrastructure" (UID SHARED_UID)',
    ARCHIVE: '"Infrastructure/Databases/Production/Archive" (UID ARCHIVE_UID)',
    "TOP_UID": '"Top" (UID TOP_UID)',
}
SUPPORTED = {"folder_uid", "new_folder_name"}
NOT_FOUND = "The folder {} was not found, or it is not shared to this KSM application."
NULL_MESSAGE = "The {} option is null. Give it a value, or leave the option out of the task."
NOT_A_STRING = ("The {} option must be a string, but it is {}. Put quotes around the value, or use the string "
                "filter.")
PADDED_NAME = ("The new_folder_name {} has leading or trailing whitespace. Remove it. In YAML, a block scalar (| or >) "
               "keeps the newline at its end.")


def assert_failure(result, msg):
    # The plugin returns a failure, so failed_when, rescue, and ignore_errors work on it. "is" because
    # {"failed": 1} == {"failed": True}.
    assert sorted(result) == ["changed", "failed", "msg"]
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["msg"] == msg


def update_failure(msg):
    return "Could not update folder: " + msg


def assert_unsupported(result, before):
    # The supported names are compared as a set: ansible-core before 2.15 did not always sort them.
    assert result["failed"] is True and result["changed"] is False
    head, marker, after = result["msg"].partition("Supported parameters include: ")
    assert head == before
    assert marker and after.endswith(".")
    assert set(after[:-1].split(", ")) == SUPPORTED


def renamed(uid, new_name, old_name, changed=True):
    return {"changed": changed, "folder_uid": uid, "folder_name": new_name, "previous_folder_name": old_name}


def same_name_warning(label, quoted_name, sibling_uids):
    return ("The parent of the folder {} already has a folder named {} ({}). After the rename, a lookup of this name "
            "fails because the name is not unique.".format(label, quoted_name, sibling_uids))


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
    assert not thread.is_alive(), "the call did not end; the parent-chain walk loops"
    return outcome


@pytest.fixture
def warning():
    with patch("keeper_secrets_manager_ansible.display.warning") as mock:
        yield mock


@pytest.fixture
def sdk_for(make_sdk, tree, folder):
    """sdk_for(extra=[(uid, parent_uid, name)]): the shared tree plus extra folders, with an autospec client."""
    return lambda extra=(): make_sdk(tree + [folder(*spec) for spec in extra], autospec=True)


def assert_sent(sdk, uid, new_name):
    # One read, and the update gets the list from that read, so the SDK does not fetch the folders again.
    sdk.client.get_folders.assert_called_once_with()
    sdk.client.update_folder.assert_called_once_with(uid, new_name, folders=sdk.client.get_folders.side_effect())


def assert_not_sent(sdk):
    sdk.client.get_folders.assert_called_once_with()
    sdk.client.update_folder.assert_not_called()


# --- Rename, no-op, and the result shape ---

@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("uid, new_name, old_name", [
    (EMPTY, "QA", "Staging"),
    (SHARED, "Infra", "Infrastructure"),
    (ARCHIVE, "Old", "Archive"),
], ids=["subfolder", "shared_folder", "deep_subfolder"])
def test_rename(sdk_for, run_plugin, uid, new_name, old_name, check_mode):
    sdk = sdk_for()
    result = run_plugin(sdk, {"folder_uid": uid, "new_folder_name": new_name}, check_mode=check_mode)

    assert result == renamed(uid, new_name, old_name)
    assert result["changed"] is True
    assert len(sdk.action_modules) == 1 and sdk.action_modules[0] is not None
    if check_mode:
        assert_not_sent(sdk)
    else:
        assert_sent(sdk, uid, new_name)
    sdk.client.get_secrets.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_same_name_is_a_no_op(sdk_for, run_plugin, check_mode):
    sdk = sdk_for()
    with patch("keeper_secrets_manager_ansible.display.vvv") as vvv:
        result = run_plugin(sdk, {"folder_uid": EMPTY, "new_folder_name": "Staging"}, check_mode=check_mode)

    assert result == renamed(EMPTY, "Staging", "Staging", changed=False)
    assert result["changed"] is False
    assert_not_sent(sdk)
    vvv.assert_called_once_with('Folder EMPTY_UID is already named "Staging". Nothing to rename.')


def test_no_op_debug_message_quotes_the_name(sdk_for):
    sdk = sdk_for([("NL_UID", SHARED, "Prod\nEU")])
    with patch("keeper_secrets_manager_ansible.display.vvv") as vvv:
        assert sdk.keeper().update_folder("NL_UID", "Prod\nEU")["changed"] is False
    vvv.assert_called_once_with('Folder NL_UID is already named "Prod\\nEU". Nothing to rename.')


def test_no_op_does_not_warn_about_a_sibling_with_the_same_name(sdk_for, warning):
    sdk = sdk_for([("DUP_UID", SHARED, "Staging")])
    assert sdk.keeper().update_folder(EMPTY, "Staging")["changed"] is False
    warning.assert_not_called()
    assert_not_sent(sdk)


# (id, current name, new name): the names are compared exactly. The value stays as written.
COMPARISON_CASES = [
    ("case_change", "Staging", "staging"),
    ("inner_whitespace", "Staging", "Sta ging"),
    ("padded_current_name", "Reports ", "Reports"),
    ("unicode_normalization_forms", "Café", "Café"),
    ("digits_of_a_longer_name", "2025", "20250"),
]


@pytest.mark.parametrize("case", COMPARISON_CASES, ids=[c[0] for c in COMPARISON_CASES])
def test_names_are_compared_exactly(sdk_for, case):
    _, old_name, new_name = case
    sdk = sdk_for([("N_UID", SHARED, old_name)])
    assert sdk.keeper().update_folder("N_UID", new_name) == renamed("N_UID", new_name, old_name)
    assert_sent(sdk, "N_UID", new_name)


def test_int_name_reaches_the_sdk_as_a_string(sdk_for):
    # The option check lets only strings through. Called directly, the method must still not send a JSON number.
    sdk = sdk_for([("YEAR_UID", SHARED, "2025")])
    assert sdk.keeper().update_folder("YEAR_UID", 2026) == renamed("YEAR_UID", "2026", "2025")
    assert_sent(sdk, "YEAR_UID", "2026")
    assert sdk.client.update_folder.call_args.args[1] == "2026"

    sdk = sdk_for([("YEAR_UID", SHARED, "2025")])
    assert sdk.keeper().update_folder("YEAR_UID", 2025)["changed"] is False
    assert_not_sent(sdk)


@pytest.mark.parametrize("uid", ["0012", "12345"])
def test_all_digit_uid_stays_a_string(sdk_for, run_plugin, uid):
    # int("0012") is 12, a different folder.
    sdk = sdk_for([(uid, SHARED, "Numbered")])
    assert run_plugin(sdk, {"folder_uid": uid, "new_folder_name": "Renamed"}) == renamed(uid, "Renamed", "Numbered")
    assert_sent(sdk, uid, "Renamed")


# --- Name and UID validation: all of it fails before the folders are read ---

@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("name", ["", " ", "\t", "\n", " \t\r\n "])
def test_blank_name_fails_before_any_sdk_call(sdk_for, run_plugin, name, check_mode):
    sdk = sdk_for()
    result = run_plugin(sdk, {"folder_uid": EMPTY, "new_folder_name": name}, check_mode=check_mode)
    assert_failure(result, update_failure("The new_folder_name is blank."))
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("name", [" Production", "Production ", "  Production  ", "\tProduction", "Production\t",
                                  "Production\n", "\nProduction", "Production\r", "Production\r\n",
                                  "Production ", "Bob's folder "])
def test_padded_name_fails_before_any_sdk_call(sdk_for, run_plugin, name):
    sdk = sdk_for()
    assert_failure(run_plugin(sdk, {"folder_uid": EMPTY, "new_folder_name": name}),
                   update_failure(PADDED_NAME.format(repr(name))))
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("uid, check_mode", [("MISSING_UID", False), (EMPTY, True)],
                         ids=["unknown_folder", "check_mode"])
def test_padded_name_check_comes_before_the_lookup_and_check_mode(sdk_for, run_plugin, uid, check_mode):
    sdk = sdk_for()
    result = run_plugin(sdk, {"folder_uid": uid, "new_folder_name": "Production "}, check_mode=check_mode)
    assert_failure(result, update_failure(PADDED_NAME.format("'Production '")))
    assert sdk.client.mock_calls == []


def test_padded_name_fails_even_if_the_folder_already_has_it(sdk_for, run_plugin):
    sdk = sdk_for([("A_UID", SHARED, "A ")])
    assert_failure(run_plugin(sdk, {"folder_uid": "A_UID", "new_folder_name": "A "}),
                   update_failure(PADDED_NAME.format("'A '")))
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("uid, message", [
    ("", "The folder_uid is blank."),
    (" \t\n", "The folder_uid is blank."),
    (EMPTY + " ", "The folder_uid 'EMPTY_UID ' has leading or trailing whitespace."),
    ("\tEMPTY_UID", "The folder_uid '\\tEMPTY_UID' has leading or trailing whitespace."),
    (EMPTY + "\r\n", "The folder_uid 'EMPTY_UID\\r\\n' has leading or trailing whitespace."),
    (" MISSING_UID", "The folder_uid ' MISSING_UID' has leading or trailing whitespace."),
])
def test_blank_or_padded_uid_fails_before_any_sdk_call(sdk_for, run_plugin, uid, message):
    sdk = sdk_for()
    assert_failure(run_plugin(sdk, {"folder_uid": uid, "new_folder_name": "QA"}), update_failure(message))
    assert sdk.client.mock_calls == []


def test_uid_is_checked_before_the_name(sdk_for, run_plugin):
    sdk = sdk_for()
    assert_failure(run_plugin(sdk, {"folder_uid": " ", "new_folder_name": " "}),
                   update_failure("The folder_uid is blank."))


def test_first_entry_of_a_uid_is_used_and_a_uid_must_match_in_full(sdk_for, folder, warning):
    # Folder data that the server should not send: the UID twice, and a UID that starts like another one.
    sdk = sdk_for([(EMPTY, SHARED, "QA")])
    assert sdk.keeper().update_folder(EMPTY, "QA") == renamed(EMPTY, "QA", "Staging")
    warning.assert_not_called()
    assert_sent(sdk, EMPTY, "QA")

    sdk = sdk_for([("EM", SHARED, "Short")])
    assert sdk.keeper().update_folder("EM", "S2") == renamed("EM", "S2", "Short")


# --- Folder not found ---

@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("uid", ["MISSING_UID", EMPTY.lower(), "Staging"], ids=["missing", "case_differs", "a_name"])
def test_unknown_folder_fails_and_nothing_is_sent(sdk_for, run_plugin, uid, check_mode):
    sdk = sdk_for()
    # The SDK has its own, less clear error for this. The module must find the problem first.
    sdk.client.update_folder.side_effect = Exception("Unable to update folder - folder key not found")
    result = run_plugin(sdk, {"folder_uid": uid, "new_folder_name": "QA"}, check_mode=check_mode)
    assert_failure(result, update_failure(NOT_FOUND.format(uid)))
    assert_not_sent(sdk)


@pytest.mark.parametrize("folders", [[], None], ids=["no_folders", "none"])
def test_no_folders_means_not_found(make_sdk, run_plugin, folders):
    sdk = make_sdk([], autospec=True)
    sdk.client.get_folders.side_effect = None
    sdk.client.get_folders.return_value = folders
    assert_failure(run_plugin(sdk, {"folder_uid": EMPTY, "new_folder_name": "QA"}),
                   update_failure(NOT_FOUND.format(EMPTY)))
    sdk.client.update_folder.assert_not_called()


# --- Sibling with the new name: Keeper allows it, so the rename happens and the module warns ---

# (id, folder, new name, extra folders, the sibling UIDs in the warning or None). Extra folders: (uid, parent, name).
WARNING_CASES = [
    ("sibling", EMPTY, "Web", [], WEB),
    ("two_siblings", EMPTY, "Web", [("WEB2_UID", SHARED, "Web")], "WEB_UID, WEB2_UID"),
    ("name_in_another_parent", EMPTY, "Production", [], None),
    ("name_of_an_own_subfolder", DB, "Production", [], None),
    ("sibling_differs_in_case", EMPTY, "web", [], None),
    ("sibling_differs_in_whitespace", EMPTY, "Web", [("PAD_UID", SHARED, "Web ")], WEB),
    ("shared_folder_name_of_a_subfolder", OPS, "Staging", [], None),
    ("shared_folders", OPS, "Infrastructure", [], SHARED),
    ("top_level_with_no_parent_uid", OPS, "Top", [("TOP_UID", None, "Top")], "TOP_UID"),
    ("top_level_from_no_parent_uid", "TOP_UID", "Operations", [("TOP_UID", None, "Top")], OPS),
    ("deep_sibling", ARCHIVE, "Old", [("OLD_UID", PROD, "Old")], "OLD_UID"),
    ("no_sibling", EMPTY, "QA", [], None),
]


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("case", WARNING_CASES, ids=[c[0] for c in WARNING_CASES])
def test_sibling_with_the_new_name_warns_and_still_renames(sdk_for, run_plugin, warning, case, check_mode):
    _, uid, new_name, extra, siblings = case
    sdk = sdk_for(extra)
    result = run_plugin(sdk, {"folder_uid": uid, "new_folder_name": new_name}, check_mode=check_mode)

    assert result["changed"] is True
    assert result["folder_name"] == new_name
    if siblings is None:
        warning.assert_not_called()
    else:
        warning.assert_called_once_with(same_name_warning(LABELS[uid], '"{}"'.format(new_name), siblings))
    if check_mode:
        assert_not_sent(sdk)
    else:
        assert_sent(sdk, uid, new_name)


# Folder names in messages are JSON-quoted, so a stray character stays visible. Non-ASCII stays as it is.
@pytest.mark.parametrize("name, quoted", [
    ('Prod "EU"', '"Prod \\"EU\\""'),
    ("Prod\nEU", '"Prod\\nEU"'),
    ("Prod\rEU", '"Prod\\rEU"'),
    ("A\tB\\C", '"A\\tB\\\\C"'),
    ("Café 数据 \U0001F512", '"Café 数据 \U0001F512"'),
], ids=["double_quote", "newline", "carriage_return", "tab_and_backslash", "non_ascii"])
def test_new_name_is_quoted_in_the_warning(sdk_for, warning, name, quoted):
    sdk_for([("SIB_UID", SHARED, name)]).keeper().update_folder(EMPTY, name)
    warning.assert_called_once_with(same_name_warning(LABELS[EMPTY], quoted, "SIB_UID"))


def test_folder_path_is_quoted_in_the_warning_and_the_error(make_sdk, folder, warning):
    folders = [folder(SHARED, "", 'Infra "Main"'), folder(DB, SHARED, "Data\nbases"), folder(EMPTY, DB, "Staging"),
               folder(PROD, DB, "Production")]
    sdk = make_sdk(folders, autospec=True)
    sdk.keeper().update_folder(EMPTY, "Production")
    warning.assert_called_once_with(same_name_warning('"Infra \\"Main\\"/Data\\nbases/Staging" (UID EMPTY_UID)',
                                                      '"Production"', PROD))

    sdk.client.update_folder.side_effect = Exception("denied")
    with pytest.raises(KeeperFolderError) as caught:
        sdk.keeper().update_folder(EMPTY, "Other")
    assert str(caught.value) == (
        'Cannot rename the folder "Infra \\"Main\\"/Data\\nbases/Staging" (UID EMPTY_UID): denied')


# --- SDK errors name the step that failed ---

def test_get_folders_error(sdk_for, run_plugin):
    sdk = sdk_for()
    sdk.client.get_folders.side_effect = Exception("network is down")
    assert_failure(run_plugin(sdk, {"folder_uid": EMPTY, "new_folder_name": "QA"}),
                   update_failure("Cannot get folders: network is down"))
    sdk.client.update_folder.assert_not_called()


@pytest.mark.parametrize("uid, error", [(EMPTY, Exception("access_denied")), (SHARED, Exception("access_denied")),
                                        (ARCHIVE, Exception("Error: 500"))])
def test_update_error_names_the_folder_and_is_not_retried(sdk_for, run_plugin, uid, error):
    sdk = sdk_for()
    sdk.client.update_folder.side_effect = error
    assert_failure(run_plugin(sdk, {"folder_uid": uid, "new_folder_name": "QA"}),
                   update_failure("Cannot rename the folder {}: {}".format(LABELS[uid], error)))
    sdk.client.update_folder.assert_called_once()


def test_update_error_label_quotes_the_folder_path(sdk_for):
    sdk = sdk_for([("Q_UID", DB, 'A "B"\n')])
    sdk.client.update_folder.side_effect = Exception("denied")
    with pytest.raises(KeeperFolderError) as caught:
        sdk.keeper().update_folder("Q_UID", "C")
    assert str(caught.value) == 'Cannot rename the folder "Infrastructure/Databases/A \\"B\\"\\n" (UID Q_UID): denied'


@pytest.mark.parametrize("error", [KeeperFolderError("The folder_uid is blank."), RuntimeError("unexpected"),
                                   AttributeError("'NoneType' object has no attribute 'folder_uid'")])
def test_any_exception_from_the_method_is_returned_not_raised(sdk_for, run_plugin, monkeypatch, error):
    def raise_error(*args, **kwargs):
        raise error
    monkeypatch.setattr(KeeperAnsible, "update_folder", raise_error)
    assert_failure(run_plugin(sdk_for(), {"folder_uid": EMPTY, "new_folder_name": "QA"}), update_failure(str(error)))


def test_config_error_from_keeper_ansible_is_raised(make_sdk, run_plugin, tree):
    sdk = make_sdk(tree, init_error=ValueError("Keeper Ansible error: no config"))
    with pytest.raises(ValueError):
        run_plugin(sdk, {"folder_uid": EMPTY, "new_folder_name": "QA"})


# --- Malformed folder data must not hang or crash the module ---

def test_folder_with_a_missing_parent_can_be_renamed(make_sdk, folder):
    sdk = make_sdk([folder(SHARED, "", "Infrastructure"), folder("ORPHAN_UID", "GONE_UID", "Orphan")], autospec=True)
    outcome = bounded(lambda: sdk.keeper().update_folder("ORPHAN_UID", "Adopted"))
    assert outcome.get("result") == renamed("ORPHAN_UID", "Adopted", "Orphan")

    sdk.client.update_folder.side_effect = Exception("denied")
    outcome = bounded(lambda: sdk.keeper().update_folder("ORPHAN_UID", "Other"))
    assert str(outcome["error"]) == 'Cannot rename the folder "Orphan" (UID ORPHAN_UID): denied'


def test_parent_cycle_does_not_hang_the_error_or_the_warning(make_sdk, folder, warning):
    folders = [folder("A_UID", "B_UID", "A"), folder("B_UID", "A_UID", "B"), folder("C_UID", "B_UID", "C")]
    sdk = make_sdk(folders, autospec=True)
    outcome = bounded(lambda: sdk.keeper().update_folder("A_UID", "C"))
    assert outcome["result"]["changed"] is True
    warning.assert_called_once()
    assert "C_UID" in warning.call_args[0][0]

    sdk.client.update_folder.side_effect = Exception("denied")
    outcome = bounded(lambda: sdk.keeper().update_folder("A_UID", "D"))
    assert isinstance(outcome["error"], KeeperFolderError)
    assert "(UID A_UID): denied" in str(outcome["error"])


# --- Options: only this module's spec is wired. tests/keeper_folder_args_test.py owns the generic checks. ---

# (id, task args, message)
OPTION_CASES = [
    ("missing_both", {}, "missing required arguments: folder_uid, new_folder_name"),
    ("missing_new_folder_name", {"folder_uid": EMPTY}, "missing required arguments: new_folder_name"),
    ("null_folder_uid", {"folder_uid": None, "new_folder_name": "QA"}, NULL_MESSAGE.format("folder_uid")),
    ("null_new_folder_name", {"folder_uid": EMPTY, "new_folder_name": None}, NULL_MESSAGE.format("new_folder_name")),
    ("list_new_folder_name", {"folder_uid": EMPTY, "new_folder_name": ["Prod", "EU"]},
     NOT_A_STRING.format("new_folder_name", "a list")),
    ("number_new_folder_name", {"folder_uid": EMPTY, "new_folder_name": 2026},
     NOT_A_STRING.format("new_folder_name", "a number (2026)")),
    ("boolean_folder_uid", {"folder_uid": True, "new_folder_name": "QA"},
     NOT_A_STRING.format("folder_uid", "a boolean (True)")),
]


@pytest.mark.parametrize("case", OPTION_CASES, ids=[c[0] for c in OPTION_CASES])
def test_bad_options_fail_before_the_sdk_is_used(make_sdk, run_plugin, tree, case):
    _, task_args, message = case
    sdk = make_sdk(tree)
    assert_failure(run_plugin(sdk, task_args), message)
    assert sdk.inits == 0
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("task_args, before", [
    ({"folder_uid": EMPTY, "new_name": "QA"},
     "missing required arguments: new_folder_name; Unsupported parameters for (keeper_update_folder) module: "
     "new_name. "),
    ({"folder_uid": EMPTY, "new_folder_name": "QA", "folder_name": "QA"},
     "Unsupported parameters for (keeper_update_folder) module: folder_name. "),
], ids=["misspelled_new_folder_name", "option_of_another_module"])
def test_unsupported_option_fails_and_renames_nothing(make_sdk, run_plugin, tree, task_args, before):
    sdk = make_sdk(tree)
    assert_unsupported(run_plugin(sdk, task_args), before)
    assert sdk.inits == 0
    assert sdk.client.mock_calls == []


# --- module_defaults for the action group of this collection ---

def test_group_defaults_of_other_modules_are_ignored_and_own_options_are_not_replaced(sdk_for, run_plugin):
    sdk = sdk_for()
    task_args = {"folder_uid": EMPTY, "new_folder_name": "QA", "shared_folder_uid": "S", "cache": "C"}
    defaults = [{GROUP: {"shared_folder_uid": "S", "cache": "C", "folder_uid": "DEFAULT_UID"}}]
    assert run_plugin(sdk, task_args, module_defaults=defaults) == renamed(EMPTY, "QA", "Staging")
    assert_sent(sdk, EMPTY, "QA")


@pytest.mark.parametrize("task_args, defaults, before", [
    pytest.param({"folder_uid": EMPTY, "new_name": "QA", "shared_folder_uid": "S"}, {GROUP: {"shared_folder_uid": "S"}},
                 "missing required arguments: new_folder_name; Unsupported parameters for (keeper_update_folder) "
                 "module: new_name. ", id="typo_next_to_a_group_default"),
    pytest.param({"folder_uid": EMPTY, "new_folder_name": "QA", "region": "r"},
                 {"group/amazon.aws.aws": {"region": "r"}},
                 "Unsupported parameters for (keeper_update_folder) module: region. ",
                 id="group_of_another_collection"),
    pytest.param({"folder_uid": EMPTY, "new_folder_name": "QA", "shared_folder_uid": "S"},
                 {"keepersecurity.keeper_secrets_manager.keeper_create_folder": {"shared_folder_uid": "S"}},
                 "Unsupported parameters for (keeper_update_folder) module: shared_folder_uid. ",
                 id="defaults_of_one_other_module"),
])
def test_unsupported_option_still_fails_with_defaults(make_sdk, run_plugin, tree, task_args, defaults, before):
    sdk = make_sdk(tree)
    assert_unsupported(run_plugin(sdk, task_args, module_defaults=[defaults]), before)
    assert sdk.inits == 0


def test_templated_group_defaults_are_resolved_with_the_plugin_templar(sdk_for, run_plugin):
    class Templar:
        calls = []

        def template(self, value):
            self.calls.append(value)
            return {"shared_folder_uid": "S", "cache": "C"}

    templar = Templar()
    task_args = {"folder_uid": EMPTY, "new_folder_name": "QA", "shared_folder_uid": "S", "cache": "C"}
    result = run_plugin(sdk_for(), task_args, module_defaults=[{GROUP: "{{ keeper_defaults }}"}], templar=templar)
    assert result["changed"] is True
    assert templar.calls == ["{{ keeper_defaults }}"]


def test_the_method_gets_the_validated_values_not_the_raw_task_args(sdk_for, run_plugin, monkeypatch):
    # A !vault value is not a str. The option check decrypts it, and the SDK must get a plain str.
    class Vaulted(object):
        def __init__(self, text):
            self.text = text

        def __str__(self):
            return self.text

    monkeypatch.setattr(KeeperAnsible, "_vault_string_types", staticmethod(lambda: (Vaulted,)))
    sdk = sdk_for()
    with patch.object(KeeperAnsible, "update_folder", autospec=True, side_effect=KeeperAnsible.update_folder) as method:
        result = run_plugin(sdk, {"folder_uid": Vaulted(EMPTY), "new_folder_name": Vaulted("QA")})
    assert result == renamed(EMPTY, "QA", "Staging")
    assert [type(arg) for arg in method.call_args.args[1:3]] == [str, str]


# --- Documentation ---

def test_docs_stub_matches_the_action_plugin_docs(plugin_module):
    stub = importlib.import_module("keeper_secrets_manager_ansible.plugins.modules.keeper_update_folder")
    for name in ["DOCUMENTATION", "EXAMPLES", "RETURN"]:
        assert getattr(stub, name) == getattr(plugin_module, name), name


def test_documented_options_match_the_argument_spec(plugin_module):
    options = yaml.safe_load(plugin_module.DOCUMENTATION)["options"]
    spec = plugin_module.ActionModule.ARGUMENT_SPEC
    assert set(options) == set(spec) == SUPPORTED
    for name, doc in options.items():
        assert doc["type"] == spec[name]["type"], name
        assert bool(doc.get("required", False)) == spec[name].get("required", False), name


def test_documented_return_values_match_the_result(sdk_for, run_plugin, plugin_module):
    documented = set(yaml.safe_load(plugin_module.RETURN))
    result = run_plugin(sdk_for(), {"folder_uid": EMPTY, "new_folder_name": "QA"})
    assert documented == set(result) - {"changed"}
