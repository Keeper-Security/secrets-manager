import importlib
import json
from unittest.mock import patch

import pytest
import yaml

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFolderError

from .conftest import GROUP, bounded

PLUGIN = "keeper_get_folder"

INFRA, APPS, TEAM_1, TEAM_2, NONE_PARENT = "SF_INFRA", "SF_APPS", "SF_TEAM_1", "SF_TEAM_2", "SF_NONE"
DB, PROD, EU, FRA, STG, WEB, WEB_DB, SLASH, YEAR, UNI = ("DB", "PROD", "EU", "FRA", "STG", "WEB", "WEB_DB", "SLASH",
                                                         "YEAR", "UNI")
DUP_1, DUP_2, DUP_3, LEAF, SVC = "DUP_1", "DUP_2", "DUP_3", "LEAF", "SVC"
# Padded is a name with a trailing space. DB_2 has a UID that starts like DB. 0012 is a UID of digits only.
PAD, DB_2, DB_2_CHILD, DIGITS = "PAD", "DB_2", "DB_2_CHILD", "0012"
UNICODE_NAME = "Données 数据库 🔐"
TOP = "at the top level (the shared folders of this KSM application)"
SUPPORTED = {"folder_name", "folder_path", "include_subfolders", "shared_folder_uid", "subfolder_uid"}
NOTHING = "There is nothing to look up. Set shared_folder_uid, subfolder_uid, folder_name, or folder_path."
NULL_MESSAGE = "The {} option is null. Give it a value, or leave the option out of the task."
NOT_A_STRING = ("The {} option must be a string, but it is {}. Put quotes around the value, or use the string "
                "filter.")

# Infrastructure and Applications are shared folders, shown with their subfolders. Parents come before children, as
# the server sends them.
#   Infrastructure: Databases (Production > EU > Frankfurt, Staging), Web (Databases), Prod/EU, 2024, Données
#   Applications: Dup, Dup (Leaf), Dup, Services. Team and Team: two shared folders with the same name.
TREE = [
    (INFRA, "", "Infrastructure"), (APPS, "", "Applications"), (TEAM_1, "", "Team"), (TEAM_2, "", "Team"),
    (NONE_PARENT, None, "NoneParent"),
    (DB, INFRA, "Databases"), (PROD, DB, "Production"), (EU, PROD, "EU"), (FRA, EU, "Frankfurt"), (STG, DB, "Staging"),
    (WEB, INFRA, "Web"), (WEB_DB, WEB, "Databases"), (SLASH, INFRA, "Prod/EU"), (YEAR, INFRA, "2024"),
    (UNI, INFRA, UNICODE_NAME), (PAD, INFRA, "Padded "), (DB_2, INFRA, "Databases2"), (DB_2_CHILD, DB_2, "Child2"),
    (DIGITS, INFRA, "Numbered"),
    (DUP_1, APPS, "Dup"), (DUP_2, APPS, "Dup"), (LEAF, DUP_2, "Leaf"), (DUP_3, APPS, "Dup"), (SVC, APPS, "Services"),
]
NAMES = {uid: name for uid, _, name in TREE}
PARENTS = {uid: parent for uid, parent, _ in TREE}


def failure(msg):
    return {"failed": True, "changed": False, "msg": msg}


def lookup_failure(msg):
    return failure("Could not look up folder: " + msg)


def found(uid, shared, entries=None):
    result = {"changed": False, "folder_uid": uid, "folder_name": NAMES[uid], "parent_uid": PARENTS[uid] or "",
              "shared_folder_uid": shared}
    if entries is not None:
        result["subfolders"] = [{"folder_uid": e, "folder_name": NAMES[e], "parent_uid": PARENTS[e]} for e in entries]
    return result


def not_found_in(name, label, uid):
    return 'No folder named {} was found in the folder "{}" (UID {}).'.format(json.dumps(name, ensure_ascii=False),
                                                                             label, uid)


def not_found_at_top(name):
    return 'No folder named {} was found {}.'.format(json.dumps(name, ensure_ascii=False), TOP)


def duplicates_in(name, label, uid, uids):
    return ('Found {} folders named "{name}" in the folder "{}" (UID {}): {}. Rename one of them in the vault. Or set '
            'subfolder_uid to the UID of the folder that you want, and remove "{name}" from folder_name or '
            'folder_path.').format(len(uids), label, uid, ", ".join(uids), name=name)


def duplicates_at_top(name, uids):
    return ('Found {n} folders named "{name}" {top}: {uids}. Rename one of them in the vault. Or set shared_folder_uid '
            'to the UID of the folder that you want, and remove "{name}" from folder_name or '
            'folder_path.').format(n=len(uids), name=name, top=TOP, uids=", ".join(uids))


def empty_name(names):
    return ('The folder_path {} has an empty folder name. Look for a leading, trailing, or double "/", or an empty '
            'list item.').format(json.dumps(names, ensure_ascii=False))


def path_item(kind):
    return ("Each folder_path item must be a folder name, but one item is {}. Put quotes around the folder "
            "names.").format(kind)


@pytest.fixture
def world(make_sdk, folder):
    """world(extra=[(uid, parent_uid, name)]): a fake SDK with TREE and extra folders."""
    return lambda extra=(): make_sdk([folder(*spec) for spec in list(TREE) + list(extra)])


def assert_read_only(sdk):
    # A lookup reads the folder list once, and nothing else.
    assert [c[0] for c in sdk.client.mock_calls] == ["get_folders"]


# --- Lookups that find a folder: (id, task args, uid, shared folder uid of the result) ---

FOUND_CASES = [
    ("shared_and_name", {"shared_folder_uid": INFRA, "folder_name": "Databases"}, DB, INFRA),
    ("shared_only", {"shared_folder_uid": INFRA}, INFRA, INFRA),
    ("shared_folder_with_a_none_parent", {"shared_folder_uid": NONE_PARENT}, NONE_PARENT, NONE_PARENT),
    ("subfolder_only", {"subfolder_uid": DB}, DB, INFRA),
    ("subfolder_and_name", {"subfolder_uid": DB, "folder_name": "Production"}, PROD, INFRA),
    ("both_uids_start_at_the_subfolder", {"shared_folder_uid": INFRA, "subfolder_uid": PROD}, PROD, INFRA),
    ("both_uids_and_name", {"shared_folder_uid": INFRA, "subfolder_uid": PROD, "folder_name": "EU"}, EU, INFRA),
    ("equal_uids", {"shared_folder_uid": INFRA, "subfolder_uid": INFRA}, INFRA, INFRA),
    ("top_level_name", {"folder_name": "Applications"}, APPS, APPS),
    ("top_level_name_of_a_folder_with_a_none_parent", {"folder_name": "NoneParent"}, NONE_PARENT, NONE_PARENT),
    ("name_with_a_trailing_space_matches_exactly", {"shared_folder_uid": INFRA, "folder_name": "Padded "}, PAD, INFRA),
    ("uid_of_digits_stays_a_string", {"subfolder_uid": DIGITS}, DIGITS, INFRA),
    ("top_level_path", {"folder_path": "Infrastructure/Databases/Production/EU"}, EU, INFRA),
    ("path_from_a_shared_folder", {"shared_folder_uid": INFRA, "folder_path": "Databases/Production/EU"}, EU, INFRA),
    ("path_from_a_subfolder", {"subfolder_uid": DB, "folder_path": "Production/EU"}, EU, INFRA),
    ("list_path_keeps_a_slash_in_a_name", {"shared_folder_uid": INFRA, "folder_path": ["Prod/EU"]}, SLASH, INFRA),
    ("tuple_path", {"shared_folder_uid": INFRA, "folder_path": ("Databases", "Staging")}, STG, INFRA),
    ("repeated_name_takes_the_right_branch", {"shared_folder_uid": INFRA, "folder_path": "Web/Databases"}, WEB_DB,
     INFRA),
    ("number_name", {"shared_folder_uid": INFRA, "folder_name": "2024"}, YEAR, INFRA),
    ("number_name_in_a_list_path", {"folder_path": ["Infrastructure", "2024"]}, YEAR, INFRA),
    ("unicode_name", {"shared_folder_uid": INFRA, "folder_name": UNICODE_NAME}, UNI, INFRA),
    ("path_below_a_duplicate_by_uid", {"subfolder_uid": DUP_2, "folder_path": ["Leaf"]}, LEAF, APPS),
    ("one_of_two_shared_folders_by_uid", {"shared_folder_uid": TEAM_2}, TEAM_2, TEAM_2),
]


@pytest.mark.parametrize("case", FOUND_CASES, ids=[c[0] for c in FOUND_CASES])
@pytest.mark.parametrize("check_mode", [False, True])
def test_lookup_finds_the_folder(world, run_plugin, case, check_mode):
    _, task_args, uid, shared = case
    sdk = world()
    assert run_plugin(sdk, task_args, check_mode=check_mode) == found(uid, shared)
    assert_read_only(sdk)
    assert len(sdk.action_modules) == 1 and sdk.action_modules[0] is not None


# --- Lookups that fail: (id, task args, message). A lookup error has the "Could not look up folder: " prefix. ---

READ_ERRORS = [
    ("name_not_found", {"shared_folder_uid": INFRA, "folder_name": "Nope"},
     not_found_in("Nope", "Infrastructure", INFRA)),
    ("name_of_another_shared_folder", {"shared_folder_uid": INFRA, "folder_name": "Dup"},
     not_found_in("Dup", "Infrastructure", INFRA)),
    ("top_level_not_found", {"folder_name": "Nope"}, not_found_at_top("Nope")),
    ("subfolder_start_shows_the_path_from_the_shared_folder", {"subfolder_uid": PROD, "folder_name": "Nope"},
     not_found_in("Nope", "Infrastructure/Databases/Production", PROD)),
    ("match_is_case_sensitive", {"shared_folder_uid": INFRA, "folder_name": "databases"},
     not_found_in("databases", "Infrastructure", INFRA)),
    ("a_grandchild_is_not_a_direct_child", {"shared_folder_uid": INFRA, "folder_name": "Production"},
     not_found_in("Production", "Infrastructure", INFRA)),
    ("a_folder_below_a_uid_that_starts_like_the_parent_is_not_a_child", {"subfolder_uid": DB, "folder_name": "Child2"},
     not_found_in("Child2", "Infrastructure/Databases", DB)),
    ("a_subfolder_is_not_at_the_top_level", {"folder_name": "Databases"}, not_found_at_top("Databases")),
    ("start_of_a_unicode_name", {"shared_folder_uid": INFRA, "folder_name": "Données"},
     not_found_in("Données", "Infrastructure", INFRA)),
    ("unicode_is_not_normalized", {"shared_folder_uid": INFRA, "folder_name": "Donne\u0301es 数据库 🔐"},
     not_found_in("Donne\u0301es 数据库 🔐", "Infrastructure", INFRA)),
    ("name_without_its_trailing_space", {"shared_folder_uid": INFRA, "folder_name": "Padded"},
     not_found_in("Padded", "Infrastructure", INFRA)),
    ("name_with_an_extra_trailing_space", {"shared_folder_uid": INFRA, "folder_name": "Databases "},
     not_found_in("Databases ", "Infrastructure", INFRA)),
    ("a_name_of_spaces_is_not_blank", {"shared_folder_uid": INFRA, "folder_name": " "},
     not_found_in(" ", "Infrastructure", INFRA)),
    ("path_name_with_a_leading_space", {"shared_folder_uid": INFRA, "folder_path": "Databases/ Production"},
     not_found_in(" Production", "Infrastructure/Databases", DB)),
    ("string_path_splits_a_slash_name", {"shared_folder_uid": INFRA, "folder_path": "Prod/EU"},
     not_found_in("Prod", "Infrastructure", INFRA)),
    ("folder_name_is_not_a_path", {"shared_folder_uid": INFRA, "folder_name": "Databases/Production"},
     not_found_in("Databases/Production", "Infrastructure", INFRA)),
    ("path_missing_level_in_the_middle", {"shared_folder_uid": INFRA, "folder_path": "Databases/Nope/EU"},
     not_found_in("Nope", "Infrastructure/Databases", DB)),
    ("path_missing_first_level", {"folder_path": "Nope/EU"}, not_found_at_top("Nope")),
    ("path_missing_last_level", {"shared_folder_uid": INFRA, "folder_path": "Databases/Production/Nope"},
     not_found_in("Nope", "Infrastructure/Databases/Production", PROD)),
    ("duplicate_names", {"shared_folder_uid": APPS, "folder_name": "Dup"},
     duplicates_in("Dup", "Applications", APPS, [DUP_1, DUP_2, DUP_3])),
    ("duplicate_in_the_middle_of_a_path", {"folder_path": "Applications/Dup/Leaf"},
     duplicates_in("Dup", "Applications", APPS, [DUP_1, DUP_2, DUP_3])),
    ("duplicate_shared_folders", {"folder_name": "Team"}, duplicates_at_top("Team", [TEAM_1, TEAM_2])),
    ("duplicate_shared_folders_in_a_path", {"folder_path": "Team/Nope"}, duplicates_at_top("Team", [TEAM_1, TEAM_2])),
    ("subfolder_in_another_shared_folder", {"shared_folder_uid": APPS, "subfolder_uid": PROD},
     'The subfolder "Infrastructure/Databases/Production" (UID PROD) is not inside the shared folder "Applications" '
     '(UID SF_APPS).'),
    ("subfolder_uid_of_another_shared_folder", {"shared_folder_uid": INFRA, "subfolder_uid": APPS},
     'The subfolder "Applications" (UID SF_APPS) is not inside the shared folder "Infrastructure" (UID SF_INFRA).'),
    ("shared_folder_uid_of_a_subfolder", {"shared_folder_uid": DB, "folder_name": "Production"},
     'The folder "Infrastructure/Databases" (UID DB) is a subfolder, not a shared folder. Set it as subfolder_uid '
     'instead.'),
    ("shared_folder_uid_of_a_deep_subfolder_even_with_a_valid_subfolder_uid",
     {"shared_folder_uid": FRA, "subfolder_uid": DB},
     'The folder "Infrastructure/Databases/Production/EU/Frankfurt" (UID FRA) is a subfolder, not a shared folder. '
     'Set it as subfolder_uid instead.'),
    ("shared_folder_not_found", {"shared_folder_uid": "NO_SUCH_UID"},
     "The shared folder NO_SUCH_UID was not found, or it is not shared to this KSM application."),
    ("subfolder_not_found", {"subfolder_uid": "NO_SUCH_UID"},
     "The subfolder NO_SUCH_UID was not found, or it is not shared to this KSM application."),
    ("subfolder_not_found_in_a_valid_shared_folder", {"shared_folder_uid": INFRA, "subfolder_uid": "NO_SUCH_UID"},
     "The subfolder NO_SUCH_UID was not found, or it is not shared to this KSM application."),
    ("uid_match_is_case_sensitive", {"shared_folder_uid": INFRA.lower()},
     "The shared folder sf_infra was not found, or it is not shared to this KSM application."),
]


@pytest.mark.parametrize("case", READ_ERRORS, ids=[c[0] for c in READ_ERRORS])
@pytest.mark.parametrize("check_mode", [False, True])
def test_lookup_fails_with_a_clear_message(world, run_plugin, case, check_mode):
    _, task_args, message = case
    sdk = world()
    assert run_plugin(sdk, task_args, check_mode=check_mode) == lookup_failure(message)
    assert_read_only(sdk)


def test_get_folders_error_and_no_folders(world, run_plugin, make_sdk):
    sdk = world()
    sdk.client.get_folders.side_effect = Exception("network is down")
    assert run_plugin(sdk, {"shared_folder_uid": INFRA}) == lookup_failure("Cannot get folders: network is down")

    sdk = make_sdk([])
    sdk.client.get_folders.side_effect = None
    sdk.client.get_folders.return_value = None
    assert run_plugin(sdk, {"shared_folder_uid": INFRA}) == lookup_failure(
        "The shared folder SF_INFRA was not found, or it is not shared to this KSM application.")


# --- Checks before the folder list is read ---

# (id, task args, message)
PRE_READ_ERRORS = [
    ("nothing_to_look_up", {"include_subfolders": True}, NOTHING),
    ("blank_shared_folder_uid", {"shared_folder_uid": " ", "folder_name": "Databases"},
     "The shared_folder_uid is set but blank. Set it to a folder UID, or remove it."),
    ("blank_uid_is_not_nothing_to_look_up", {"subfolder_uid": ""},
     "The subfolder_uid is set but blank. Set it to a folder UID, or remove it."),
    ("shared_folder_uid_is_checked_first", {"shared_folder_uid": "", "subfolder_uid": ""},
     "The shared_folder_uid is set but blank. Set it to a folder UID, or remove it."),
    ("padded_shared_folder_uid", {"shared_folder_uid": "SF_INFRA ", "folder_name": "Databases"},
     "The shared_folder_uid 'SF_INFRA ' has leading or trailing whitespace."),
    ("padded_subfolder_uid", {"subfolder_uid": "DB\n"},
     "The subfolder_uid 'DB\\n' has leading or trailing whitespace."),
    ("blank_folder_name", {"shared_folder_uid": INFRA, "folder_name": ""},
     "The folder_name is set but blank. Set it to a folder name, or remove it."),
    ("double_slash_in_a_path", {"folder_path": "Infrastructure//Databases"},
     empty_name(["Infrastructure", "", "Databases"])),
    ("leading_slash_in_a_path", {"folder_path": "/Databases"}, empty_name(["", "Databases"])),
    ("trailing_slash_in_a_path", {"shared_folder_uid": INFRA, "folder_path": "Données/"},
     empty_name(["Données", ""])),
    ("empty_string_path", {"folder_path": ""}, empty_name([""])),
    ("empty_list_path", {"shared_folder_uid": INFRA, "folder_path": []}, empty_name([])),
    ("null_item_in_a_list_path", {"shared_folder_uid": INFRA, "folder_path": ["Databases", None]},
     empty_name(["Databases", ""])),
    ("empty_item_next_to_an_existing_name", {"folder_path": ["Infrastructure", ""]},
     empty_name(["Infrastructure", ""])),
    ("dictionary_path", {"folder_path": {"name": "Databases"}}, "The folder_path must be a string or a list of folder "
                                                                 "names."),
    ("number_path", {"folder_path": 2024}, "The folder_path must be a string or a list of folder names."),
    ("boolean_item", {"folder_path": ["Databases", True]}, path_item("a boolean (True)")),
    ("float_item", {"folder_path": ["Databases", 1.1]}, path_item("a number (1.1)")),
    ("number_item", {"folder_path": ["Infrastructure", 2024]}, path_item("a number (2024)")),
    ("list_item", {"folder_path": ["Infrastructure", ["Databases"]]}, path_item("a list")),
]


@pytest.mark.parametrize("case", PRE_READ_ERRORS, ids=[c[0] for c in PRE_READ_ERRORS])
def test_bad_values_fail_before_the_folders_are_read(world, run_plugin, case):
    _, task_args, message = case
    sdk = world()
    assert run_plugin(sdk, task_args) == lookup_failure(message)
    assert sdk.client.mock_calls == []


# --- Result: subfolders, include_subfolders ---

SHARED_SUBTREE = [DB, PROD, EU, FRA, STG, WEB, WEB_DB, SLASH, YEAR, UNI, PAD, DB_2, DB_2_CHILD, DIGITS]


@pytest.mark.parametrize("value", [True, "yes", "true"])
@pytest.mark.parametrize("task_args, uid, shared, entries", [
    ({"shared_folder_uid": INFRA}, INFRA, INFRA, SHARED_SUBTREE),
    ({"shared_folder_uid": INFRA, "folder_name": "Databases"}, DB, INFRA, [PROD, EU, FRA, STG]),
    ({"subfolder_uid": PROD}, PROD, INFRA, [EU, FRA]),
    ({"folder_path": "Infrastructure/Databases/Staging"}, STG, INFRA, []),
    ({"shared_folder_uid": APPS}, APPS, APPS, [DUP_1, DUP_2, LEAF, DUP_3, SVC]),
    ({"shared_folder_uid": NONE_PARENT}, NONE_PARENT, NONE_PARENT, []),
], ids=["whole_shared_folder", "from_a_name", "from_a_subfolder", "leaf", "same_named_siblings", "no_subfolders"])
def test_include_subfolders_lists_every_folder_below_depth_first(world, run_plugin, task_args, uid, shared, entries,
                                                                 value):
    # Depth first, each parent before its children, children in the order of the server. Not the folder itself.
    sdk = world()
    assert run_plugin(sdk, dict(task_args, include_subfolders=value)) == found(uid, shared, entries)
    assert_read_only(sdk)


@pytest.mark.parametrize("value", [False, "no", "false"])
def test_subfolders_are_left_out_unless_asked_for(world, run_plugin, value):
    result = run_plugin(world(), {"shared_folder_uid": INFRA, "include_subfolders": value})
    assert result == found(INFRA, INFRA)
    assert "subfolders" not in result


# --- Folder names with special characters: JSON-quoted in messages, matched exactly ---

SPECIAL = [
    ('Say "hi"', '"Say \\"hi\\""'),
    ("Ops\tEU", '"Ops\\tEU"'),
    ("Back\\slash", '"Back\\\\slash"'),
    ("New\nLine", '"New\\nLine"'),
    ("Café 数据", '"Café 数据"'),
]


@pytest.mark.parametrize("name, quoted", SPECIAL, ids=["double_quote", "tab", "backslash", "newline", "non_ascii"])
def test_special_characters_in_a_folder_name(world, run_plugin, name, quoted):
    sdk = world([("SP_UID", INFRA, name), ("TWIN_1", APPS, name), ("TWIN_2", APPS, name)])
    assert run_plugin(sdk, {"shared_folder_uid": INFRA, "folder_name": name})["folder_uid"] == "SP_UID"
    assert run_plugin(sdk, {"shared_folder_uid": APPS, "folder_name": name}) == lookup_failure(
        'Found 2 folders named {q} in the folder "Applications" (UID SF_APPS): TWIN_1, TWIN_2. Rename one of them in '
        'the vault. Or set subfolder_uid to the UID of the folder that you want, and remove {q} from folder_name or '
        'folder_path.'.format(q=quoted))
    assert run_plugin(world(), {"shared_folder_uid": APPS, "folder_name": name}) == lookup_failure(
        'No folder named {} was found in the folder "Applications" (UID SF_APPS).'.format(quoted))


def test_folder_path_is_quoted_in_the_start_and_not_inside_labels(world, run_plugin):
    sdk = world([("Q_UID", INFRA, 'A "B"\n'), ("QC_UID", "Q_UID", "Child")])
    assert run_plugin(sdk, {"subfolder_uid": "QC_UID", "folder_name": "Nope"}) == lookup_failure(
        'No folder named "Nope" was found in the folder "Infrastructure/A \\"B\\"\\n/Child" (UID QC_UID).')
    assert run_plugin(sdk, {"shared_folder_uid": APPS, "subfolder_uid": "QC_UID"}) == lookup_failure(
        'The subfolder "Infrastructure/A \\"B\\"\\n/Child" (UID QC_UID) is not inside the shared folder '
        '"Applications" (UID SF_APPS).')


# --- Malformed folder data must not hang or crash the lookup ---

CYCLE = [("A", "B", "A"), ("B", "A", "B")]


def run_bounded(sdk, run_plugin, task_args):
    outcome = bounded(lambda: run_plugin(sdk, task_args))
    assert "error" not in outcome, outcome
    return outcome["result"]


@pytest.mark.parametrize("extra, task_args, expected", [
    pytest.param(CYCLE, {"subfolder_uid": "A"},
                 {"changed": False, "folder_uid": "A", "folder_name": "A", "parent_uid": "B",
                  "shared_folder_uid": None},
                 id="cycle_has_no_shared_folder"),
    pytest.param(CYCLE, {"subfolder_uid": "A", "include_subfolders": True},
                 {"changed": False, "folder_uid": "A", "folder_name": "A", "parent_uid": "B", "shared_folder_uid": None,
                  "subfolders": [{"folder_uid": "B", "folder_name": "B", "parent_uid": "A"}]},
                 id="cycle_lists_each_folder_once"),
    pytest.param(CYCLE, {"subfolder_uid": "A", "folder_path": "B/A/B"},
                 {"changed": False, "folder_uid": "B", "folder_name": "B", "parent_uid": "A",
                  "shared_folder_uid": None},
                 id="name_walk_through_a_cycle_ends"),
    pytest.param(CYCLE, {"subfolder_uid": "A", "folder_name": "Nope"},
                 lookup_failure('No folder named "Nope" was found in the folder "B/A" (UID A).'),
                 id="cycle_in_a_label"),
    pytest.param(CYCLE, {"shared_folder_uid": "A"},
                 lookup_failure('The folder "B/A" (UID A) is a subfolder, not a shared folder. Set it as '
                                'subfolder_uid instead.'), id="cycle_as_shared_folder"),
    pytest.param(CYCLE, {"shared_folder_uid": INFRA, "subfolder_uid": "A"},
                 lookup_failure('The subfolder "B/A" (UID A) is not inside the shared folder "Infrastructure" '
                                '(UID SF_INFRA).'), id="cycle_is_not_inside_a_shared_folder"),
    pytest.param([("S", "S", "Self")], {"subfolder_uid": "S"},
                 {"changed": False, "folder_uid": "S", "folder_name": "Self", "parent_uid": "S",
                  "shared_folder_uid": None}, id="self_parent"),
    pytest.param([("O", "GONE", "Orphan")], {"subfolder_uid": "O"},
                 {"changed": False, "folder_uid": "O", "folder_name": "Orphan", "parent_uid": "GONE",
                  "shared_folder_uid": None}, id="missing_parent"),
    pytest.param([("O", "GONE", "Orphan")], {"shared_folder_uid": INFRA, "subfolder_uid": "O"},
                 lookup_failure('The subfolder "Orphan" (UID O) is not inside the shared folder "Infrastructure" '
                                '(UID SF_INFRA).'), id="missing_parent_is_not_inside"),
    pytest.param([("X", "Y", "X"), ("Y", "Z", "Y"), ("Z", "Y", "Z")],
                 {"subfolder_uid": "Y", "include_subfolders": True},
                 {"changed": False, "folder_uid": "Y", "folder_name": "Y", "parent_uid": "Z", "shared_folder_uid": None,
                  "subfolders": [{"folder_uid": "X", "folder_name": "X", "parent_uid": "Y"},
                                 {"folder_uid": "Z", "folder_name": "Z", "parent_uid": "Y"}]},
                 id="cycle_below_the_folder"),
])
def test_malformed_folder_data(world, run_plugin, extra, task_args, expected):
    assert run_bounded(world(extra), run_plugin, task_args) == expected


def test_method_called_directly_checks_its_own_arguments(world):
    # The option check of the plugin rejects these first. The method does not rely on it.
    keeper = world().keeper()
    with pytest.raises(KeeperFolderError, match="The folder_name and folder_path are both set. Set only one of them."):
        keeper.get_folder(shared_folder_uid=INFRA, folder_name="Databases", folder_path="Databases")
    assert keeper.get_folder(shared_folder_uid=INFRA, folder_name=2024)["folder_uid"] == YEAR


# --- Options and the plugin wiring ---

def test_include_subfolders_default_and_the_result_is_not_a_change(world, run_plugin):
    result = run_plugin(world(), {"shared_folder_uid": INFRA})
    assert result["changed"] is False
    assert "subfolders" not in result


@pytest.mark.parametrize("option, extra", [
    ("shared_folder_uid", {"folder_name": "Infrastructure"}),
    ("subfolder_uid", {"shared_folder_uid": INFRA}),
    ("folder_name", {"shared_folder_uid": INFRA}),
    ("folder_path", {"shared_folder_uid": INFRA}),
    ("include_subfolders", {"shared_folder_uid": INFRA}),
])
def test_null_option_fails_instead_of_meaning_not_set(world, run_plugin, option, extra):
    # As "not set", a null shared_folder_uid would look up the name among the shared folders instead.
    sdk = world()
    assert run_plugin(sdk, dict(extra, **{option: None})) == failure(NULL_MESSAGE.format(option))
    assert sdk.inits == 0
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("task_args, message", [
    ({"shared_folder_uid": ["SF_INFRA"]}, NOT_A_STRING.format("shared_folder_uid", "a list")),
    ({"shared_folder_uid": INFRA, "folder_name": 2024}, NOT_A_STRING.format("folder_name", "a number (2024)")),
    ({"subfolder_uid": True}, NOT_A_STRING.format("subfolder_uid", "a boolean (True)")),
])
def test_str_options_reject_other_types(world, run_plugin, task_args, message):
    sdk = world()
    assert run_plugin(sdk, task_args) == failure(message)
    assert sdk.inits == 0


def test_include_subfolders_that_is_not_a_boolean_fails(world, run_plugin):
    sdk = world()
    result = run_plugin(sdk, {"shared_folder_uid": INFRA, "include_subfolders": "maybe"})
    assert result["failed"] is True and result["changed"] is False
    assert result["msg"].startswith("argument 'include_subfolders' is of type ")
    assert sdk.inits == 0


def assert_unsupported(result, before):
    # The supported names are compared as a set: ansible-core before 2.15 did not always sort them.
    assert result["failed"] is True and result["changed"] is False
    head, marker, after = result["msg"].partition("Supported parameters include: ")
    assert head == before
    assert marker and set(after.rstrip(".").split(", ")) == SUPPORTED


@pytest.mark.parametrize("task_args, before", [
    ({"shared_folder_uid": INFRA, "folder_nme": "Databases"},
     "Unsupported parameters for (keeper_get_folder) module: folder_nme. "),
    ({"shared_folder_uid": INFRA, "folder_uid": "x", "path": "y"},
     "Unsupported parameters for (keeper_get_folder) module: folder_uid, path. "),
], ids=["one_typo", "several"])
def test_unsupported_option_fails_before_the_sdk_is_used(world, run_plugin, task_args, before):
    sdk = world()
    assert_unsupported(run_plugin(sdk, task_args), before)
    assert sdk.inits == 0 and sdk.client.mock_calls == []


def test_folder_name_and_folder_path_are_mutually_exclusive(world, run_plugin):
    sdk = world()
    result = run_plugin(sdk, {"shared_folder_uid": INFRA, "folder_name": "Databases", "folder_path": "Databases"})
    assert result["failed"] is True
    assert result["msg"].startswith("parameters are mutually exclusive: folder_name|folder_path")
    assert sdk.inits == 0


@pytest.mark.parametrize("error", [RuntimeError("unexpected"), AttributeError("'NoneType' object has no attribute")])
def test_any_exception_from_the_method_is_returned_not_raised(world, run_plugin, monkeypatch, error):
    def raise_error(*args, **kwargs):
        raise error
    monkeypatch.setattr(KeeperAnsible, "get_folder", raise_error)
    assert run_plugin(world(), {"shared_folder_uid": INFRA}) == lookup_failure(str(error))


def test_config_error_from_keeper_ansible_is_raised(make_sdk, run_plugin):
    sdk = make_sdk([], init_error=ValueError("Keeper Ansible error: no config"))
    with pytest.raises(ValueError):
        run_plugin(sdk, {"shared_folder_uid": INFRA})


def test_every_option_reaches_the_method(world, run_plugin):
    with patch.object(KeeperAnsible, "get_folder", autospec=True, return_value={"folder_uid": "X"}) as method:
        result = run_plugin(world(), {"shared_folder_uid": INFRA, "subfolder_uid": DB, "folder_name": "Production",
                                      "include_subfolders": "yes"})
    assert result == {"folder_uid": "X", "changed": False}
    assert method.call_args.kwargs == {"shared_folder_uid": INFRA, "subfolder_uid": DB, "folder_name": "Production",
                                       "folder_path": None, "include_subfolders": True}
    assert method.call_args.args[0].client is not None

    with patch.object(KeeperAnsible, "get_folder", autospec=True, return_value={}) as method:
        run_plugin(world(), {"folder_path": ["Infrastructure"]})
    assert method.call_args.kwargs == {"shared_folder_uid": None, "subfolder_uid": None, "folder_name": None,
                                       "folder_path": ["Infrastructure"], "include_subfolders": False}


@pytest.mark.parametrize("as_list", [False, True], ids=["vault_string_path_is_split_on_slash",
                                                          "vault_items_in_a_list_are_one_name_each"])
def test_vault_values_are_used_decrypted(world, run_plugin, monkeypatch, as_list):
    # A !vault value is not a str. The option check must accept it, and the lookup must use its text.
    class Vaulted(object):
        def __init__(self, text):
            self.text = text

        def __str__(self):
            return self.text

    monkeypatch.setattr(KeeperAnsible, "_vault_string_types", staticmethod(lambda: (Vaulted,)))
    folder_path = [Vaulted("Infrastructure"), Vaulted("Databases")] if as_list else Vaulted("Infrastructure/Databases")
    assert run_plugin(world(), {"folder_path": folder_path})["folder_uid"] == DB


def test_vault_value_for_a_name_with_a_slash_stays_one_name(world, run_plugin, monkeypatch):
    class Vaulted(object):
        def __str__(self):
            return "Prod/EU"

    monkeypatch.setattr(KeeperAnsible, "_vault_string_types", staticmethod(lambda: (Vaulted,)))
    assert run_plugin(world(), {"shared_folder_uid": INFRA, "folder_path": [Vaulted()]})["folder_uid"] == SLASH


# --- module_defaults for the action group of this collection ---

def test_group_defaults_of_other_modules_are_ignored(world, run_plugin):
    task_args = {"shared_folder_uid": INFRA, "folder_name": "Databases", "cache": "C", "new_folder_name": "X"}
    defaults = [{GROUP: {"cache": "C", "new_folder_name": "X", "include_subfolders": False}}]
    assert run_plugin(world(), task_args, module_defaults=defaults) == found(DB, INFRA)


@pytest.mark.parametrize("task_args, defaults, before", [
    pytest.param({"shared_folder_uid": INFRA, "folder_nme": "x", "cache": "C"}, {GROUP: {"cache": "C"}},
                 "Unsupported parameters for (keeper_get_folder) module: folder_nme. ",
                 id="typo_next_to_a_group_default"),
    pytest.param({"shared_folder_uid": INFRA, "region": "r"}, {"group/amazon.aws.aws": {"region": "r"}},
                 "Unsupported parameters for (keeper_get_folder) module: region. ", id="group_of_another_collection"),
    pytest.param({"shared_folder_uid": INFRA, "cache": "C"},
                 {"keepersecurity.keeper_secrets_manager.keeper_create_folder": {"cache": "C"}},
                 "Unsupported parameters for (keeper_get_folder) module: cache. ", id="defaults_of_one_other_module"),
])
def test_unsupported_option_still_fails_with_defaults(world, run_plugin, task_args, defaults, before):
    sdk = world()
    assert_unsupported(run_plugin(sdk, task_args, module_defaults=[defaults]), before)
    assert sdk.inits == 0


def test_a_group_default_for_an_option_of_this_module_is_still_checked(world, run_plugin):
    task_args = {"shared_folder_uid": INFRA, "include_subfolders": "maybe"}
    result = run_plugin(world(), task_args, module_defaults=[{GROUP: {"include_subfolders": "maybe"}}])
    assert result["failed"] is True and "include_subfolders" in result["msg"]


def test_templated_group_defaults_are_resolved_with_the_plugin_templar(world, run_plugin):
    class Templar:
        calls = []

        def template(self, value):
            self.calls.append(value)
            return {"cache": "C"}

    templar = Templar()
    result = run_plugin(world(), {"shared_folder_uid": INFRA, "cache": "C"},
                        module_defaults=[{GROUP: "{{ keeper_defaults }}"}], templar=templar)
    assert result == found(INFRA, INFRA)
    assert templar.calls == ["{{ keeper_defaults }}"]


# --- Documentation ---

def test_docs_stub_matches_the_action_plugin_docs(plugin_module):
    stub = importlib.import_module("keeper_secrets_manager_ansible.plugins.modules.keeper_get_folder")
    for name in ["DOCUMENTATION", "EXAMPLES", "RETURN"]:
        assert getattr(stub, name) == getattr(plugin_module, name), name


def test_documented_options_match_the_argument_spec(plugin_module):
    options = yaml.safe_load(plugin_module.DOCUMENTATION)["options"]
    spec = plugin_module.ActionModule.ARGUMENT_SPEC
    assert set(options) == set(spec) == SUPPORTED
    for name, doc in options.items():
        assert doc["type"] == spec[name]["type"], name
        assert bool(doc.get("required", False)) == spec[name].get("required", False), name
    assert options["include_subfolders"]["default"] is spec["include_subfolders"]["default"] is False


def test_documented_return_values_match_the_result(world, run_plugin, plugin_module):
    documented = set(yaml.safe_load(plugin_module.RETURN))
    result = run_plugin(world(), {"shared_folder_uid": INFRA, "include_subfolders": True})
    assert documented == set(result) - {"changed"}
