import logging
import os
from unittest.mock import patch

import pytest
import yaml
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.keeper_globals import logger_name

from ._helpers import run_target
from ..folder_fake_server import FakeKeeperServer

TARGET = os.path.join(os.path.dirname(os.path.realpath(__file__)), "targets", "keeper_get_folder", "playbook.yml")

# Shared folders come before their subfolders, as the real server sends them.
FOLDERS = [
    {"uid": "SHARED_UID", "name": "Infrastructure", "parent": None},
    {"uid": "OTHER_SHARED_UID", "name": "Applications", "parent": None},
    {"uid": "DATABASES_UID", "name": "Databases", "parent": "SHARED_UID"},
    {"uid": "PRODUCTION_UID", "name": "Production", "parent": "DATABASES_UID"},
    {"uid": "EU_UID", "name": "EU", "parent": "PRODUCTION_UID"},
    {"uid": "STAGING_UID", "name": "Staging", "parent": "DATABASES_UID"},
    {"uid": "SLASH_UID", "name": "Prod/EU", "parent": "SHARED_UID"},
    {"uid": "YEAR_UID", "name": "2024", "parent": "SHARED_UID"},
    {"uid": "UNICODE_UID", "name": "Données 数据库 🔐", "parent": "SHARED_UID"},
    {"uid": "QUOTE_UID", "name": 'Say "hi"', "parent": "SHARED_UID"},
    {"uid": "TWIN_1_UID", "name": 'Twin "A"', "parent": "SHARED_UID"},
    {"uid": "TWIN_2_UID", "name": 'Twin "A"', "parent": "SHARED_UID"},
    {"uid": "DUP_1_UID", "name": "Dup", "parent": "OTHER_SHARED_UID"},
    {"uid": "DUP_2_UID", "name": "Dup", "parent": "OTHER_SHARED_UID"},
    {"uid": "LEAF_UID", "name": "Leaf", "parent": "DUP_2_UID"},
]
UID_VARS = {name + "_uid": name.upper() + "_UID" for name in
            ["shared", "other_shared", "databases", "production", "eu", "staging", "slash", "year", "unicode", "quote"]}

NOT_A_STRING = ("The {} option must be a string, but it is {}. Put quotes around the value, or use the string "
                "filter.")
UNSUPPORTED = "Unsupported parameters for (keeper_get_folder) module: "
DUP_HINT = ("Rename one of them in the vault. Or set subfolder_uid to the UID of the folder that you want, and remove "
            "{q} from folder_name or folder_path.")
EXPECTED = {
    "list": NOT_A_STRING.format("folder_name", "a list"),
    "int": NOT_A_STRING.format("folder_name", "a number (2024)"),
    "date": NOT_A_STRING.format("folder_name", "a date (2026-09-29)"),
    "bool": NOT_A_STRING.format("folder_name", "a boolean (True)"),
    "not_a_boolean": "argument 'include_subfolders' is of type ",
    "typo": UNSUPPORTED + "folder_nme. Supported parameters include: ",
    "exclusive": "parameters are mutually exclusive: folder_name|folder_path",
    "null_shared": "The shared_folder_uid option is null. Give it a value, or leave the option out of the task.",
    "null_name": "The folder_name option is null. Give it a value, or leave the option out of the task.",
    "blank_name": "Could not look up folder: The folder_name is set but blank. Set it to a folder name, or remove it.",
    "padded": "Could not look up folder: The shared_folder_uid 'SHARED_UID ' has leading or trailing whitespace.",
    "path_type": "Could not look up folder: The folder_path must be a string or a list of folder names.",
    "item_bool": "Could not look up folder: Each folder_path item must be a folder name, but one item is a boolean "
                 "(True). Put quotes around the folder names.",
    "item_float": "Could not look up folder: Each folder_path item must be a folder name, but one item is a number "
                  "(1.1). Put quotes around the folder names.",
    "item_int": "Could not look up folder: Each folder_path item must be a folder name, but one item is a number "
                "(2024). Put quotes around the folder names.",
    "failed": [
        'Could not look up folder: No folder named "Nope" was found in the folder "Infrastructure" '
        '(UID SHARED_UID).',
        'Could not look up folder: Found 2 folders named "Dup" in the folder "Applications" (UID OTHER_SHARED_UID): '
        'DUP_1_UID, DUP_2_UID. ' + DUP_HINT.format(q='"Dup"'),
        'Could not look up folder: Found 2 folders named "Dup" in the folder "Applications" (UID OTHER_SHARED_UID): '
        'DUP_1_UID, DUP_2_UID. ' + DUP_HINT.format(q='"Dup"'),
        'Could not look up folder: Found 2 folders named "Twin \\"A\\"" in the folder "Infrastructure" '
        '(UID SHARED_UID): TWIN_1_UID, TWIN_2_UID. ' + DUP_HINT.format(q='"Twin \\"A\\""'),
        'Could not look up folder: No folder named "Say \\"hi\\"" was found in the folder "Applications" '
        '(UID OTHER_SHARED_UID).',
        'Could not look up folder: No folder named "Ops\\tEU" was found in the folder "Applications" '
        '(UID OTHER_SHARED_UID).',
        'Could not look up folder: The folder "Infrastructure/Databases" (UID DATABASES_UID) is a subfolder, not a '
        'shared folder. Set it as subfolder_uid instead.',
    ],
}


@pytest.fixture(scope="module")
def run():
    server = FakeKeeperServer(folders=FOLDERS)
    variables = dict(UID_VARS, expected=EXPECTED)
    with run_target(server, TARGET, variables, collection=True) as result:
        yield (server,) + result


def test_playbook_passes(run):
    _, recap, out, err = run
    summary = "\n".join(l for l in (out + err).splitlines() if "fatal:" in l or "[ERROR]" in l or "FAILED" in l)
    expected = {"ok": 27, "changed": 0, "failed": 0, "unreachable": 0, "skipped": 0, "rescued": 1, "ignored": 12}
    assert {k: recap.get(k) for k in expected} == expected, summary


def test_every_request_is_a_read_and_the_vault_is_unchanged(run):
    server, _, _, _ = run
    assert {c["path"] for c in server.calls()} == {"get_folders"}
    assert server.folders() == [dict(f) for f in FOLDERS]


def test_action_rejects_simulated_partial_read_names_but_preserves_explicit_uids(tmp_path):
    """Compatibility simulation around real encrypted folder reads, not a public SDK partial-read reproduction."""
    hidden = {"uid": "UNREADABLE_TWIN_UID", "name": "Databases", "parent": "SHARED_UID"}
    server = FakeKeeperServer(folders=FOLDERS + [hidden])
    original_get = SecretsManager.get_folders

    def partial_read(sm):
        readable = original_get(sm)
        logging.getLogger(logger_name).warning("Folder %s skipped due to error: %s", hidden["uid"],
                                               "simulated unreadable metadata")
        return [folder for folder in readable if folder.folder_uid != hidden["uid"]]

    names = [
        {"shared_folder_uid": "SHARED_UID", "folder_name": "Databases"},
        {"subfolder_uid": "DATABASES_UID", "folder_name": "Production"},
        {"shared_folder_uid": "SHARED_UID", "folder_path": ["Databases", "Production", "EU"]},
        {"folder_path": "Infrastructure/Databases"},
    ]
    uids = [
        {"shared_folder_uid": "SHARED_UID", "expected_uid": "SHARED_UID"},
        {"subfolder_uid": "PRODUCTION_UID", "expected_uid": "PRODUCTION_UID"},
    ]
    options = {key: "{{ item." + key + " | default(omit) }}" for key in
               ("shared_folder_uid", "subfolder_uid", "folder_name", "folder_path")}
    playbook = tmp_path / "partial_read_lookup.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "my_systems", "gather_facts": False, "tasks": [
            {"name": "Reject uncertain name targets", "keeper_get_folder": options, "loop": "{{ name_targets }}",
             "register": "names", "ignore_errors": True},
            {"name": "Keep readable UID targets", "keeper_get_folder": options, "loop": "{{ uid_targets }}",
             "register": "uids"},
            {"name": "Check name rejection", "assert": {"that": [
                "item is failed", "'Absence and uniqueness cannot be confirmed' in item.msg",
                "'folder_uid' not in item",
            ]}, "loop": "{{ names.results }}"},
            {"name": "Check UID controls", "assert": {"that": [
                "item is not failed", "item is not changed", "item.folder_uid == item.item.expected_uid",
            ]}, "loop": "{{ uids.results }}"},
        ],
    }], sort_keys=False), encoding="utf-8")
    sdk_patch = patch.object(SecretsManager, "get_folders", autospec=True, side_effect=partial_read)
    with run_target(server, str(playbook), {"name_targets": names, "uid_targets": uids},
                    sdk_patch=sdk_patch) as (recap, out, err):
        assert recap.get("failed") == 0 and recap.get("unreachable") == 0, out + err
        assert recap.get("ignored") == 1, out + err
        assert {call["path"] for call in server.calls()} == {"get_folders"}
        assert len(server.calls()) == len(names) + len(uids)
        assert server.folders() == FOLDERS + [hidden]
