import contextlib
import importlib
import os
import shutil
import sys
import tempfile
from unittest.mock import patch

import pytest

import keeper_secrets_manager_ansible.plugins
from ..ansible_test_framework import AnsibleTestFramework
from ..folder_fake_server import FakeKeeperServer

TARGET = os.path.join(os.path.dirname(os.path.realpath(__file__)), "targets", "keeper_get_folder", "playbook.yml")
COMPONENT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
RUNTIME_YML = os.path.join(COMPONENT_DIR, "ansible_galaxy", "keepersecurity", "keeper_secrets_manager", "meta",
                           "runtime.yml")
PLUGINS_DIR = os.path.dirname(os.path.realpath(keeper_secrets_manager_ansible.plugins.__file__))

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


@contextlib.contextmanager
def _environment(name, value):
    saved = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = saved


@contextlib.contextmanager
def _collection_path():
    """A collections path with the real meta/runtime.yml, so Ansible applies the action group module_defaults."""
    root = tempfile.mkdtemp(prefix="ksm_target_collections_")
    collection = os.path.join(root, "ansible_collections", "keepersecurity", "keeper_secrets_manager")
    try:
        os.makedirs(os.path.join(collection, "meta"))
        os.makedirs(os.path.join(collection, "plugins"))
        shutil.copyfile(RUNTIME_YML, os.path.join(collection, "meta", "runtime.yml"))
        for name in ("action", "modules"):
            os.symlink(os.path.join(PLUGINS_DIR, name), os.path.join(collection, "plugins", name))
        with _environment("ANSIBLE_COLLECTIONS_PATH", root):
            yield
    finally:
        # Unlink first, so rmtree can never reach the real plugin files.
        for name in ("action", "modules"):
            link = os.path.join(collection, "plugins", name)
            if os.path.islink(link):
                os.unlink(link)
        shutil.rmtree(root)


def _unload_ansible():
    # A loaded ansible plugin loader has the default plugin path, and then the run fails with "couldn't resolve
    # module/action". AnsibleTestFramework unloads ansible after each run for the same reason.
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)


@pytest.fixture(scope="module")
def run():
    _unload_ansible()
    server = FakeKeeperServer(folders=FOLDERS)
    variables = dict(UID_VARS, expected=EXPECTED)
    try:
        with server.patch(), _collection_path():
            # Imported after the collections path is set: an import of ansible.utils.display reads that path.
            errors = importlib.import_module("ansible.errors")
            with patch("keeper_secrets_manager_ansible.AnsibleError", errors.AnsibleError):
                recap, out, err = AnsibleTestFramework(playbook=TARGET, vars=variables).run()
        yield server, recap, out, err
    finally:
        server.cleanup()
        _unload_ansible()


def test_playbook_passes(run):
    _, recap, out, err = run
    summary = "\n".join(l for l in (out + err).splitlines() if "fatal:" in l or "[ERROR]" in l or "FAILED" in l)
    expected = {"ok": 26, "changed": 0, "failed": 0, "unreachable": 0, "skipped": 0, "rescued": 1, "ignored": 11}
    assert {k: recap.get(k) for k in expected} == expected, summary


def test_every_request_is_a_read_and_the_vault_is_unchanged(run):
    server, _, _, _ = run
    assert {c["path"] for c in server.calls()} == {"get_folders"}
    assert server.folders() == [dict(f) for f in FOLDERS]
