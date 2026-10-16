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

TARGET = os.path.join(os.path.dirname(os.path.realpath(__file__)), "targets", "keeper_update_folder", "playbook.yml")
COMPONENT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
RUNTIME_YML = os.path.join(COMPONENT_DIR, "ansible_galaxy", "keepersecurity", "keeper_secrets_manager", "meta",
                           "runtime.yml")
PLUGINS_DIR = os.path.dirname(os.path.realpath(keeper_secrets_manager_ansible.plugins.__file__))
VAULT_PASSWORD = "keeper-update-folder-test-only"

# Infrastructure (shared) holds every folder. Frankfurt is two levels down: Staging > EU > Frankfurt.
FOLDERS = [
    {"uid": "SHARED_UID", "name": "Infrastructure", "parent": None},
    {"uid": "FOLDER_UID", "name": "Staging", "parent": "SHARED_UID"},
    {"uid": "SIBLING_UID", "name": "Databases", "parent": "SHARED_UID"},
    {"uid": "MIDDLE_UID", "name": "EU", "parent": "FOLDER_UID"},
    {"uid": "DEEP_UID", "name": "Frankfurt", "parent": "MIDDLE_UID"},
    {"uid": "REPORTS_UID", "name": "Reports ", "parent": "SHARED_UID"},
    {"uid": "NOTES_UID", "name": "Notes", "parent": "SHARED_UID"},
    {"uid": "YEAR_UID", "name": "2025", "parent": "SHARED_UID"},
    {"uid": "ARCHIVE_UID", "name": "Archive ", "parent": "SHARED_UID"},
    {"uid": "PRODUCTION_UID", "name": "Production", "parent": "SHARED_UID"},
    {"uid": "OLD_UID", "name": "Old", "parent": "SHARED_UID"},
    {"uid": "QUOTE_SIBLING_UID", "name": 'Prod "EU"', "parent": "SHARED_UID"},
    {"uid": "QUOTE_UID", "name": "Older", "parent": "SHARED_UID"},
    {"uid": "VAULT_UID", "name": "Before Vault", "parent": "SHARED_UID"},
    {"uid": "CHECK_UID", "name": "Before Check", "parent": "SHARED_UID"},
]
UID_VARS = {name + "_uid": name.upper() + "_UID" for name in
            ["shared", "folder", "sibling", "middle", "deep", "reports", "notes", "year", "archive", "old", "quote",
             "vault", "check"]}
UID_VARS["missing_uid"] = "MISSING_UID"

UNICODE_NAME = "Frankfurt am Main äöüß 数据 \U0001F512"
NOT_A_STRING = ("The new_folder_name option must be a string, but it is {}. Put quotes around the value, or use the "
                "string filter.")
PADDED = ("Could not update folder: The new_folder_name 'Archive\\n' has leading or trailing whitespace. Remove it. "
          "In YAML, a block scalar (| or >) keeps the newline at its end.")
EXPECTED = {
    "block_scalar": PADDED,
    "not_found": "Could not update folder: The folder MISSING_UID was not found, or it is not shared to this KSM "
                 "application.",
    "misspelled_before": "missing required arguments: new_folder_name; Unsupported parameters for "
                         "(keeper_update_folder) module: new_name. Supported parameters include: ",
    "types": {
        "list": NOT_A_STRING.format("a list"),
        "int": NOT_A_STRING.format("a number (2026)"),
        "octal": NOT_A_STRING.format("a number (8)"),
        "hex": NOT_A_STRING.format("a number (31)"),
        "underscore": NOT_A_STRING.format("a number (1000)"),
        "bool": NOT_A_STRING.format("a boolean (True)"),
        "float": NOT_A_STRING.format("a number (1.1)"),
        "date": NOT_A_STRING.format("a date (2026-09-29)"),
        "datetime": NOT_A_STRING.format("a date and time (2026-09-29 10:00:00)"),
        "dict": NOT_A_STRING.format("a dictionary"),
        "uid": "The folder_uid option must be a string, but it is a number (12345). Put quotes around the value, or "
               "use the string filter.",
    },
}
AFTER = " After the rename, a lookup of this name fails because the name is not unique."
WARNINGS = [
    'The parent of the folder "Infrastructure 2026/Old" (UID OLD_UID) already has a folder named "Production" '
    '(PRODUCTION_UID).' + AFTER,
    'The parent of the folder "Infrastructure 2026/Older" (UID QUOTE_UID) already has a folder named '
    '"Prod \\"EU\\"" (QUOTE_SIBLING_UID).' + AFTER,
]
# Every update that reaches the server, in order.
UPDATES = [
    ("FOLDER_UID", "QA"),
    ("FOLDER_UID", "qa"),
    ("DEEP_UID", UNICODE_NAME),
    ("MIDDLE_UID", "EU/West"),
    ("REPORTS_UID", "Reports"),
    ("NOTES_UID", "Line 1\nLine 2\tEnd"),
    ("YEAR_UID", "2026"),
    ("SIBLING_UID", "2025"),
    ("SHARED_UID", "Infrastructure 2026"),
    ("ARCHIVE_UID", "Archive"),
    ("OLD_UID", "Production"),
    ("QUOTE_UID", 'Prod "EU"'),
    ("VAULT_UID", "Vaulted Name"),
    ("SIBLING_UID", "Data Stores"),
    ("SIBLING_UID", "Databases"),
]


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
    fd, password_file = tempfile.mkstemp(prefix="ksm_target_vault_", suffix=".txt")
    with os.fdopen(fd, "w") as fh:
        fh.write(VAULT_PASSWORD + "\n")
    variables = dict(UID_VARS, expected=EXPECTED)
    # keeper_secrets_manager_ansible keeps the AnsibleError class and the Display of its first import. A config error
    # from a later run recurses in __str__ on ansible-core 2.19+, and a warning goes to the old Display instead of the
    # worker's output. Bind the classes of this run, as in production.
    try:
        with server.patch(), _environment("ANSIBLE_VAULT_PASSWORD_FILE", password_file), _collection_path():
            # Imported after the collections path is set: an import of ansible.utils.display reads that path.
            errors = importlib.import_module("ansible.errors")
            display = importlib.import_module("ansible.utils.display").Display()
            with patch("keeper_secrets_manager_ansible.AnsibleError", errors.AnsibleError), \
                    patch("keeper_secrets_manager_ansible.display", display):
                recap, out, err = AnsibleTestFramework(playbook=TARGET, vars=variables).run()
        yield server, recap, out, err
    finally:
        os.remove(password_file)
        server.cleanup()
        _unload_ansible()


def test_playbook_passes(run):
    _, recap, out, err = run
    summary = "\n".join(l for l in (out + err).splitlines() if "fatal:" in l or "[ERROR]" in l or "FAILED" in l)
    expected = {"ok": 45, "changed": 11, "failed": 0, "unreachable": 0, "skipped": 0, "rescued": 1, "ignored": 18}
    assert {k: recap.get(k) for k in expected} == expected, summary


def test_the_server_got_only_the_expected_updates(run):
    server, _, _, _ = run
    # Check mode, the failed tasks, and the bad input sent nothing.
    assert [(c["folder_uid"], c["folder_name"]) for c in server.calls("update_folder")] == UPDATES
    assert all(isinstance(c["folder_name"], str) for c in server.calls("update_folder"))


def test_what_the_vault_holds_afterwards(run):
    server, _, _, _ = run
    names = {f["uid"]: f["name"] for f in server.folders()}
    changes = dict(UPDATES)
    assert names == {f["uid"]: changes.get(f["uid"], f["name"]) for f in FOLDERS}


def test_the_sibling_warnings_are_shown(run):
    _, _, out, err = run
    output = " ".join((out + err).split())
    for warning in WARNINGS:
        assert "[WARNING]: " + warning in output
