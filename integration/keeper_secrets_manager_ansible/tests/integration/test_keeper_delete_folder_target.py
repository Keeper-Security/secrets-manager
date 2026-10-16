import contextlib
import importlib
import os
import shutil
import sys
import tempfile
from unittest.mock import patch

import pytest
import yaml

import keeper_secrets_manager_ansible.plugins
from ..ansible_test_framework import AnsibleTestFramework
from ..folder_fake_server import FakeKeeperServer

TARGET = os.path.join(os.path.dirname(os.path.realpath(__file__)), "targets", "keeper_delete_folder", "playbook.yml")
COMPONENT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
RUNTIME_YML = os.path.join(COMPONENT_DIR, "ansible_galaxy", "keepersecurity", "keeper_secrets_manager", "meta",
                           "runtime.yml")
PLUGINS_DIR = os.path.dirname(os.path.realpath(keeper_secrets_manager_ansible.plugins.__file__))
VAULT_PASSWORD = "keeper-delete-folder-test-only"

# Infrastructure (shared) holds every folder below. Records sit in Web, Databases, Production, Ledger, and the
# quoted folder; Operations is a second shared folder.
FOLDERS = [
    {"uid": "SHARED_UID", "name": "Infrastructure", "parent": None},
    {"uid": "EMPTY_FOLDER_UID", "name": "Staging", "parent": "SHARED_UID"},
    {"uid": "DRAFT_UID", "name": "Drafts", "parent": "SHARED_UID"},
    {"uid": "TEMP_UID", "name": "Temporary", "parent": "SHARED_UID"},
    {"uid": "SCRATCH_UID", "name": "Scratch", "parent": "SHARED_UID"},
    {"uid": "WEB_UID", "name": "Web", "parent": "SHARED_UID"},
    {"uid": "TREE_UID", "name": "Databases", "parent": "SHARED_UID"},
    {"uid": "TREE_CHILD_UID", "name": "Production", "parent": "TREE_UID"},
    {"uid": "APPS_UID", "name": "Apps", "parent": "SHARED_UID"},
    {"uid": "APPS_CHILD_UID", "name": "Archive", "parent": "APPS_UID"},
    {"uid": "LEDGER_UID", "name": "Ledger", "parent": "SHARED_UID"},
    {"uid": "QUOTED_UID", "name": 'Reports "Q1"\n', "parent": "SHARED_UID"},
]
RECORDS = [{"uid": uid, "title": uid, "folder": "SHARED_UID", "inner": inner} for uid, inner in [
    ("R_WEB", "WEB_UID"), ("R_TREE", "TREE_UID"), ("R_PROD", "TREE_CHILD_UID"), ("R_LEDGER", "LEDGER_UID"),
    ("R_QUOTED", "QUOTED_UID")]]
RECORD_UIDS = sorted(r["uid"] for r in RECORDS)

UID_VARS = {name + "_uid": name.upper() + "_UID" for name in
            ["shared", "draft", "scratch", "web", "tree", "apps", "ledger", "quoted"]}
# The inline !vault value in the playbook encrypts this UID.
UID_VARS["empty_uid"] = "EMPTY_FOLDER_UID"


def _not_empty(label, records, subfolders):
    return ("Could not delete folder: The folder {} is not empty. It contains {} record(s) and {} subfolder(s). Set "
            "force_deletion to true to delete the folder and everything in it.".format(label, records, subfolders))


EXPECTED = {
    "not_found": "The folder DRAFT_UID was not found, or it is not shared to this KSM application. Nothing was "
                 "deleted.",
    "web_not_empty": _not_empty('"Infrastructure/Web" (UID WEB_UID)', 1, 0),
    "tree_not_empty": _not_empty('"Infrastructure/Databases" (UID TREE_UID)', 1, 1),
    "apps_not_empty": _not_empty('"Infrastructure/Apps" (UID APPS_UID)', 0, 1),
    "padded": "Could not delete folder: The folder_uid 'EMPTY_FOLDER_UID ' has leading or trailing whitespace.",
    # A JSON-quoted name: the plugin must not turn \" back into ".
    "quoted": _not_empty(r'"Infrastructure/Reports \"Q1\"\n" (UID QUOTED_UID)', 1, 0),
    "forse_before": "Unsupported parameters for (keeper_delete_folder) module: forse. "
                    "Supported parameters include: ",
    "second_lookup": 'Could not look up folder: No folder named "Temporary" was found in the folder '
                     '"Infrastructure" (UID SHARED_UID).',
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
    server = FakeKeeperServer(folders=FOLDERS, records=RECORDS)
    fd, password_file = tempfile.mkstemp(prefix="ksm_target_vault_", suffix=".txt")
    with os.fdopen(fd, "w") as fh:
        fh.write(VAULT_PASSWORD + "\n")
    variables = dict(UID_VARS, expected=EXPECTED)
    # keeper_secrets_manager_ansible keeps the AnsibleError class of its first import. A config error raised from a
    # later run recurses in __str__ on ansible-core 2.19+, so bind the class of this run, as in production.
    ansible_errors = importlib.import_module("ansible.errors")
    try:
        with server.patch(), patch("keeper_secrets_manager_ansible.AnsibleError", ansible_errors.AnsibleError), \
                _environment("ANSIBLE_VAULT_PASSWORD_FILE", password_file), _collection_path():
            recap, out, err = AnsibleTestFramework(playbook=TARGET, vars=variables).run()
        yield server, recap, out, err
    finally:
        os.remove(password_file)
        server.cleanup()
        _unload_ansible()


def test_playbook_passes(run):
    _, recap, out, err = run
    summary = "\n".join(l for l in (out + err).splitlines() if "fatal:" in l or "[ERROR]" in l or "FAILED" in l)
    expected = {"ok": 32, "changed": 7, "failed": 0, "unreachable": 0, "skipped": 1, "rescued": 1, "ignored": 8}
    assert {k: recap.get(k) for k in expected} == expected, summary


def test_the_server_got_only_the_expected_deletes(run):
    server, _, _, _ = run
    deletes = [(c["folder_uids"], c["force"]) for c in server.calls("delete_folder")]
    # Check mode, the refused deletes, and the bad input sent nothing. A forced delete sent force True, a real bool.
    assert deletes == [(["DRAFT_UID"], False), (["TREE_UID"], True), (["EMPTY_FOLDER_UID"], False),
                       (["TEMP_UID"], False), (["SCRATCH_UID"], False), (["LEDGER_UID"], True)]
    assert all(isinstance(force, bool) for _, force in deletes)


def test_what_is_left_in_the_vault(run):
    server, _, _, _ = run
    gone = {"DRAFT_UID", "TREE_UID", "TREE_CHILD_UID", "EMPTY_FOLDER_UID", "TEMP_UID", "SCRATCH_UID", "LEDGER_UID"}
    assert sorted(f["uid"] for f in server.folders()) == sorted(f["uid"] for f in FOLDERS if f["uid"] not in gone)
    kept = [u for u in RECORD_UIDS if u not in ("R_TREE", "R_PROD", "R_LEDGER")]
    assert sorted(r["uid"] for r in server.records()) == kept


class _PlaybookLoader(yaml.SafeLoader):
    pass


_PlaybookLoader.add_constructor("!vault", lambda loader, node: loader.construct_scalar(node))


def test_the_idempotent_tasks_in_the_playbook_are_the_documented_examples():
    _unload_ansible()
    plugin = importlib.import_module("keeper_secrets_manager_ansible.plugins.action.keeper_delete_folder")
    _unload_ansible()
    examples = yaml.safe_load(plugin.EXAMPLES)
    index = next(i for i, task in enumerate(examples) if "keeper_get_folder" in task)
    lookup, delete = examples[index], examples[index + 1]
    with open(TARGET) as fh:
        tasks = yaml.load(fh, Loader=_PlaybookLoader)[0]["tasks"]
    starts = [i for i, t in enumerate(tasks) if t.get("keeper_get_folder", {}).get("folder_name") == "Temporary"]
    assert len(starts) == 2
    for i in starts:
        assert set(tasks[i]["keeper_get_folder"]) == set(lookup["keeper_get_folder"])
        assert tasks[i]["register"] == lookup["register"]
        assert tasks[i]["failed_when"] == lookup["failed_when"]
        assert tasks[i + 1]["keeper_delete_folder"] == delete["keeper_delete_folder"]
        assert tasks[i + 1]["when"] == delete["when"]
