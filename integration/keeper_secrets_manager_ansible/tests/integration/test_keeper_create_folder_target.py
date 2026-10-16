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

TARGET = os.path.join(os.path.dirname(os.path.realpath(__file__)), "targets", "keeper_create_folder", "playbook.yml")
COMPONENT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
RUNTIME_YML = os.path.join(COMPONENT_DIR, "ansible_galaxy", "keepersecurity", "keeper_secrets_manager", "meta",
                           "runtime.yml")
PLUGINS_DIR = os.path.dirname(os.path.realpath(keeper_secrets_manager_ansible.plugins.__file__))

FOLDERS = [
    {"uid": "SHARED_UID", "name": "Infrastructure", "parent": None},
    {"uid": "DATABASES_UID", "name": "Databases", "parent": "SHARED_UID"},
    {"uid": "PRODUCTION_UID", "name": "Production", "parent": "DATABASES_UID"},
]
UID_VARS = {name + "_uid": name.upper() + "_UID" for name in ["shared", "databases", "production"]}
EXPECTED = {
    "no_name": "The folder_name is blank. keeper_create_folder requires this value to be set.",
    "no_shared": "The shared_folder_uid is blank. keeper_create_folder requires this value to be set.",
    "no_such_shared": "Could not create folder: Cannot create folder: ",
}
# Every create that reaches the server: (name, shared folder, parent in the request). A folder directly in a shared
# folder has no parent in the request.
CREATES = [
    ("Staging", "SHARED_UID", None),
    ("Nested", "SHARED_UID", "DATABASES_UID"),
    ("Deeper", "SHARED_UID", "PRODUCTION_UID"),
    ('Say "hi"', "SHARED_UID", None),
    ("Données 数据库 🔐", "SHARED_UID", None),
    ("Prod/EU", "SHARED_UID", None),
    ("Group Defaults", "SHARED_UID", None),
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
    expected = {"ok": 19, "changed": 5, "failed": 0, "unreachable": 0, "skipped": 0, "rescued": 1, "ignored": 3}
    assert {k: recap.get(k) for k in expected} == expected, summary


def test_the_server_got_only_the_expected_creates(run):
    server, _, _, _ = run
    # Existing folders, check mode, and the failed tasks sent no create.
    sent = [(c["folder_name"], c["shared_folder_uid"], c["parent_uid"]) for c in server.calls("create_folder")]
    assert sent == CREATES
    assert {c["path"] for c in server.calls()} <= {"get_folders", "create_folder"}


def test_the_folders_the_vault_holds_afterwards(run):
    server, _, _, _ = run
    created = [(f["name"], f["parent"]) for f in server.folders() if f["uid"] not in {x["uid"] for x in FOLDERS}]
    assert created == [(name, parent or shared) for name, shared, parent in CREATES]
