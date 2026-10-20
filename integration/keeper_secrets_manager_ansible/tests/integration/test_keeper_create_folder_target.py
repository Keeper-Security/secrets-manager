import os

import pytest

from ._helpers import run_target
from ..folder_fake_server import FakeKeeperServer

TARGET = os.path.join(os.path.dirname(os.path.realpath(__file__)), "targets", "keeper_create_folder", "playbook.yml")

FOLDERS = [
    {"uid": "SHARED_UID", "name": "Infrastructure", "parent": None},
    {"uid": "DATABASES_UID", "name": "Databases", "parent": "SHARED_UID"},
    {"uid": "PRODUCTION_UID", "name": "Production", "parent": "DATABASES_UID"},
]
UID_VARS = {name + "_uid": name.upper() + "_UID" for name in ["shared", "databases", "production"]}
EXPECTED = {
    "no_name": "missing required arguments: folder_name",
    "no_shared": "missing required arguments: shared_folder_uid",
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


@pytest.fixture(scope="module")
def run():
    server = FakeKeeperServer(folders=FOLDERS)
    variables = dict(UID_VARS, expected=EXPECTED)
    with run_target(server, TARGET, variables, collection=True) as result:
        yield (server,) + result


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
