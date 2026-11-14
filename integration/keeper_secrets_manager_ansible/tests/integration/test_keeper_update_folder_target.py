import os

import pytest

from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from ._helpers import run_target
from ..folder_fake_server import FakeKeeperServer

TARGET = os.path.join(os.path.dirname(os.path.realpath(__file__)), "targets", "keeper_update_folder", "playbook.yml")
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
SHARED_REFUSED = "Error: access_denied, message=Folder SHARED_UID is not editable"
EXPECTED = {
    "block_scalar": PADDED,
    "shared_refused": ('Could not update folder: Cannot rename the folder "Infrastructure" (UID SHARED_UID): '
                       + SHARED_REFUSED),
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
WARNINGS = [
    "A sibling folder already has the requested name. After the rename, a lookup of this name fails because "
    "the name is not unique.",
]
# Every accepted update, in order.
UPDATES = [
    ("FOLDER_UID", "QA"),
    ("FOLDER_UID", "qa"),
    ("DEEP_UID", UNICODE_NAME),
    ("MIDDLE_UID", "EU/West"),
    ("REPORTS_UID", "Reports"),
    ("NOTES_UID", "Line 1\nLine 2\tEnd"),
    ("YEAR_UID", "2026"),
    ("SIBLING_UID", "2025"),
    ("ARCHIVE_UID", "Archive"),
    ("OLD_UID", "Production"),
    ("QUOTE_UID", 'Prod "EU"'),
    ("VAULT_UID", "Vaulted Name"),
    ("SIBLING_UID", "Data Stores"),
    ("SIBLING_UID", "Databases"),
]


@pytest.fixture(scope="module")
def run():
    server = FakeKeeperServer(folders=FOLDERS)
    variables = dict(UID_VARS, expected=EXPECTED)
    with run_target(server, TARGET, variables, collection=True, vault_password=VAULT_PASSWORD) as result:
        yield (server,) + result


def test_playbook_passes(run):
    _, recap, out, err = run
    summary = "\n".join(l for l in (out + err).splitlines() if "fatal:" in l or "[ERROR]" in l or "FAILED" in l)
    expected = {"ok": 45, "changed": 10, "failed": 0, "unreachable": 0, "skipped": 0, "rescued": 1, "ignored": 19}
    assert {k: recap.get(k) for k in expected} == expected, summary


def test_the_server_got_only_the_expected_updates(run):
    server, _, _, _ = run
    updates = server.calls("update_folder")
    # Older SDKs send the shared folder rename to the server. Newer SDKs refuse it before the request.
    assert [(c["folder_uid"], c["folder_name"]) for c in updates if c["folder_uid"] != "SHARED_UID"] == UPDATES
    assert [(c["folder_uid"], c["folder_name"]) for c in updates if c["folder_uid"] == "SHARED_UID"] in (
        [], [("SHARED_UID", "Infrastructure 2026")])
    assert all(isinstance(c["folder_name"], str) for c in updates)


def test_the_fake_server_refuses_a_shared_folder_rename():
    server = FakeKeeperServer(folders=[FOLDERS[0]])
    client = SecretsManager(config=InMemoryKeyValueStorage(config=mock.MockConfig.make_base64()))
    try:
        with server.patch():
            folder = client.get_folders()[0]
            payload = SecretsManager.prepare_update_folder_payload(
                client.config, folder.folder_uid, "Infrastructure 2026", folder.folder_key)
            with pytest.raises(KeeperError) as refusal:
                server.handle(client, "update_folder", payload)
        assert str(refusal.value) == SHARED_REFUSED
        assert server.calls("update_folder") == [
            {"path": "update_folder", "folder_uid": "SHARED_UID", "folder_name": "Infrastructure 2026"}]
        assert server.folders() == [FOLDERS[0]]
    finally:
        server.cleanup()


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
