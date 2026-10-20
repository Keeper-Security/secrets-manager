from pathlib import Path

import pytest

from ._helpers import run_target
from ..unreadable_record_server import SECRET, UID, UnreadableRecordServer

TARGET = Path(__file__).parent / "targets/keeper_remove_unreadable/playbook.yml"


@pytest.fixture(scope="module", params=["attachment", "folder_key"])
def run(request):
    server = UnreadableRecordServer(request.param, shared_title=True)
    with run_target(server, str(TARGET), {}) as (recap, out, err):
        yield server, recap, out + err


def test_unreadable_uid_and_title_fail_in_normal_and_check_modes_without_deleting(run):
    server, recap, output = run
    expected = {"failed": 0, "unreachable": 0, "changed": 0, "ignored": 1, "ok": 2}
    assert {key: recap.get(key) for key in expected} == expected, output
    assert SECRET not in output
    assert not server.calls("delete_secret")
    assert UID in [record["uid"] for record in server.records()]
