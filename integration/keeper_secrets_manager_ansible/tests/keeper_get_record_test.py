import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from keeper_secrets_manager_core.mock import Record, Response
from keeper_secrets_manager_core.dto.dtos import SecretsManagerResponse

from keeper_secrets_manager_ansible import KeeperAnsible
from .ansible_test_framework import AnsibleTestFramework


mock_response = Response()
mock_record = Record(title="Record 1", record_type="login")
mock_record.field("login", "MYLOGIN")
mock_record.field("password", "MYPASSWORD")
mock_record.field("text", "TEXT", "Text Label")
mock_record.field("phone", [
    {
        "number": "15551234",
        "type": "Home"
    },
    {
        "number": "15557890",
        "type": "Work"
    }
])
mock_record.field("fileRef", ["XXXXX", "YYYYY"])
mock_record.custom_field("C1","CUSTOM 1", field_type="text")
mock_record.custom_field("D1", "DUP 1", field_type="text")
mock_record.custom_field("D1", "DUP 2", field_type="text")
mock_record.custom_field("This! **I$** A Bad Label...", "BAD", field_type="text")
mock_record.custom_field("  This! **I$** A Bad Label...", "BAD 2", field_type="text")
mock_response.add_record(record=mock_record)


@pytest.mark.parametrize("playbook, expected_ok", [
    ("keeper_get_record.yml", 8),
    ("keeper_get_record_cache.yml", 7),
])
def test_keeper_get_record(playbook, expected_ok):
    with tempfile.TemporaryDirectory() as temp_dir:
        result, out, err = AnsibleTestFramework(
            playbook=playbook,
            vars={"tmp_dir": temp_dir, "uid": mock_record.uid, "title": mock_record.title},
            mock_responses=[mock_response],
        ).run()
    assert result["ok"] == expected_ok, out + err
    assert result["failed"] == 0, out + err
    assert result["changed"] == 0, out + err
    if playbook == "keeper_get_record_cache.yml":
        assert "MYPASSWORD" in out


@pytest.mark.parametrize("selector, attr, missing", [("uids", "uid", "MISSING_UID"), ("titles", "title", "Missing Title")])
@pytest.mark.parametrize("partial", [False, True], ids=["all_missing", "partial_selection"])
@pytest.mark.parametrize("allow_missing", [False, True], ids=["strict", "allow_missing"])
def test_record_selection_completeness(selector, attr, missing, partial, allow_missing):
    record = SimpleNamespace(uid="FOUND_UID", title="Found Title")
    keeper = object.__new__(KeeperAnsible)
    keeper.client = MagicMock()
    response = SecretsManagerResponse()
    response.records = [record] if partial else []
    keeper.client.get_secrets.return_value = response if allow_missing else response.records
    selected = ([getattr(record, attr)] if partial else []) + [missing]
    kwargs = {selector: selected, "allow_missing": allow_missing}
    if allow_missing:
        assert keeper.get_records_from_vault(**kwargs) == ([record] if partial else [])
    else:
        with pytest.raises(Exception) as caught:
            keeper.get_records_from_vault(**kwargs)
        assert caught.value.args[0] == "The following record {}(s) could not be found: {!r}".format(attr, [missing])
    keeper.client.get_secrets.assert_called_once_with(
        *((selected,) if selector == "uids" else ()), **({"full_response": True} if allow_missing else {}))
