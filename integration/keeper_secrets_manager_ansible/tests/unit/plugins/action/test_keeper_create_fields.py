import json
import sys
from unittest.mock import patch

import pytest
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.dto.dtos import RecordCreate
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from keeper_secrets_manager_ansible import KeeperAnsible


PLUGIN = "keeper_create"
SHARED_UID = "SHARED_UID"
OMITTED = object()
RECORD_TYPES = {
    "checkbox": "pamDatabase",
    "text": "bankCard",
    "date": "encryptedNotes",
    "name": "birthCertificate",
    "address": "address",
}


@pytest.fixture(scope="module", autouse=True)
def unload_create_plugin():
    # Ansible is unloaded between modules; do not retain its old exception class in the action.
    yield
    sys.modules.pop("keeper_secrets_manager_ansible.plugins.action." + PLUGIN, None)


@pytest.fixture
def sdk(make_sdk, folder):
    sdk = make_sdk([folder(SHARED_UID, "", "Shared Folder")])
    sdk.client.config = InMemoryKeyValueStorage(mock.MockConfig.make_base64())
    sdk.client.create_secret_with_options.return_value = "NEW_UID"
    sdk.client.prepare_create_payload.side_effect = SecretsManager.prepare_create_payload
    return sdk


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("section", ["fields", "custom_fields"], ids=["standard", "custom"])
@pytest.mark.parametrize("field_type, value, expected", [
    pytest.param("checkbox", False, [False], id="checkbox_false"),
    pytest.param("text", 0, [0], id="text_zero"),
    pytest.param("date", 0, [0], id="date_zero"),
    pytest.param("text", OMITTED, [], id="omitted"),
    pytest.param("text", None, [], id="null"),
    pytest.param("text", "", [], id="empty_string"),
    pytest.param("name", [], [], id="empty_name"),
    pytest.param("address", [], [], id="empty_address"),
    pytest.param("name", [{"first": "Example"}], [{"first": "Example"}], id="populated_complex_list"),
])
def test_field_values_reach_the_real_helper_payload(sdk, run_plugin, check_mode, section, field_type, value, expected):
    field = {"type": field_type}
    if value is not OMITTED:
        field["value"] = value
    elif section == "custom_fields":
        expected = ["text"]
    args = {
        "shared_folder_uid": SHARED_UID,
        "record_type": RECORD_TYPES[field_type],
        "title": "Field Value Test",
        section: [field],
    }
    original_args = json.dumps(args)
    with patch.object(KeeperAnsible, "create_record", autospec=True,
                      side_effect=KeeperAnsible.create_record) as create_record:
        result = run_plugin(sdk, args, check_mode=check_mode)
    assert result == {"changed": True, "record_uid": None if check_mode else "NEW_UID"}
    create_record.assert_called_once()
    record = create_record.call_args.args[1]
    assert isinstance(record, RecordCreate)
    assert create_record.call_args.kwargs == {
        "shared_folder_uid": SHARED_UID, "subfolder_uid": None, "check_mode": check_mode,
    }
    payload = json.loads(record.to_json())
    assert (payload["type"], payload["title"]) == (args["record_type"], args["title"])
    fields = payload["fields" if section == "fields" else "custom"]
    matches = [item for item in fields if item["type"] == field_type]
    assert len(matches) == 1
    assert json.dumps(matches[0]["value"]) == json.dumps(expected)
    assert json.dumps(args) == original_args
    if check_mode:
        sdk.client.create_secret_with_options.assert_not_called()
        sdk.client.prepare_create_payload.assert_called_once()
        assert json.loads(sdk.client.prepare_create_payload.call_args.args[2]) == payload
    else:
        sdk.client.create_secret_with_options.assert_called_once()
        assert sdk.client.create_secret_with_options.call_args.args[1] is record
        sdk.client.prepare_create_payload.assert_not_called()
    sdk.client._post_query.assert_not_called()
