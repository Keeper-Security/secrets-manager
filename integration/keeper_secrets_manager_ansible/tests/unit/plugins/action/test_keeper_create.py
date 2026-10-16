from unittest.mock import ANY

import pytest
from keeper_secrets_manager_core.dto.dtos import KeeperFolder

# Only the folder options of keeper_create are covered here: shared_folder_uid, subfolder_uid, and the renamed
# folder_uid. The record content is covered by tests/keeper_create_test.py.
PLUGIN = "keeper_create"

SHARED, DB = "SHARED_UID", "DB_UID"
RECORD = {"record_type": "login", "title": "My Record", "generate_password": True,
          "fields": [{"type": "login", "value": "johndoe@localhost"}]}


SHARED_KEY = b"s" * 32


@pytest.fixture
def sdk_for(make_sdk, tree):
    def make():
        # The shared folder has its own key, so a check that takes the key of another folder fails.
        sdk = make_sdk([KeeperFolder(SHARED_KEY, f.folder_uid, f.parent_uid, f.name) if f.folder_uid == SHARED else f
                        for f in tree])
        sdk.client.create_secret_with_options.return_value = "NEW_UID"
        return sdk
    return make


def options_of(sdk):
    sdk.client.create_secret_with_options.assert_called_once()
    options = sdk.client.create_secret_with_options.call_args.args[0]
    return options.folder_uid, options.subfolder_uid


@pytest.mark.parametrize("subfolder, expected", [
    pytest.param(DB, DB, id="subfolder"),
    pytest.param(None, None, id="none"),
    pytest.param("", None, id="empty_string_is_none"),
])
def test_subfolder_uid_reaches_the_create_options(sdk_for, run_plugin, subfolder, expected):
    sdk = sdk_for()
    args = dict(RECORD, shared_folder_uid=SHARED)
    if subfolder is not None:
        args["subfolder_uid"] = subfolder
    assert run_plugin(sdk, args) == {"changed": True, "record_uid": "NEW_UID"}
    assert len(sdk.action_modules) == 1 and sdk.action_modules[0] is not None
    assert options_of(sdk) == (SHARED, expected)
    sdk.client.create_secret.assert_not_called()


@pytest.mark.parametrize("args, message", [
    (dict(RECORD), "The shared_folder_uid is blank. keeper_create requires this value to be set."),
    (dict(RECORD, shared_folder_uid=None),
     "The shared_folder_uid is blank. keeper_create requires this value to be set."),
    (dict(RECORD, shared_folder_uid=SHARED, folder_uid=DB),
     "The folder_uid parameter for keeper_create has been renamed to subfolder_uid. Please update your playbook."),
    (dict(RECORD, shared_folder_uid=SHARED, folder_uid=""),
     "The folder_uid parameter for keeper_create has been renamed to subfolder_uid. Please update your playbook."),
], ids=["no_shared_folder_uid", "null_shared_folder_uid", "stale_folder_uid_key", "empty_stale_folder_uid_key"])
def test_bad_folder_options_raise_before_any_request(sdk_for, run_plugin, args, message):
    sdk = sdk_for()
    with pytest.raises(Exception) as caught:
        run_plugin(sdk, args)
    assert str(caught.value) == message
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("subfolder", [None, DB])
def test_check_mode_prepares_the_payload_for_the_folder_and_creates_nothing(sdk_for, run_plugin, subfolder):
    sdk = sdk_for()
    args = dict(RECORD, shared_folder_uid=SHARED)
    if subfolder:
        args["subfolder_uid"] = subfolder
    assert run_plugin(sdk, args, check_mode=True) == {"changed": True, "record_uid": None}
    sdk.client.create_secret_with_options.assert_not_called()
    sdk.client.prepare_create_payload.assert_called_once_with(sdk.client.config, ANY, ANY, SHARED_KEY)
    options = sdk.client.prepare_create_payload.call_args.args[1]
    assert (options.folder_uid, options.subfolder_uid) == (SHARED, subfolder)


def test_check_mode_needs_the_key_of_the_shared_folder(sdk_for, run_plugin):
    sdk = sdk_for()
    with pytest.raises(Exception) as caught:
        run_plugin(sdk, dict(RECORD, shared_folder_uid="NO_SUCH_UID"), check_mode=True)
    assert str(caught.value) == ("Could not create record: Cannot get create record: Unable to create record - folder "
                                 "key for NO_SUCH_UID not found")


def test_create_error_is_wrapped(sdk_for, run_plugin):
    sdk = sdk_for()
    sdk.client.create_secret_with_options.side_effect = Exception("access denied")
    with pytest.raises(Exception) as caught:
        run_plugin(sdk, dict(RECORD, shared_folder_uid=SHARED))
    assert str(caught.value) == "Could not create record: Cannot get create record: access denied"
