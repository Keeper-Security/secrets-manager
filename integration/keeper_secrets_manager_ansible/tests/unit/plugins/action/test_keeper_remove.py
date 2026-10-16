import types
from unittest.mock import patch

import pytest

from keeper_secrets_manager_ansible import KeeperAnsible

PLUGIN = "keeper_remove"

UID, TITLE = "RECORD_UID", "Record 1"
GROUP = "group/keepersecurity.keeper_secrets_manager.keeper"
DENIED = "User does not have permission to delete this record"
NULL_MESSAGE = "The {} option is null. Give it a value, or leave the option out of the task."


def rec(uid=UID, title=TITLE):
    return types.SimpleNamespace(uid=uid, title=title)


def ok(uid=UID):
    return {"recordUid": uid, "responseCode": "ok"}


def failure(msg):
    return {"failed": True, "changed": False, "msg": msg}


def removed(uid=UID, title=TITLE):
    return {"changed": True, "record_uid": uid, "record_title": title}


CONFIRMED = object()
LABEL = '"Record 1" (UID RECORD_UID)'
NOT_DELETED = "Could not remove record: The Keeper server did not delete record " + LABEL + ". It returned {}."
NOT_CONFIRMED = "Could not remove record: The Keeper server did not confirm the delete of record " + LABEL + "."


@pytest.fixture
def vault(make_sdk):
    """A fake SDK with one record, and a delete_secret that confirms the delete unless a response is given."""
    def make(records=None, response=CONFIRMED):
        sdk = make_sdk([])
        sdk.client.get_secrets.return_value = [rec()] if records is None else records
        sdk.client.delete_secret.return_value = [ok()] if response is CONFIRMED else response
        return sdk
    return make


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("args, reads", [
    ({"uid": UID}, [([UID],)]),
    ({"title": TITLE}, [()]),
], ids=["by_uid", "by_title"])
def test_remove_returns_the_record_and_deletes_only_outside_check_mode(vault, run_plugin, args, reads, check_mode):
    sdk = vault([rec(), rec("OTHER_UID", "Keep Me")])
    assert run_plugin(sdk, args, check_mode=check_mode) == removed()
    assert [c.args for c in sdk.client.get_secrets.call_args_list] == [r for r in reads]
    assert [c.args for c in sdk.client.delete_secret.call_args_list] == ([] if check_mode else [([UID],)])


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("records", [[], [rec("OTHER_UID", "Keep Me")]], ids=["empty_vault", "other_record"])
@pytest.mark.parametrize("args", [{"uid": "MISSING_UID"}, {"title": "Missing Title"}], ids=["uid", "title"])
def test_a_missing_record_is_a_no_op(vault, run_plugin, args, records, check_mode):
    sdk = vault(records)
    assert run_plugin(sdk, args, check_mode=check_mode) == {
        "changed": False,
        "msg": "The record was not found, or it is not shared to this KSM application. Nothing was deleted."}
    sdk.client.delete_secret.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_a_duplicate_title_fails_with_every_uid_and_deletes_nothing(vault, run_plugin, check_mode):
    sdk = vault([rec(), rec("TWIN_UID")])
    assert run_plugin(sdk, {"title": TITLE}, check_mode=check_mode) == failure(
        'Could not remove record: Found multiple records for the title "Record 1": RECORD_UID, TWIN_UID. Use a '
        'single UID to select the record to delete.')
    sdk.client.delete_secret.assert_not_called()


# (id, response of delete_secret, message of the failure or None for a confirmed delete)
RESPONSES = [
    ("ok", [ok()], None),
    ("matched_by_uid_not_position", [None, {"recordUid": "OTHER_UID", "responseCode": "access_denied"}, ok()], None),
    ("access_denied_with_message", [{"recordUid": UID, "responseCode": "access_denied", "errorMessage": DENIED}],
     NOT_DELETED.format("access_denied: " + DENIED)),
    ("not_found", [{"recordUid": UID, "responseCode": "not_found"}], NOT_DELETED.format("not_found")),
    ("near_miss_code", [{"recordUid": UID, "responseCode": "OK", "errorMessage": DENIED}],
     NOT_DELETED.format("OK: " + DENIED)),
    ("no_code_keeps_the_message", [{"recordUid": UID, "errorMessage": "The delete was refused"}],
     NOT_DELETED.format("no response code: The delete was refused")),
    ("none", None, NOT_CONFIRMED),
    ("empty_list", [], NOT_CONFIRMED),
    ("empty_dict", {}, NOT_CONFIRMED),
    ("dict_with_records", {"records": []}, NOT_CONFIRMED),
    ("string", "ok", NOT_CONFIRMED),
    ("junk_items", [None, "ok"], NOT_CONFIRMED),
    ("status_without_uid", [{"responseCode": "ok"}], NOT_CONFIRMED),
    ("status_of_another_record", [ok("OTHER_UID")], NOT_CONFIRMED),
    ("two_statuses_for_the_record", [ok(), ok()], NOT_CONFIRMED),
    ("ok_and_denied", [ok(), {"recordUid": UID, "responseCode": "access_denied"}], NOT_CONFIRMED),
]


@pytest.mark.parametrize("case", RESPONSES, ids=[c[0] for c in RESPONSES])
def test_only_an_ok_status_for_the_record_confirms_the_delete(vault, run_plugin, case):
    _, response, message = case
    sdk = vault(response=response)
    result = run_plugin(sdk, {"uid": UID})
    assert result == (removed() if message is None else failure(message))
    sdk.client.delete_secret.assert_called_once_with([UID])


def test_sdk_errors_are_task_failures_not_no_ops(vault, run_plugin):
    sdk = vault()
    sdk.client.get_secrets.side_effect = RuntimeError("Cannot reach Keeper")
    assert run_plugin(sdk, {"uid": UID}) == failure("Could not remove record: Cannot get record: Cannot reach Keeper")
    sdk.client.delete_secret.assert_not_called()

    sdk = vault()
    sdk.client.delete_secret.side_effect = RuntimeError("Connection lost")
    assert run_plugin(sdk, {"uid": UID}) == failure("Could not remove record: Connection lost")


def test_the_cache_option_is_ignored_with_a_warning(vault, run_plugin):
    # A cache can hold a record that is deleted already, or hide a second record with the same title.
    sdk = vault([rec(), rec("TWIN_UID")])
    with patch.object(KeeperAnsible, "decrypt", return_value=[rec()]) as decrypt, \
            patch("keeper_secrets_manager_ansible.display.warning") as warning:
        result = run_plugin(sdk, {"title": TITLE, "cache": "stale-cache"})
    assert result["failed"] is True and "TWIN_UID" in result["msg"]
    decrypt.assert_not_called()
    warning.assert_called_once()
    assert "The cache option of keeper_remove has no effect" in warning.call_args.args[0]
    sdk.client.delete_secret.assert_not_called()


# --- Options ---

BAD_OPTIONS = [
    ("nothing", {}, "keeper_remove requires either uid or title to be set."),
    ("both", {"uid": UID, "title": TITLE}, "parameters are mutually exclusive: uid|title"),
    ("null_uid", {"uid": None}, NULL_MESSAGE.format("uid")),
    ("null_title", {"title": None}, NULL_MESSAGE.format("title")),
    ("blank_uid", {"uid": " "}, "The uid is blank."),
    ("blank_title", {"title": ""}, "The title is blank."),
    ("padded_uid", {"uid": " RECORD_UID "}, "The uid ' RECORD_UID ' has leading or trailing whitespace."),
    ("list_uid", {"uid": [UID]}, "The uid option must be a string, but it is a list. Put quotes around the value, "
                                 "or use the string filter."),
    ("number_uid", {"uid": 123}, "The uid option must be a string, but it is a number (123). Put quotes around the "
                                 "value, or use the string filter."),
    ("dict_cache", {"uid": UID, "cache": {}}, "The cache option must be an encrypted cache string or byte string."),
    ("typo", {"uid": UID, "titel": TITLE}, "Unsupported parameters for (keeper_remove) module: titel. "),
]


@pytest.mark.parametrize("case", BAD_OPTIONS, ids=[c[0] for c in BAD_OPTIONS])
def test_bad_options_fail_before_the_sdk_is_used(vault, run_plugin, case):
    _, args, message = case
    sdk = vault()
    result = run_plugin(sdk, args)
    assert result["failed"] is True and result["changed"] is False
    assert result["msg"].startswith(message), result["msg"]
    assert sdk.inits == 0 and sdk.client.mock_calls == []


def test_a_title_may_have_spaces_and_a_bytes_cache_is_accepted(vault, run_plugin):
    sdk = vault([rec(title=" Spaced ")])
    with patch("keeper_secrets_manager_ansible.display.warning"):
        assert run_plugin(sdk, {"title": " Spaced ", "cache": b"cache"}) == removed(title=" Spaced ")


def test_group_defaults_of_other_modules_are_ignored(vault, run_plugin):
    sdk = vault()
    result = run_plugin(sdk, {"uid": UID, "force": True}, module_defaults=[{GROUP: {"force": True}}])
    assert result == removed()
