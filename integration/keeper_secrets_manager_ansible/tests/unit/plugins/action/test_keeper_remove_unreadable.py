import logging
from unittest.mock import patch

import pytest
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.dto.dtos import SecretsManagerResponse
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from ....unreadable_record_server import FAULTS, SECRET, UnreadableRecordServer
from .test_keeper_remove import NOT_FOUND, TITLE, UID, rec, removed

PLUGIN = "keeper_remove"


def bad_record(uid):
    return {"r": {"recordUid": uid, "data": SECRET}, "err": SECRET}


def bad_folder(records=None):
    return {"f": {"folderUid": "FOLDER_UID", "records": records, "data": SECRET}, "err": SECRET}


CASES = [
    pytest.param("uid", [], [bad_record(UID)], [], "unreadable", id="target_record"),
    pytest.param("uid", [], [], [bad_folder([{"recordUid": UID}])], "unreadable", id="target_in_bad_folder"),
    pytest.param("uid", [rec()], [bad_record(UID)], [], "unreadable", id="target_also_returned_readable"),
    pytest.param("title", [], [bad_record("OTHER_UID")], [], "uniqueness", id="title_absence_is_uncertain"),
    pytest.param("title", [rec()], [bad_record("OTHER_UID")], [], "uniqueness", id="title_uniqueness_is_uncertain"),
    pytest.param("title", [rec()], [], [bad_folder()], "uniqueness", id="title_with_unknown_folder_records"),
    pytest.param("title", [rec()], [], [bad_folder([])], "removed", id="title_with_known_empty_folder"),
    pytest.param("title", [], [], [bad_folder([])], "missing", id="absent_title_with_known_empty_folder"),
    pytest.param("uid", [], [bad_record(None)], [], "cannot confirm", id="unknown_record_uid"),
    pytest.param("uid", [], [], [bad_folder()], "cannot confirm", id="unknown_folder_records"),
    pytest.param("uid", [], [bad_record("OTHER_UID")], [], "missing", id="unrelated_bad_record"),
    pytest.param("uid", [], [], [bad_folder([{"recordUid": "OTHER_UID"}])], "missing", id="unrelated_bad_folder"),
    pytest.param("uid", [rec()], [bad_record("OTHER_UID")], [], "removed", id="readable_uid_bad_record"),
    pytest.param("uid", [rec()], [], [bad_folder()], "removed", id="readable_uid_unknown_folder"),
]


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("selector,records,bad_records,bad_folders,outcome", CASES)
def test_lookup_errors_never_become_successful_absence_or_uncertain_deletion(
        make_sdk, run_plugin, selector, records, bad_records, bad_folders, outcome, check_mode):
    sdk = make_sdk([])
    response = SecretsManagerResponse()
    response.records, response.bad_records, response.bad_folders = records, bad_records, bad_folders
    sdk.client.get_secrets.return_value = response
    sdk.client.delete_secret.return_value = [{"recordUid": UID, "responseCode": "ok"}]
    result = run_plugin(sdk, {selector: UID if selector == "uid" else TITLE}, check_mode=check_mode)
    if outcome in ("missing", "removed"):
        assert result == (NOT_FOUND if outcome == "missing" else removed())
    else:
        assert result["failed"] is True and result["changed"] is False
        assert outcome in result["msg"].lower()
    assert SECRET not in str(result)
    sdk.client.get_secrets.assert_called_once_with(*(([UID],) if selector == "uid" else ()), full_response=True)
    assert sdk.client.delete_secret.call_count == int(outcome == "removed" and not check_mode)


@pytest.mark.parametrize("read_fails", [False, True])
def test_sdk_skip_errors_are_hidden_and_logger_filters_are_restored(
        make_sdk, run_plugin, caplog, monkeypatch, read_fails):
    logger = logging.getLogger("ksm")
    monkeypatch.setattr(logger, "disabled", False)
    caplog.set_level(logging.ERROR, logger="ksm")
    filters = list(logger.filters)
    sdk = make_sdk([])

    def read(*args, **kwargs):
        for kind in ("Record", "Folder"):
            logger.error("%s %s skipped due to error: %s", kind, UID, SECRET)
        if read_fails:
            raise ConnectionError("offline")
        response = SecretsManagerResponse()
        response.bad_records = [bad_record(UID)]
        return response

    sdk.client.get_secrets.side_effect = read
    result = run_plugin(sdk, {"uid": UID})
    assert result["failed"] is True and result["changed"] is False
    assert SECRET not in str(result) + caplog.text
    assert logger.filters == filters
    sdk.client.delete_secret.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("fault,selected", [(fault, UID) for fault in FAULTS] + [
    (fault, selected) for fault in ("attachment", "folder_key") for selected in ("OTHER_UID", "MISSING_UID")
] + [("folder_peer", "UNREADABLE_PEER")])
def test_real_sdk_errors_preserve_unreadable_readable_and_absent_uid_behavior(
        make_sdk, run_plugin, fault, selected, check_mode, caplog):
    server = UnreadableRecordServer(fault)
    sdk = make_sdk([])
    sdk.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()))
    try:
        with server.patch(), patch.object(sdk.client, "delete_secret", wraps=sdk.client.delete_secret) as delete:
            with patch.object(sdk.client.logger, "disabled", True):
                response = sdk.client.get_secrets([UID], full_response=True)
            readable_uids = [record.uid for record in response.records]
            bad_record_uids = [error["r"]["recordUid"] for error in response.bad_records]
            bad_folder_uids = [error["f"]["folderUid"] for error in response.bad_folders]
            raw_records = [error["r"] for error in response.bad_records]
            raw_records += [record for error in response.bad_folders for record in error["f"]["records"]]
            unreadable_uids = [record["recordUid"] for record in raw_records]
            # SDK 17.3.0 omits the folder; SDK 18.0.0 keeps its readable records.
            if fault == "folder_peer" and not response.bad_folders:
                assert readable_uids == [UID, "OTHER_UID"]
                assert bad_record_uids == ["UNREADABLE_PEER"]
                assert unreadable_uids == ["UNREADABLE_PEER"]
            else:
                assert readable_uids == ["OTHER_UID"]
                assert UID in unreadable_uids
                if fault in ("folder_key", "folder_peer"):
                    assert not bad_record_uids and bad_folder_uids == ["DAMAGED_FOLDER"]
                    assert unreadable_uids == ([UID, "UNREADABLE_PEER"] if fault == "folder_peer" else [UID])
                else:
                    assert bad_record_uids == [UID] and not bad_folder_uids
            can_delete = selected == "OTHER_UID" or (selected == UID and UID in readable_uids)
            caplog.clear()
            with patch.object(sdk.client.logger, "disabled", False), \
                    caplog.at_level("WARNING", logger=sdk.client.logger.name):
                result = run_plugin(sdk, {"uid": selected}, check_mode=check_mode)
            if selected in unreadable_uids:
                assert result["failed"] is True and result["changed"] is False
                assert "unreadable" in result["msg"] and selected in result["msg"]
            else:
                assert result == (NOT_FOUND if selected == "MISSING_UID" else
                                  removed(selected, TITLE if selected == UID else "Keep Me"))
            assert SECRET not in str(result) + caplog.text
            assert "UNREADABLE_PEER" not in caplog.text
            if selected != "UNREADABLE_PEER":
                assert "UNREADABLE_PEER" not in str(result)
            assert delete.call_count == int(can_delete and not check_mode)
            if can_delete and not check_mode:
                delete.assert_called_once_with([selected])
        assert [call["record_uids"] for call in server.calls("delete_secret")] == (
            [[selected]] if can_delete and not check_mode else [])
        assert [record["uid"] for record in server.records()] == [
            uid for uid in (UID, "OTHER_UID") if not (can_delete and not check_mode and uid == selected)]
    finally:
        server.cleanup()
