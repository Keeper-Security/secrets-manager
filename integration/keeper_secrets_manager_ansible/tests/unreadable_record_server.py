import base64

import keeper_secrets_manager_core
from keeper_secrets_manager_core.crypto import CryptoUtils

from .folder_fake_server import FakeKeeperServer

UID, TITLE = "RECORD_UID", "Record 1"
SECRET = "SECRET_PAYLOAD_NOT_FOR_DIAGNOSTICS"
FAULTS = ("attachment", "record_data", "folder_key", "folder_peer")
PEER_UID = "UNREADABLE_PEER"


# Core 18.0.0 is the first release that skips one bad record of a shared folder. An older core, such as 17.3.0 from
# PyPI on Python 3.9, hides the whole folder and reports it in bad_folders.
SKIPS_BAD_FOLDER_RECORD = int(keeper_secrets_manager_core.__version__.split(".")[0]) >= 18


def unreadable_uid(fault):
    # With folder_peer and a core that skips the bad peer, only the added peer is unreadable and UID stays readable.
    return PEER_UID if fault == "folder_peer" and SKIPS_BAD_FOLDER_RECORD else UID


def lists_bad_records(fault):
    """True when the core reports the unreadable record in bad_records, False when it reports a bad folder."""
    return fault in ("attachment", "record_data") or (fault == "folder_peer" and SKIPS_BAD_FOLDER_RECORD)


class UnreadableRecordServer(FakeKeeperServer):
    """Real encrypted records, with a bad record or folder that the SDK omits from its readable list."""

    def __init__(self, fault, shared_title=False):
        self.fault = fault
        super().__init__(
            folders=[{"uid": "DAMAGED_FOLDER", "name": "Damaged"}, {"uid": "GOOD_FOLDER", "name": "Readable"}],
            records=[{"uid": UID, "title": TITLE, "folder": "DAMAGED_FOLDER"},
                     {"uid": "OTHER_UID", "title": TITLE if shared_title else "Keep Me", "folder": "GOOD_FOLDER"}])

    def _secrets(self, state, app_key):
        response = super()._secrets(state, app_key)
        folder = response["folders"][0]
        record = folder["records"][0]
        bad = base64.b64encode(SECRET.encode()).decode()
        if self.fault == "folder_key":
            folder["folderKey"] = bad
        elif self.fault == "folder_peer":
            folder["records"].append(dict(record, recordUid=PEER_UID, data=bad))
        else:
            response["records"].append(folder["records"].pop())
            if self.fault == "attachment":
                record["files"] = [{"fileUid": "FILE_UID", "fileKey": bad, "data": bad,
                                    "url": "https://unused.invalid/" + SECRET}]
            else:
                invalid_json = b'{"password": "' + SECRET.encode() + b'"'
                record["data"] = base64.b64encode(CryptoUtils.encrypt_aes(invalid_json, app_key)).decode()
        return response

    def handle(self, sm, path, payload):
        if path != "delete_secret":
            return super().handle(sm, path, payload)
        state = self._load()
        uids = list(payload.recordUids)
        state["calls"].append({"path": path, "record_uids": uids})
        state["records"] = [record for record in state["records"] if record["uid"] not in uids]
        self._save(state)
        return self._json({"records": [{"recordUid": uid, "responseCode": "ok"} for uid in uids]})
