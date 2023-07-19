import unittest
from keeper_secrets_manager_core.mock import Record, Response
from .ansible_test_framework import AnsibleTestFramework
import tempfile


class KeeperCacheRecord(unittest.TestCase):

    def test_keeper_cache_records(self):

        mock_response = Response()
        uids = []
        titles = []
        record_10_uid = None
        for index in range(0, 100):

            title = f"Record {index}"
            record = mock_response.add_record(title=title, record_type="login")
            record.field("login", f"MYLOGIN_{index}")
            record.field("password", f"MYPASSWORD_{index}")

            if index == 10:
                record_10_uid = record.uid

            if index < 50:
                uids.append(record.uid)
            else:
                titles.append(title)

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_cache_records.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uids": uids,
                    "titles": titles,
                    "record_10_uid": record_10_uid
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 7, "7 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            assert "MYPASSWORD_10" in out
            assert "MYPASSWORD_75" in out



