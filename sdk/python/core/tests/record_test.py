import unittest
import tempfile
import json
import os

from keeper_secrets_manager_core.storage import FileKeyValueStorage
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core import mock


class RecordTest(unittest.TestCase):

    def setUp(self):

        self.orig_working_dir = os.getcwd()

    def tearDown(self):

        os.chdir(self.orig_working_dir)

    def test_the_login_record_password(self):

        """ If the record type is login, the password will be placed in the instance attribute.
        """

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(
                    json.dumps({
                        "hostname": "fake.keepersecurity.com",
                        "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw=",
                        "clientId": "Ae3589ktgynN6vvFtBwlsAbf0fHhXCcf7JqtKXK/3UCE"
                                    "LujQuYuXvFFP08d2rb4aQ5Z4ozgD2yek9sjbWj7YoQ==",
                        "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
                        "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9d"
                                        "jH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbE"
                                        "T6joq0xCjhKMhHQFaHYI"
                    })
                )
                fh.seek(0)
                secrets_manager = SecretsManager(config=FileKeyValueStorage(config_file_location=fh.name))

                # A good record.
                # 'fields': [...{'type': 'password', 'value': ['My Password']}...]
                good_res = mock.Response()
                good = good_res.add_record(title="Good Record", record_type='login')
                good.field("login", "My Login")
                good.field("password", "My Password")

                # A bad record. This would be like if someone removed a password text from an existing field.
                # 'fields': [...{'type': 'password', 'value': []}...]
                bad_res = mock.Response()
                bad = bad_res.add_record(title="Bad Record", record_type='login')
                bad.field("login", "My Login")
                bad.field("password", [])

                # A ugly record. The application didn't even add the field. We need to set flags to prune empty fields.
                # 'fields': [...]
                ugly_res = mock.Response(flags={"prune_empty_fields": True})
                ugly = ugly_res.add_record(title="Ugly Record", record_type='login')
                ugly.field("login", "My Login")
                ugly.field("password", []) # this will be removed from the fields array.

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(good_res)
                res_queue.add_response(bad_res)
                res_queue.add_response(ugly_res)

                records = secrets_manager.get_secrets()
                self.assertEqual(1, len(records), "didn't get 1 record for the good")
                self.assertEqual("My Password", records[0].password, "did not get correct password for the good")

                records = secrets_manager.get_secrets()
                self.assertEqual(1, len(records), "didn't get 1 record for the bad")
                self.assertIsNone(records[0].password, "password is defined for the bad")

                records = secrets_manager.get_secrets()
                self.assertEqual(1, len(records), "didn't get 1 record for the ugly")
                self.assertIsNone(records[0].password, "password is defined for the ugly")
        finally:
            try: os.unlink(fh.name)
            except Exception: pass
