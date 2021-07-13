import unittest
import tempfile
import json
import os

from keepercommandersm.exceptions import KeeperError
from keepercommandersm.storage import FileKeyValueStorage, InMemoryKeyValueStorage
from keepercommandersm import Commander
from keepercommandersm.configkeys import ConfigKeys
from keepercommandersm import mock


class SmokeTest(unittest.TestCase):

    def setUp(self):

        self.orig_working_dir = os.getcwd()

    def tearDown(self):

        os.chdir(self.orig_working_dir)

    def test_the_works(self):

        """ Perform a simple get_secrets

        This test is mocked to return 3 record (2 records, 1 folder with a record)

        """

        with tempfile.NamedTemporaryFile("w") as fh:
            fh.write(
                json.dumps({
                    "server": "fake.keepersecurity.com",
                    "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
                    "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26"
                                "C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
                    "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
                    "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9d"
                                  "jH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbE"
                                  "T6joq0xCjhKMhHQFaHYI"
                })
            )
            fh.seek(0)
            c = Commander(config=FileKeyValueStorage(config_file_location=fh.name))

            # --------------------------
            # Add three records, 2 outside a folder, 1 inside folder

            res_1 = mock.Response()

            one = res_1.add_record(title="My Record 1")
            one.field("login", "My Login 1")
            one.field("password", "My Password 1")
            one.custom_field("My Custom 1", "custom1")

            # The frontend allows for custom field to not have unique names :(. The best way we
            # can handle this is to set label and field type.
            one.custom_field("My Custom 2", "custom2")
            one.custom_field("My Custom 2", "my secret", field_type='secret')

            two = res_1.add_record(title="My Record 2")
            two.field("login", "My Login 2")
            two.field("password", "My Password 2")
            two.add_file("My File 1")
            two.add_file("My File 2")

            folder = res_1.add_folder()
            three = folder.add_record(title="My Record 3")
            three.field("login", "My Login 3")
            three.field("password", "My Password 3")

            # --------------------------

            res_2 = mock.Response()

            # Use the existing first record of res_1
            res_2.add_record(record=one)

            # --------------------------

            res_queue = mock.ResponseQueue(client=c)

            # All records
            res_queue.add_response(res_1)
            # Single record
            res_queue.add_response(res_2)
            # Save response
            res_queue.add_response(mock.Response(content=""))

            # --------------------------
            # DO THE WORKS

            records = c.get_secrets()
            self.assertEqual(len(records), 3, "didn't get 3 records")

            records = c.get_secrets([one.uid])
            self.assertEqual(len(records), 1, "didn't get 1 records")
            record = records[0]

            # Test field gets
            login = record.field("login", single=True)
            self.assertEqual(login, "My Login 1", "didn't get the correct login")
            login_values = record.field("login")
            self.assertEqual(len(login_values), 1, "didn't find only 1 login")
            self.assertEqual(login_values[0], "My Login 1", "didn't get the correct login in array")

            # Test custom field gets
            custom = record.custom_field("My Custom 1", single=True)
            self.assertEqual(custom, "custom1", "didn't get the correct My Custom 1 value")
            custom = record.custom_field("My Custom 2", field_type='text')
            self.assertEqual(custom[0], "custom2", "didn't get the correct My Custom 2/text value")
            custom = record.custom_field("My Custom 2", field_type='secret')
            self.assertEqual(custom[0], "my secret", "didn't get the correct My Custom 2/secret value")

            # Test field sets
            record.field("login", value="ABC")
            self.assertEqual(record.field("login", single=True), "ABC", "didn't get the correct login for str")
            record.field("login", value=["XYZ"])
            self.assertEqual(record.field("login", single=True), "XYZ", "didn't get the correct login for array")

            # Test custom field sets
            record.custom_field("My Custom 1", "NEW VALUE")
            custom = record.custom_field("My Custom 1", single=True)
            self.assertEqual(custom, "NEW VALUE", "didn't get the correct My Custom 1 value after set")

            # SAVE THE RECORD

            c.save(record)

            # Take the save record and queue it back up as a response.
            saved_res = mock.Response()
            saved_res.add_record(keeper_record=record)
            res_queue.add_response(saved_res)

            records = c.get_secrets([record.uid])
            self.assertEqual(len(records), 1, "didn't get 1 records")
            record = records[0]
            custom = record.custom_field("My Custom 1", single=True)
            self.assertEqual(custom, "NEW VALUE", "didn't get the correct My Custom 1 value after write")

    def test_403_signature_error(self):

        c = Commander(config=InMemoryKeyValueStorage({
            "server": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        res_queue = mock.ResponseQueue(client=c)

        # Make the error message
        error_json = {
            "path": "https://fake.keepersecurity.com/api/rest/sm/v1/get_secret, POST, python-requests/2.25.1",
            "additional_info": "",
            "location": "default exception manager - api validation exception",
            "error": "access_denied",
            "message": "Signature is invalid"
        }

        res = mock.Response(content=json.dumps(error_json).encode(), status_code=403)
        res_queue.add_response(res)

        try:
            c.get_secrets()
        except KeeperError as err:
            self.assertRegex(err.message, r'Signature is invalid', 'did not get correct error message')


    def test_verify_ssl_certs(self):

        config = InMemoryKeyValueStorage()
        config.set(ConfigKeys.KEY_CLIENT_KEY, 'ABC123')

        os.environ.pop("KSM_SKIP_VERIFY", None)
        c = Commander(config=config)
        self.assertEqual(c.verify_ssl_certs, True, "verify_ssl_certs is not true on 'no args; instance")

        os.environ.pop("KSM_SKIP_VERIFY", None)
        c = Commander(config=config, verify_ssl_certs=True)
        self.assertEqual(c.verify_ssl_certs, True, "verify_ssl_certs is not true on param instance")

        os.environ.pop("KSM_SKIP_VERIFY", None)
        c = Commander(config=config, verify_ssl_certs=False)
        self.assertEqual(c.verify_ssl_certs, False, "verify_ssl_certs is not false on param instance")

        os.environ["KSM_SKIP_VERIFY"] = "FALSE"
        c = Commander(config=config)
        self.assertEqual(c.verify_ssl_certs, True, "verify_ssl_certs is not false on env set (FALSE)")

        os.environ["KSM_SKIP_VERIFY"] = "NO"
        c = Commander(config=config)
        self.assertEqual(c.verify_ssl_certs, True, "verify_ssl_certs is not false on env set (NO)")

        os.environ["KSM_SKIP_VERIFY"] = "True"
        c = Commander(config=config)
        self.assertEqual(c.verify_ssl_certs, False, "verify_ssl_certs is not true on env set (True)")