import unittest
import tempfile
import json
import os

from keepercommandersm.storage import FileKeyValueStorage
from keepercommandersm import Commander
from keepercommandersm import mock


class NotationTest(unittest.TestCase):

    def setUp(self):

        self.orig_working_dir = os.getcwd()

    def tearDown(self):

        os.chdir(self.orig_working_dir)

    def test_get_notation(self):

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
            one.custom_field("My Custom 1", "custom1")
            one.custom_field("My Custom 2", ['one', 'two', 'three'])
            one.custom_field("phone", [
                {"number": "555-5555555", "ext": "55"},
                {"number": "777-7777777", "ext": "77"},
                {"number": "888-8888888", "ext": "", "type": "Home"},
                {"number": "999-9999999", "type": "Work"}
            ])
            one.custom_field("name", [{"first": "Jenny", "middle": "X", "last": "Smith"}])

            # --------------------------

            res_queue = mock.ResponseQueue(client=c)

            # Add the same response for each call
            for t in range(0, 14):
                res_queue.add_response(res_1)

            prefix = Commander.notation_prefix

            # Simple call. With prefix
            value = c.get_notation("{}://{}/field/login".format(prefix, one.uid))
            self.assertEqual("My Login 1", value, "field login is not correct for simple call w/ prefix")

            # Simple call. Without prefix
            value = c.get_notation("{}/field/login".format(one.uid))
            self.assertEqual("My Login 1", value, "field login is not correct for simple call w/o prefix")

            # Same call, but specifically telling to return value at index 0
            value = c.get_notation("{}://{}/field/login[0]".format(prefix, one.uid))
            self.assertEqual("My Login 1", value, "field login is not correct for predicate of index 0")

            # There is only 1 value. Asking for second item should throw an error.
            try:
                c.get_notation("{}://{}/field/login[1]".format(prefix, one.uid))
                self.fail("Should not have gotten here.")
            except ValueError as err:
                self.assertRegex(str(err), r'value at index', 'did not get correct exception')

            # We should get an array instead of a single value.
            value = c.get_notation("{}://{}/field/login[]".format(prefix, one.uid))
            self.assertEqual(["My Login 1"], value, "field login is not correct for array value")

            # Custom field, simple
            value = c.get_notation("{}://{}/custom_field/My Custom 1".format(prefix, one.uid))
            self.assertEqual("custom1", value, "custom field My Custom 1 is not correct")

            # Custom field, only the first
            value = c.get_notation("{}://{}/custom_field/My Custom 2".format(prefix, one.uid))
            self.assertEqual("one", value, "custom field My Custom 1, only the first, is not correct")

            # Custom field, get the second value
            value = c.get_notation("{}://{}/custom_field/My Custom 2[1]".format(prefix, one.uid))
            self.assertEqual("two", value, "custom field My Custom 1, second value, is not correct")

            # Custom field, get the second value
            value = c.get_notation("{}://{}/custom_field/My Custom 2[]".format(prefix, one.uid))
            self.assertEqual(["one", "two", "three"], value, "custom field My Custom 1, all value, is not correct")

            # Custom field, get first phone number
            value = c.get_notation("{}://{}/custom_field/phone[0][number]".format(prefix, one.uid))
            self.assertEqual("555-5555555", value, "custom field phone, did not get first home number")

            # Custom field, get second phone number
            value = c.get_notation("{}://{}/custom_field/phone[1][number]".format(prefix, one.uid))
            self.assertEqual("777-7777777", value, "custom field phone, did not get second home number")

            # Custom field, get all of the third phone number
            value = c.get_notation("{}://{}/custom_field/phone[2]".format(prefix, one.uid))
            self.assertEqual({"number": "888-8888888", "ext": "", "type": "Home"}, value,
                             "custom field phone, did not get correct dict for third")

            # Custom field, get first name
            value = c.get_notation("{}/custom_field/name[first]".format(one.uid))
            self.assertEqual("Jenny", value, "custom field name, got the first name")

            # Custom field, get last name
            value = c.get_notation("{}/custom_field/name[last]".format(one.uid))
            self.assertEqual("Smith", value, "custom field name, got the last name")

    def test_commander_custom_field(self):

        """ Test how Commander store custom fields

        If no custom fields are added via Commander, the JSON will be missing the "custom" key. Make
        a record that has no custom field and see if stuff still works.

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

            # We want to remove the 'custom' key from the JSON
            res_1 = mock.Response(flags={
                "prune_custom_fields": True
            })

            one = res_1.add_record(title="My Record 1")
            one.field("login", "My Login 1")
            one.field("password", "My Password 1")

            res_queue = mock.ResponseQueue(client=c)
            res_queue.add_response(res_1)
            res_queue.add_response(res_1)

            # Make sure the mock worked
            records = c.get_secrets()
            self.assertEqual(len(records), 1, "didn't get 1 records")
            self.assertIsNone(records[0].dict.get("custom"), "found 'custom' in the JSON, mock failed")

            try:
                c.get_notation("{}/custom_field/My Custom 1".format(one.uid))
                self.fail("Should not have gotten here.")
            except ValueError as err:
                self.assertRegex(str(err), r'Cannot find the custom field label', 'did not get correct exception')
            except Exception as err:
                self.fail("Didn't get the correct exception message: {}".format(err))
