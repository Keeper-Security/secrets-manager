import unittest
import tempfile
import json
import os

from keeper_secrets_manager_core.storage import FileKeyValueStorage
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core import mock


class NotationTest(unittest.TestCase):

    def setUp(self):

        self.orig_working_dir = os.getcwd()

    def tearDown(self):

        os.chdir(self.orig_working_dir)

    def test_get_notation(self):

        """ Perform a simple get_secrets

        This test is mocked to return 3 record (2 records, 1 folder with a record)

        """

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(
                    json.dumps({
                        "hostname": "fake.keepersecurity.com",
                        "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw=",
                        "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26"
                                    "C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ==",
                        "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
                        "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9d"
                                    "jH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbE"
                                    "T6joq0xCjhKMhHQFaHYI"
                    })
                )
                fh.seek(0)
                secrets_manager = SecretsManager(config=FileKeyValueStorage(config_file_location=fh.name))

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

                res_queue = mock.ResponseQueue(client=secrets_manager)

                # Add the same response for each call
                for t in range(0, 14):
                    res_queue.add_response(res_1)

                prefix = SecretsManager.notation_prefix

                # Simple call. With prefix
                value = secrets_manager.get_notation("{}://{}/field/login".format(prefix, one.uid))
                self.assertEqual("My Login 1", value, "field login is not correct for simple call w/ prefix")

                # Simple call. Without prefix
                value = secrets_manager.get_notation("{}/field/login".format(one.uid))
                self.assertEqual("My Login 1", value, "field login is not correct for simple call w/o prefix")

                # Same call, but specifically telling to return value at index 0
                value = secrets_manager.get_notation("{}://{}/field/login[0]".format(prefix, one.uid))
                self.assertEqual("My Login 1", value, "field login is not correct for predicate of index 0")

                # There is only 1 value. Asking for second item should throw an error.
                try:
                    secrets_manager.get_notation("{}://{}/field/login[1]".format(prefix, one.uid))
                    self.fail("Should not have gotten here.")
                except ValueError as err:
                    self.assertRegex(str(err), r'value at index', 'did not get correct exception')

                # We should get an array instead of a single value.
                value = secrets_manager.get_notation("{}://{}/field/login[]".format(prefix, one.uid))
                self.assertEqual(["My Login 1"], value, "field login is not correct for array value")

                # Custom field, simple
                value = secrets_manager.get_notation("{}://{}/custom_field/My Custom 1".format(prefix, one.uid))
                self.assertEqual("custom1", value, "custom field My Custom 1 is not correct")

                # Custom field, only the first
                value = secrets_manager.get_notation("{}://{}/custom_field/My Custom 2".format(prefix, one.uid))
                self.assertEqual("one", value, "custom field My Custom 1, only the first, is not correct")

                # Custom field, get the second value
                value = secrets_manager.get_notation("{}://{}/custom_field/My Custom 2[1]".format(prefix, one.uid))
                self.assertEqual("two", value, "custom field My Custom 1, second value, is not correct")

                # Custom field, get the second value
                value = secrets_manager.get_notation("{}://{}/custom_field/My Custom 2[]".format(prefix, one.uid))
                self.assertEqual(["one", "two", "three"], value, "custom field My Custom 1, all value, is not correct")

                # Custom field, get first phone number
                value = secrets_manager.get_notation("{}://{}/custom_field/phone[0][number]".format(prefix, one.uid))
                self.assertEqual("555-5555555", value, "custom field phone, did not get first home number")

                # Custom field, get second phone number
                value = secrets_manager.get_notation("{}://{}/custom_field/phone[1][number]".format(prefix, one.uid))
                self.assertEqual("777-7777777", value, "custom field phone, did not get second home number")

                # Custom field, get all of the third phone number
                value = secrets_manager.get_notation("{}://{}/custom_field/phone[2]".format(prefix, one.uid))
                self.assertEqual({"number": "888-8888888", "ext": "", "type": "Home"}, value,
                                "custom field phone, did not get correct dict for third")

                # Custom field, get first name
                value = secrets_manager.get_notation("{}/custom_field/name[first]".format(one.uid))
                self.assertEqual("Jenny", value, "custom field name, got the first name")

                # Custom field, get last name
                value = secrets_manager.get_notation("{}/custom_field/name[last]".format(one.uid))
                self.assertEqual("Smith", value, "custom field name, got the last name")
        finally:
            try: os.unlink(fh.name)
            except Exception: pass

    def test_secrets_manager_custom_field(self):

        """ Test how Secrets Manager store custom fields

        If no custom fields are added via Secrets Manager, the JSON will be missing the "custom" key. Make
        a record that has no custom field and see if stuff still works.

        """

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(
                    json.dumps({
                        "hostname": "fake.keepersecurity.com",
                        "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw=",
                        "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26"
                                    "C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ==",
                        "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
                        "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9d"
                                    "jH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbE"
                                    "T6joq0xCjhKMhHQFaHYI"
                    })
                )
                fh.seek(0)
                secrets_manager = SecretsManager(config=FileKeyValueStorage(config_file_location=fh.name))

                # --------------------------

                # We want to remove the 'custom' key from the JSON
                res_1 = mock.Response(flags={
                    "prune_custom_fields": True
                })

                one = res_1.add_record(title="My Record 1")
                one.field("login", "My Login 1")
                one.field("password", "My Password 1")

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res_1)
                res_queue.add_response(res_1)

                # Make sure the mock worked
                records = secrets_manager.get_secrets()
                self.assertEqual(len(records), 1, "didn't get 1 records")
                self.assertIsNone(records[0].dict.get("custom"), "found 'custom' in the JSON, mock failed")

                try:
                    secrets_manager.get_notation("{}/custom_field/My Custom 1".format(one.uid))
                    self.fail("Should not have gotten here.")
                except ValueError as err:
                    self.assertRegex(str(err), r'Cannot find ', 'did not get correct exception')
                except Exception as err:
                    self.fail("Didn't get the correct exception message: {}".format(err))
        finally:
            try: os.unlink(fh.name)
            except Exception: pass

    def test_notation_inflate(self):

        """ Test inflating the field values

        The main record has a cardRef type, which reference a Payment Card record which has an addressRef, which
        references an Address record. When we use notation to get the cardRef, we want the data not the record UIDs.
        Replace the UIDs with actual data.
        """

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(
                    json.dumps({
                        "hostname": "fake.keepersecurity.com",
                        "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw=",
                        "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26"
                                    "C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ==",
                        "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
                        "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9d"
                        "jH0YEvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbE"
                        "T6joq0xCjhKMhHQFaHYI"
                    })
                )
                fh.seek(0)

                prefix = SecretsManager.notation_prefix

                secrets_manager = SecretsManager(config=FileKeyValueStorage(config_file_location=fh.name))

                # Create records in reverse order

                address_res = mock.Response()
                address = address_res.add_record(title="Address Record")
                address.field("address", [{
                    "street1": "100 West Street",
                    "city": "Central City",
                    "state": "AZ",
                    "zip": "53211"
                }])

                card_res = mock.Response()
                card = card_res.add_record(title="Card Record")
                card.field("paymentCard", [{"cardNumber": "5555555555555555",
                    "cardExpirationDate": "01/2021",
                    "cardSecurityCode": "543"}])
                card.field("text", value=["Cardholder"], label="Cardholder Name")
                card.field("pinCode", "1234")
                # card contains the address
                card.field("addressRef", [address.uid])

                main_res = mock.Response()
                main = main_res.add_record(title="Main Record")
                # main contains the card
                main.field("cardRef", [card.uid])

                queue = mock.ResponseQueue(client=secrets_manager)

                # Get the entire value

                queue.add_response(main_res)
                queue.add_response(card_res)
                queue.add_response(address_res)

                value = secrets_manager.get_notation("{}://{}/field/cardRef".format(prefix, main.uid))

                self.assertEqual('5555555555555555', value.get("cardNumber"), 'card number is wrong')
                self.assertEqual('Cardholder', value.get("Cardholder Name"), 'Cardholder Name is wrong')
                self.assertEqual('100 West Street', value.get("street1"), 'street1 is wrong')


                # Get a value in the dictionary
                queue.add_response(main_res)
                queue.add_response(card_res)
                queue.add_response(address_res)

                value = secrets_manager.get_notation("{}://{}/field/cardRef[cardSecurityCode]".format(prefix, main.uid))
                self.assertEqual("543", value, "cardSecurityCode is wrong")

                # This is done via morbid curiosity. We coded for this, but we don't actually have an inflation that does
                # it.

                address_res = mock.Response()
                address = address_res.add_record(title="Address Record")
                address.field("address", [{
                    "street1": "100 West Street",
                    "city": "Central City",
                    "state": "AZ",
                    "zip": "53211"
                }])

                card_res = mock.Response()
                card = card_res.add_record(title="Card Record")

                # Have the string be first instead of the object.
                card.field("pinCode", "1234")
                card.field("text", value=["Cardholder"], label="Cardholder Name")
                card.field("paymentCard", [{"cardNumber": "5555555555555555",
                                            "cardExpirationDate": "01/2021",
                                            "cardSecurityCode": "543"}])
                # card contains the address
                card.field("addressRef", [address.uid])

                main_res = mock.Response()
                main = main_res.add_record(title="Main Record")
                # main contains the card
                main.field("cardRef", [card.uid])

                queue.add_response(main_res)
                queue.add_response(card_res)
                queue.add_response(address_res)

                value = secrets_manager.get_notation("{}://{}/field/cardRef".format(prefix, main.uid))

                self.assertEqual('5555555555555555', value.get("cardNumber"), 'card number is wrong')
                self.assertEqual('Cardholder', value.get("Cardholder Name"), 'Cardholder Name is wrong')
                self.assertEqual('100 West Street', value.get("street1"), 'street1 is wrong')
        finally:
            try: os.unlink(fh.name)
            except Exception: pass
