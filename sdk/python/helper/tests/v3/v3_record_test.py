import os
import unittest
from keeper_secrets_manager_helper.record_type import RecordType
from keeper_secrets_manager_helper.v3.record import Record
from keeper_secrets_manager_helper.v3.parser import Parser
from keeper_secrets_manager_helper.v3.field_type import PasswordComplexity
import tempfile
import json


class ParserTest(unittest.TestCase):

    def test_build_record_simple(self):

        p = Parser()

        login_data = [
            "login=My Login",
            "password=My Password",
            "url=http://localhost:80"
        ]

        fields = p.parse_field(login_data)

        r = Record(
            record_type='login',
            title="My Login Record",
            notes="This is my note",
            fields=fields,
        )
        # Passing fields in on the constructor will automatically call build_record.
        # r.build_record()
        self.assertEqual("login", r.record_type, "helper type is not correct")
        self.assertEqual("My Login Record", r.title, "title is not correct")
        self.assertEqual("This is my note", r.notes, "notes is not correct")

        fields = r.fields
        # There is 6 fields per helper type. We only set 3 in the test, but there should be 5
        self.assertEqual(6, len(fields), "got 6 fields")
        index = 0
        for field_type in ["passkey", "login", "password", "url", "fileRef", "oneTimeCode"]:
            self.assertEqual(field_type, fields[index].get("type"), "first helper is the wrong type")
            index += 1

    def test_build_record_complex(self):

        bank_account_data = [
            # Build in pieces
            "f.bankAccount.accountType=sAvInGs",
            "f.bankAccount.routingNumber=Routing",
            "f.bankAccount.accountNumber=Account",

            # Build using JSON object
            'f.name={"first": "John", "last": "Doe"}',

            # The standard
            "url=https://mybank.localhost.com",

            # Build using JSON array
            'cardRef=["PpR0AKIZAtUiyvq1r2BC1w"]',

            # Custom with label
            'c.name[NAME].first=John',
            'c.name[NAME].middle=X',
            'c.name[NAME].last=Smith',

            # Phone with 4 numbers :)
            'c.phone[Phone]={"region": "CA", "number": "ONE", "type": "Work"}',
            'c.phone[Phone]={"region": "US", "number": "TWO", "type": "Home"}',

            'c.phone[Phone].number=THREE',
            'c.phone[Phone].type=Home',
            
            'c.phone[Phone].number=FOUR',
        ]

        p = Parser()
        fields = p.parse_field(bank_account_data)

        r = Record(
            record_type='bankAccount',
            title="Bank",
            fields=fields,
            password_generate=True
        )
        # No need to call this since passing in fields in the constructor will do build_record. But run it to make
        # sure we don't get dups.
        r.build_record()

        # This includes the fields not set
        self.assertEqual(8, len(r.fields), "there were not 4 fields")

        self.assertEqual(2, len(r.custom_fields), "there were not 2 custom fields")

        self.assertEqual("password", r.fields[3]["type"], "password is not the 4th field")

        # password_generate will cause the password to be set
        pc = PasswordComplexity()
        self.assertEqual(pc.length, len(r.fields[3]["value"][0]), "password is not set correctly")

        self.assertEqual(4, len(r.custom_fields[1]["value"]), "custom field phone does have 4 values")
        self.assertEqual("ONE", r.custom_fields[1]["value"][0]["number"], "first number is not ONE")
        self.assertEqual("TWO", r.custom_fields[1]["value"][1]["number"], "second number is not TWO")
        self.assertEqual("THREE", r.custom_fields[1]["value"][2]["number"], "third number is not THREE")
        self.assertEqual("FOUR", r.custom_fields[1]["value"][3]["number"], "fourth number is not FOUR")

    def test_value_key_rule_label_grouping(self):

        # Make sure the labels make the field unique
        custom_fields = [
            "c.name[My Doctor].first=Jane",
            "c.name[My Doctor].last=Smith",
            "c.name[My Lawyer].first=John",
            "c.name[My Lawyer].last=Doe"
        ]
        p = Parser()
        fields = p.parse_field(custom_fields)

        r = Record(
            record_type='login',
            title="Custom Fields",
            fields=fields,
            password_generate=True,
            password_complexity={
                "length": 64,
                "filter_characters": ["$", "!"]
            }
        )

        self.assertEqual(2, len(r.custom_fields), "there were not 2 custom fields")
        field = r.custom_fields[0]
        self.assertEqual("name", field.get("type"), "field type is not name")
        self.assertEqual("My Doctor", field.get("label"), "field label is not My Doctor")
        value = field.get("value")
        self.assertEqual(1, len(value), "there is not 1 value in the first field's value")
        self.assertDictEqual(value[0], {'first': 'Jane', 'last': 'Smith'}, "first field's value is not correct")

        field = r.custom_fields[1]
        self.assertEqual("name", field.get("type"), "field type is not name")
        self.assertEqual("My Lawyer", field.get("label"), "field label is not My Lawyer")
        value = field.get("value")
        self.assertEqual(1, len(value), "there is not 1 value in the second field's value")
        self.assertDictEqual(value[0], {'first': 'John', 'last': 'Doe'}, "second field's value is not correct")

    def test_value_key_rule_no_label_grouping(self):

        # Make sure an initial JSON value completes the field. We should get two fields
        custom_fields = [
            # Since this is JSON, this is value one in the field
            'c.phone={"number": "5551231234"}',
            # Since this is JSON, this is value two in the field
            'c.phone={"number": "5559999999"}',
            # Since the first record are considered complete due to being set by JSON, this creates a third value
            "c.phone.number=5551111111"
        ]
        p = Parser()
        fields = p.parse_field(custom_fields)

        r = Record(
            record_type='login',
            title="Custom Fields",
            fields=fields,
            password_generate=True
        )

        self.assertEqual(1, len(r.custom_fields), "there were not 1 custom fields")
        self.assertEqual(3, len(r.custom_fields[0].get("value")), "did not find three phone numbers")

    def test_adding_to_complete_field(self):

        # Since the phone is being set with a list, the field is considered complete. Nothing else can be added to it.
        custom_fields = [
            'c.phone=[{"number": "5551231234"}]',
            "c.phone.number=5551111111"
        ]
        p = Parser()
        fields = p.parse_field(custom_fields)

        try:
            Record(
                record_type='login',
                title="Custom Fields",
                fields=fields,
                password_generate=True
            )
            self.fail("This should have failed due to the field not being unique")
        except ValueError as err:
            self.assertRegex(str(err), r'Cannot add this field due to it not being unique')

    def test_custom_record_with_duplicate_fields(self):

        data = {
            "version": "v3",
            "kind": "KeeperRecordType",
            "data": [
                {
                    "class": "MyCustom2",
                    "name": "myCustom2",
                    "fields": [
                        {"type": "text", "label": "Text One"},
                        {"type": "text", "label": "Text Two"},
                        {"type": "text", "label": "Text Three"}
                    ]
                }
            ]
        }

        custom_fields = [
            'text=ONE',
            'text=TWO',
            'text=THREE',
        ]

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
                fh.write(json.dumps(data))
                fh.seek(0)
                RecordType.load_record_types(fh.name)
                fh.close()

                p = Parser()
                fields = p.parse_field(custom_fields)

                r = Record(
                    record_type='myCustom2',
                    title="Custom Record",
                    fields=fields,
                    password_generate=True
                )
                self.assertEqual(3, len(r.fields), "did not find 3 text fields")
                self.assertEqual("ONE", r.fields[0].get("value")[0], "first field is ONE")
                self.assertEqual("TWO", r.fields[1].get("value")[0], "first field is TWO")
                self.assertEqual("THREE", r.fields[2].get("value")[0], "first field is THREE")
        finally:
            try:
                os.unlink(fh.name)
            except IOError:
                pass


    def test_invalid_field(self):

        """Attempt to add field that doesn't exist in the record type schema"""

        p = Parser()

        login_data = [
            "login=My Login",
            "password=My Password",
            # Bad Field
            "text=RANDOM TEXT"
        ]

        fields = p.parse_field(login_data)

        r = Record(
            record_type='login',
            title="Bad Record",
        )
        # Add field using method instead of constructor
        try:
            for field in fields:
                r.add_fields(field)
            r.build_record()
            self.fail("Should have failed due to text not being in standard fields.")
        except ValueError as err:
            self.assertRegex(str(err), 'The standard fields do not have a ')
