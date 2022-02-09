import unittest
from keeper_secrets_manager_helper.v3.record import Record
from keeper_secrets_manager_helper.v3.parser import Parser
from keeper_secrets_manager_helper.v3.field_type import PasswordComplexity


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
            fields=fields
        )
        # Passing fields in on the constructor will automatically call build_record.
        # r.build_record()
        print(r.fields)
        self.assertEqual("login", r.record_type, "helper type is not correct")
        self.assertEqual("My Login Record", r.title, "title is not correct")
        self.assertEqual("This is my note", r.notes, "notes is not correct")

        fields = r.fields
        # There is 5 fields per helper type. We only set 3 in the test, but there should be 5
        self.assertEqual(5, len(fields), "got 5 fields")
        index = 0
        for field_type in ["login", "password", "url", "fileRef", "oneTimeCode"]:
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
            "url=http://mybank.localhost.com",

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

    def test_invalid_field(self):

        p = Parser()

        login_data = [
            "login=My Login",
            "password=My Password",
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
