import unittest
from keeper_secrets_manager_helper.v3.enum import AccountTypeEnum, CountryEnum
from keeper_secrets_manager_helper.v3.field_type import (
    Address, AddressRef, BankAccount, BankAccounts, BirthDate,
    CardRef, Checkbox, DatabaseType, Date, DirectoryType, Email,
    ExpirationDate, FileRef, HiddenField, Host, KeyPair,
    LicenseNumber, Login, Multiline, Name, OneTimeCode,
    OneTimePassword, PamHostname, PamResources, Passkey,
    Password, PasswordComplexity, PaymentCard, PaymentCards,
    Phone, Phones, PinCode, RecordRef, Schedule, Script,
    SecureNote, SecurityQuestions, Text, Url
)


class FieldTypeTest(unittest.TestCase):

    def _check_dict(self, field_type, value=None, label=None, extra_params=None, check_value=True):
        field_dict: dict = field_type.to_dict()
        self.assertIsNotNone(field_dict)
        self.assertIsInstance(field_dict, dict)
        self.assertEqual(field_type.name, field_dict.get("type"), "type is not correct")
        if check_value is True:
            if isinstance(value, dict) is True:
                self.assertDictEqual(field_dict.get("value")[0], value, "value (dict) is not correct")
            elif isinstance(value, list) is True:
                self.assertListEqual(field_dict.get("value"), value, "value (list) is not correct")
            else:
                self.assertEqual(field_dict.get("value")[0], value, "value (str) is not correct")
        else:
            self.assertIsNotNone(field_dict.get("value"), "value doesn't exist")
        if label is not None:
            self.assertEqual(label, field_dict.get("label"), "label is not correct")
        if extra_params is not None:
            for k, v in extra_params.items():
                self.assertEqual(v, field_dict.get(k), f"{k} is not correct")

    def test_text(self):
        # Set as str
        text = Text("My Text", label="MY LABEL")
        self._check_dict(text, value="My Text", label="MY LABEL")

    def test_url(self):
        # Set using attributes
        url = Url()
        url.value = "http://localhost"
        self._check_dict(url, value="http://localhost")

    def test_pin_code(self):
        pc = PinCode()
        pc.value = "111111"
        self._check_dict(pc, value="111111")

    def test_multiline(self):
        # Set as array value
        ml = Multiline(["this\nhas\ntext"])
        self._check_dict(ml, value="this\nhas\ntext")

    def test_file_ref(self):
        f = FileRef()
        f.value = "OlLZ6JLjnyMOS3CiIPHBjw"
        self._check_dict(f, value="OlLZ6JLjnyMOS3CiIPHBjw")

    def test_email(self):
        # Set as array value
        e = Email("smith@localhost")
        self._check_dict(e, value="smith@localhost")

    def test_phone(self):
        # Set Phone via attributes
        p = Phone()
        p.number = "5555551234"
        p.ext = "7777"
        p.type = "Mobile"
        p.region = "US"
        self._check_dict(p, value={"number": "5555551234", "ext": "7777", "type": "Mobile", "region": "US"})

        # Set phone via constructor args
        p = Phone(number="123456", type="Work", region="US", ext="1234")
        self.assertEqual("123456", p.number, "Phone number is not correct")
        self.assertEqual("Work", p.type, "Phone type is not correct")
        self.assertEqual("US", p.region, "Phone region is not correct")
        self.assertEqual("1234", p.ext, "Phone region is not correct")
        self._check_dict(p, value={"number": "123456", "ext": "1234", "type": "Work", "region": "US"})

        # Set Phone via constructor value
        p = Phone({"number": "1234567890", "type": "Home"})
        self.assertEqual("1234567890", p.number, "Phone number is not correct")
        self.assertEqual("Home", p.type, "Phone type is not correct")
        self._check_dict(p, value={"number": "1234567890", "type": "Home"})

        # Test bad enum via constructor
        try:
            Phone({"number": "1234567890", "type": "Bad"})
            raise Exception("Should have failed due to bad Enum")
        except ValueError:
            pass
        except Exception as err:
            self.fail(str(err))

    def test_phones(self):
        p1 = Phone()
        p1.number = "5555551234"

        p2 = Phone()
        p2.number = "6666661234"

        # Add value via add_value method. Appends a value.
        ps = Phones()
        ps.add_value(p1)
        ps.add_value(p2)
        self._check_dict(ps, value=[{"number": "5555551234"}, {"number": "6666661234"}])

        # Set value via constructor
        ps = Phones([p2, p1])
        self._check_dict(ps, value=[{"number": "6666661234"}, {"number": "5555551234"}])

        ps = Phones([
            {"number": "1234567890", "type": "Home"},
            {"number": "5555555555", "type": "Work", "region": "US"}
        ])
        self._check_dict(ps, value=[
            {"number": "1234567890", "type": "Home"},
            {"number": "5555555555", "type": "Work", "region": "US"}
        ])

    def test_name(self):
        # Set as array value
        n = Name({"first": "John", "middle": "X", "last": "Doe"}, label="A LABEL")
        self._check_dict(n, value={"first": "John", "middle": "X", "last": "Doe"}, label="A LABEL")

    def test_address(self):
        a = Address()
        a.street1 = "North Main Street"
        a.street2 = "Apt B"
        a.city = "Gotham"
        a.zip = "11111-2222"
        a.country = CountryEnum.CA
        self._check_dict(a, value={
            "street1": "North Main Street",
            "street2": "Apt B",
            "city": "Gotham",
            "zip": "11111-2222",
            "country": "CA"
        })

    def test_address_ref(self):
        a = AddressRef()
        a.value = "OlLZ6JLjnyMOS3CiIPHBjw"
        self._check_dict(a, value="OlLZ6JLjnyMOS3CiIPHBjw")

    def test_account_number(self):
        a = Email("111111")
        self._check_dict(a, value="111111")

    def test_login(self):
        ml = Login("my_login")
        self._check_dict(ml, value="my_login")

    def test_hidden_field(self):
        ft = HiddenField("HIDDEN")
        self._check_dict(ft, value="HIDDEN")

    def test_password(self):

        p = Password("MY PASSWORD")
        self._check_dict(p, value="MY PASSWORD")

        p = Password()
        p.enforce_generation = True
        self._check_dict(p, check_value=False, extra_params={
            "enforceGeneration": True,
            "complexity": PasswordComplexity().to_dict()
        })

    def test_security_question(self):
        ft = SecurityQuestions()
        ft.question = "Question"
        ft.answer = "Answer"
        self._check_dict(ft, {"question": "Question", "answer": "Answer"})

    def test_one_time_password(self):
        ft = OneTimePassword("otpauth://localhost")
        self._check_dict(ft, value="otpauth://localhost")

    def test_one_time_code(self):
        ft = OneTimeCode("otpauth://localhost")
        self._check_dict(ft, value="otpauth://localhost")

    def test_card_ref(self):
        ft = CardRef()
        ft.value = "OlLZ6JLjnyMOS3CiIPHBjw"
        self._check_dict(ft, value="OlLZ6JLjnyMOS3CiIPHBjw")

    def test_payment_card(self):

        ft = PaymentCard()
        ft.cardNumber = "5555 5555 5555 5555"
        ft.cardExpirationDate = "01/2007"
        ft.cardSecurityCode = "555"
        self._check_dict(ft, value={"cardNumber": "5555 5555 5555 5555", "cardExpirationDate": "01/2007",
                                    "cardSecurityCode": "555"})

        # Test bad field format
        try:
            ft = PaymentCard()
            ft.cardNumber = "5555 5555 5555 5555"
            ft.cardExpirationDate = "BAD"
            ft.to_dict()
            raise Exception("Should have failed due to bad cardExpirationDate format")
        except ValueError:
            pass
        except Exception as err:
            self.fail(str(err))

    def test_payment_cards(self):

        pc = PaymentCard()
        pc.cardNumber = "5555 5555 5555 5555"
        pc.cardExpirationDate = "01/2007"
        pc.cardSecurityCode = "555"

        pcs = PaymentCards(pc)
        self._check_dict(pcs, value={"cardNumber": "5555 5555 5555 5555", "cardExpirationDate": "01/2007",
                                     "cardSecurityCode": "555"})

        pcs = PaymentCards([{"cardNumber": "5555 5555 5555 5555"}])
        self._check_dict(pcs, value={"cardNumber": "5555 5555 5555 5555"})

    def test_date(self):

        d = Date("2021-07-01 12:00:00")
        self._check_dict(d, value=1625140800000)

        d = Date("2021-07-01T12:34:56.1234+06:00")
        self._check_dict(d, value=1625142896123)

        d = Date(1625140800000)
        self._check_dict(d, value=1625140800000)

        d = Date(["1625140800000"])
        self._check_dict(d, value=1625140800000)

    def test_birth_date(self):

        d = BirthDate("2021-07-01 12:00:00")
        self._check_dict(d, value=1625140800000)

        d = Date("2021-07-01T12:34:56.1234+06:00")
        self._check_dict(d, value=1625142896123)

        d = Date(1625140800000)
        self._check_dict(d, value=1625140800000)

        d = Date(["1625140800000"])
        self._check_dict(d, value=1625140800000)

    def test_expiration_date(self):

        d = ExpirationDate("2021-07-01 12:00:00")
        self._check_dict(d, value=1625140800000)

        d = Date("2021-07-01T12:34:56.1234+06:00")
        self._check_dict(d, value=1625142896123)

        d = Date(1625140800000)
        self._check_dict(d, value=1625140800000)

        d = Date(["1625140800000"])
        self._check_dict(d, value=1625140800000)

    def test_bank_account(self):

        b = BankAccount()
        b.accountType = AccountTypeEnum.CHECKING
        b.routingNumber = "12345"
        b.accountNumber = "ABCDE"
        self._check_dict(b, value={"accountType": "Checking", "routingNumber": "12345", "accountNumber": "ABCDE"})

        # Test bad field format
        try:
            b = BankAccount()
            b.accountType = "BAD"
            b.routingNumber = "12345"
            b.accountNumber = "ABCDE"
            b.to_dict()
            raise Exception("Should have failed due to bad enum for account type")
        except ValueError:
            pass
        except Exception as err:
            self.fail(str(err))

    def test_bank_accounts(self):

        b = BankAccount({"accountType": "SAVINGS", "routingNumber": "12345", "accountNumber": "ABCDE"})
        ba = BankAccounts()
        ba.add_value(b)
        self._check_dict(b, value={"accountType": "Savings", "routingNumber": "12345", "accountNumber": "ABCDE"})

    def test_key_pair(self):

        ft = KeyPair()
        ft.publicKey = "PUBLIC KEY"
        ft.privateKey = "PRIVATE KEY"
        self._check_dict(ft, value={"publicKey": "PUBLIC KEY", "privateKey": "PRIVATE KEY"})

    def test_host(self):
        ft = Host()
        ft.hostName = "localhost"
        ft.port = "22"
        self._check_dict(ft, value={"hostName": "localhost", "port": "22"})

    def test_license_number(self):
        ft = LicenseNumber("LIC123")
        self._check_dict(ft, value="LIC123")

    def test_secret_note(self):
        ft = SecureNote("Secret Note")
        self._check_dict(ft, value="Secret Note")

    def test_record_ref(self):
        ft = RecordRef()
        ft.value = "OlLZ6JLjnyMOS3CiIPHBjw"
        self._check_dict(ft, value="OlLZ6JLjnyMOS3CiIPHBjw")

    def test_schedule(self):
        ft = Schedule()
        ft.type = "WEEKLY"
        ft.time = "00:00:00"
        ft.tz = "America/Chicago"
        ft.weekday = "WEDNESDAY"
        ft.intervalCount = 1
        self._check_dict(ft, value={"type": "WEEKLY", "time": "00:00:00", "tz": "America/Chicago", "weekday": "WEDNESDAY", "intervalCount": 1})

    def test_directory_type(self):
        ft = DirectoryType()
        ft.value = "openldap"
        self._check_dict(ft, value="openldap")

    def test_database_type(self):
            ft = DatabaseType()
            ft.value = "mariadb-flexible"
            self._check_dict(ft, value="mariadb-flexible")

    def test_pam_hostname(self):
        ft = PamHostname()
        ft.hostName = "localhost"
        ft.port = "22"
        self._check_dict(ft, value={"hostName": "localhost", "port": "22"})

    def test_pam_resources(self):
        ft = PamResources()
        ft.controllerUid = "OlLZ6JLjnyMOS3CiIPHBjw"
        ft.folderUid = "so5ja6A46Zmr9J1QyCc06g"
        ft.resourceRef = ["hUrGHrcM0PI3Y6Ch5wCrAQ"]
        ft.allowedSettings = {
                "connections": True,
                "portForwards": True,
                "rotation": True,
                "sessionRecording": True,
                "typescriptRecording": True
            }
        self._check_dict(ft, value={
            "controllerUid": "OlLZ6JLjnyMOS3CiIPHBjw",
            "folderUid": "so5ja6A46Zmr9J1QyCc06g",
            "resourceRef": ["hUrGHrcM0PI3Y6Ch5wCrAQ"],
            "allowedSettings": {
                "connections": True,
                "portForwards": True,
                "rotation": True,
                "sessionRecording": True,
                "typescriptRecording": True
            }
            })

    def test_checkbox(self):
        ft = Checkbox()
        ft.value = True
        self._check_dict(ft, value=True)

    def test_passkey(self):
        ft = Passkey()
        ft.privateKey = {
                "crv":"CRV",
                "d": "DDDDD",
                "ext": False,
                "key_ops": [],
                "kty": "KTY",
                "x": "XXX",
                "y": "YYY"
        }
        ft.credentialId = "OlLZ6JLjnyMOS3CiIPHBjw"
        ft.signCount = 1
        ft.userId = "so5ja6A46Zmr9J1QyCc06g"
        ft.relyingParty = "hUrGHrcM0PI3Y6Ch5wCrAQ"
        ft.username = "user1"
        ft.createdDate = 1625140800000
        self._check_dict(ft, value={
            "privateKey": {
                "crv": "CRV",
                "d": "DDDDD",
                "ext": False,
                "key_ops": [],
                "kty": "KTY",
                "x": "XXX",
                "y": "YYY"
            },
            "credentialId": "OlLZ6JLjnyMOS3CiIPHBjw",
            "signCount": 1,
            "userId": "so5ja6A46Zmr9J1QyCc06g",
            "relyingParty": "hUrGHrcM0PI3Y6Ch5wCrAQ",
            "username": "user1",
            "createdDate": 1625140800000})
        
    def test_script(self):
        ft = Script()
        ft.fileRef = "OlLZ6JLjnyMOS3CiIPHBjw"
        ft.command = "/bin/zsh"
        ft.recordRef = "hUrGHrcM0PI3Y6Ch5wCrAQ"
        self._check_dict(ft, value={"fileRef": "OlLZ6JLjnyMOS3CiIPHBjw", "command": "/bin/zsh", "recordRef": "hUrGHrcM0PI3Y6Ch5wCrAQ"})
