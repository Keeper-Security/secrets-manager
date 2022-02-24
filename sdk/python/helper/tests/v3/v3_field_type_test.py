import unittest
from keeper_secrets_manager_helper.v3.field_type import *


class FieldTypeTest(unittest.TestCase):

    def test_password_complexity(self):

        pc = PasswordComplexity()
        d = pc.to_dict()
        self.assertEqual(64, d.get("length"))
        self.assertEqual(0, d.get("caps"))
        self.assertEqual(0, d.get("lowercase"))
        self.assertEqual(0, d.get("digits"))
        self.assertEqual(0, d.get("special"))

        pc = PasswordComplexity(length=32, caps=5, lowercase=5, digits=5, special=5)
        d = pc.to_dict()
        self.assertEqual(32, d.get("length"))
        self.assertEqual(5, d.get("caps"))
        self.assertEqual(5, d.get("lowercase"))
        self.assertEqual(5, d.get("digits"))
        self.assertEqual(5, d.get("special"))

        pc = PasswordComplexity({"length": 16, "caps": 2, "lowercase": 3, "digits": 4, "special": 0})
        d = pc.to_dict()
        self.assertEqual(16, d.get("length"))
        self.assertEqual(2, d.get("caps"))
        self.assertEqual(3, d.get("lowercase"))
        self.assertEqual(4, d.get("digits"))
        self.assertEqual(0, d.get("special"))

        # Uhm, so how a password is generate is up in the air. This is based on the Python SDK, which will use the
        # counts over the length. So the password is going to be 9 characters, not 16 :/
        pc = PasswordComplexity({"length": 16, "caps": 2, "lowercase": 3, "digits": 4, "special": 0})
        password = pc.generate_password()
        self.assertEqual(9, len(password), "password is too short")

    def test_load_map(self):
        get_field_type_map()

        # Nice test to make sure we loaded all the fields, if we add more fields this will fail ... but in a good way.
        self.assertEqual(30, len(field_map.keys()))

        # Check if we get a Login class
        self.assertEqual(get_class_by_type("login"), Login)

        try:
            get_class_by_type("BAD BAD BAD")
            self.fail("Should have gotten an exception get bad field class")
        except ImportError as _:
            pass
