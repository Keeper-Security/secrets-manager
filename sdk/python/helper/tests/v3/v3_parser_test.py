import unittest
from keeper_secrets_manager_helper.v3.parser import Parser
from keeper_secrets_manager_helper.field import FieldSectionEnum
import json


class ParserTest(unittest.TestCase):

    def test_parser_field(self):

        p = Parser()
        field = p.parse_field("login=My Login")[0]
        self.assertEqual(field.field_section, FieldSectionEnum.STANDARD)
        self.assertEqual(field.type, "login")
        self.assertEqual(field.value, "My Login")
        self.assertIsNone(field.label)
        self.assertIsNone(field.value_key)

        field = p.parse_field("f.password[My Password]=****")[0]
        self.assertEqual(field.field_section, FieldSectionEnum.STANDARD)
        self.assertEqual(field.type, "password")
        self.assertEqual(field.value, "****")
        self.assertEqual(field.label, "My Password")
        self.assertIsNone(field.value_key)

        field = p.parse_field('c.phone[My Phone Numbers]='
                              '{"region": "US", "number": "55555512324", "ext": "7777", "type":"Mobile"}')[0]
        self.assertEqual(field.field_section, FieldSectionEnum.CUSTOM)
        self.assertEqual(field.type, "phone")
        self.assertDictEqual(field.value, {"ext": "7777", "number": "55555512324", "region": "US", "type": "Mobile"})
        self.assertEqual(field.label, "My Phone Numbers")
        self.assertIsNone(field.value_key)

        field = p.parse_field("name[My Name].first=John")[0]
        self.assertEqual(field.field_section, FieldSectionEnum.STANDARD)
        self.assertEqual(field.type, "name")
        self.assertDictEqual(field.value, {'first': 'John'})
        self.assertEqual(field.label, "My Name")
        self.assertEqual(field.value_key, "first")

        # Test crazy [] in the label, and test the escape of the escape character
        field = p.parse_field(r"name[\[\[\[My\\ Name\]\[\]].first=John")[0]
        self.assertEqual(field.field_section, FieldSectionEnum.STANDARD)
        self.assertEqual(field.type, "name")
        self.assertDictEqual(field.value, {'first': 'John'})
        self.assertEqual(field.label, r"[[[My\ Name][]")
        self.assertEqual(field.value_key, "first")

        # JSON Value
        field = p.parse_field('f.name={"first": "John", "last": "name"}')[0]
        self.assertEqual(field.field_section, FieldSectionEnum.STANDARD)
        self.assertEqual(field.type, "name")
        self.assertDictEqual(field.value, {"first": "John", "last": "name"})
        self.assertIsNone(field.label)
        self.assertIsNone(field.value_key)

    def test_bad_syntax(self):
        p = Parser()

        # Is this allowed? It's bad JSON ... but is it JSON. Maybe a warning?
        p.parse_field('f.text={"first": "John", "last": "name"')

        # Label is not terminated
        try:
            p.parse_field('f.text[BLAH=OK')
            self.fail("Bad label should have failed")
        except ValueError as err:
            self.assertRegex(str(err), r'Could not find the end of the label')

        # Bad field section
        try:
            p.parse_field('k.text=OK')
            self.fail("Bad label should have failed")
        except ValueError as err:
            self.assertRegex(str(err), r"Field section can only be 'f' or 'c'")

        # Text is not a dictionary. The key 'value' doesn't exist.
        try:
            p.parse_field('c.text.value=OK')
            self.fail("Bad key should have failed")
        except ValueError as err:
            self.assertRegex(str(err), r"does not have value keys")

        # Double value keys
        try:
            p.parse_field('c.phone.number.number=5551234567')
            self.fail("Duplicate value keys should have failed")
        except ValueError as err:
            self.assertRegex(str(err), r"has already been found")

        # Bad field type
        try:
            p.parse_field('c.aaaaa=BAD')
            self.fail("Bad field type should have failed")
        except ValueError as err:
            self.assertRegex(str(err), r"does not exists")

        # Bad value type
        try:
            p.parse_field('c.phone.i_dont_exists=5551234567')
            self.fail("Bad value keys should have failed")
        except ValueError as err:
            self.assertRegex(str(err), r"does not have the value key")


