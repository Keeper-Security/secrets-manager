import io
import logging
import unittest

from keeper_secrets_manager_helper.field import Field, FieldSectionEnum

SECRET = "Zq9#w-do-not-print"


class FieldStrMaskTest(unittest.TestCase):
    """The string forms of a Field must never contain its value."""

    def test_field_value_absent_from_str_format_repr_and_logging(self):
        field = Field(field_section=FieldSectionEnum.STANDARD, type="password", label="db", value=SECRET)

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("field_str_test")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        try:
            logger.debug("field: %s", field)
            logger.debug("fields: %r", [field])
        finally:
            logger.removeHandler(handler)

        for rendered in (str(field), format(field), f"{field}", repr(field), f"{field!r}", stream.getvalue()):
            self.assertNotIn(SECRET, rendered)

    def test_list_and_dict_values_are_masked(self):
        list_field = Field(type="password", value='["' + SECRET + '"]')
        self.assertEqual(list_field.value, [SECRET])
        self.assertNotIn(SECRET, str(list_field))

        dict_field = Field(type="name", value={"first": "usr", "last": SECRET})
        self.assertEqual(dict_field.value, {"first": "usr", "last": SECRET})
        self.assertNotIn(SECRET, str(dict_field))

    def test_field_str_is_masked_and_balanced(self):
        text = str(Field(type="login", label="user", value="usr"))
        self.assertIn("value=***", text)
        self.assertEqual(text.count("("), text.count(")"))

    def test_repr_matches_the_masked_string_form(self):
        field = Field(type="password", label="db", value=SECRET)
        self.assertEqual(repr(field), str(field))
        self.assertIn("value=***", repr([field]))
        self.assertNotIn(SECRET, repr({"db": field}))

    def test_json_number_value_is_masked(self):
        field = Field(type="pinCode", value="2468")
        self.assertEqual(field.value, 2468)  # The setter decodes JSON text.
        self.assertNotIn("2468", str(field))

    def test_repr_of_a_half_built_field_does_not_raise(self):
        self.assertIn("Field object at", repr(Field.__new__(Field)))
