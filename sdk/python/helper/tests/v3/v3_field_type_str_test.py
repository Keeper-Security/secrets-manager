import io
import logging
import traceback
import unittest

from keeper_secrets_manager_helper.v3.field_type import FieldType, FileRef, Login, Password, get_field_type_map

SECRET = "Zq9-hunter2-do-not-print"


class FieldTypeStrMaskTest(unittest.TestCase):
    """String forms of a field must never contain its value (KSM-1807)."""

    def test_password_value_absent_from_str_fstring_and_logging(self):
        field = Password(label="db", value=SECRET)

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("ksm1807")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        try:
            logger.debug("field: %s", field)
        finally:
            logger.removeHandler(handler)

        for rendered in (str(field), f"{field}", stream.getvalue(), repr(field)):
            self.assertNotIn(SECRET, rendered)

    def test_password_str_is_masked_and_balanced(self):
        text = str(Password(label="db", value=SECRET))
        self.assertIn("value=***", text)
        self.assertEqual(text.count("("), text.count(")"))

    def test_base_field_str_masks_value(self):
        text = str(Login(label="user", value=SECRET))
        self.assertNotIn(SECRET, text)
        self.assertIn("value=***", text)

    def test_repr_uses_the_masked_string_form(self):
        password = Password(label="db", value=SECRET, enforce_generation=True)
        login = Login(label="user", value=SECRET)

        # Password overrides __str__; Login uses the FieldType one. repr() must follow both.
        for field in (password, login):
            self.assertEqual(repr(field), str(field))
        self.assertIn("enforce_generation=True", repr(password))

        # Containers, %r and !r format their items with repr().
        for rendered in (repr([password, login]), str({"db": password}), "%r" % (login,), f"{password!r}"):
            self.assertNotIn(SECRET, rendered)
            self.assertIn("value=***", rendered)
        self.assertIn("Login(label=user, value=***", repr([password, login]))

    def test_every_field_type_masks_its_value(self):
        for cls in [FieldType, *get_field_type_map().values()]:
            # Pass each dict key too: __init__ copies the keys to attributes.
            field = cls(label="x", **dict.fromkeys(cls.schema.get("schema", {}), SECRET))
            # Set _value directly: some types need a dict, a record UID or an enum value.
            field._value = [SECRET]
            for rendered in (str(field), repr(field)):
                self.assertNotIn(SECRET, rendered, cls.__name__)

    def test_repr_of_a_half_built_field_type_does_not_raise(self):
        # A failed __init__ leaves an object without a label in the traceback frames.
        self.assertIn("FileRef object at", repr(FileRef.__new__(FileRef)))
        with self.assertRaises(ValueError) as ctx:
            FileRef(value="not-a-uid")
        text = "".join(traceback.TracebackException.from_exception(ctx.exception, capture_locals=True).format())
        self.assertIn("ValueError", text)
