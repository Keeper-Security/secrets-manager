import io
import logging
import unittest

from keeper_secrets_manager_helper.v3.field_type import Login, Password

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
