import unittest
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig
import os
import tempfile


class MockTest(unittest.TestCase):
    """
    Test if mock is working correctly.
    """

    def setUp(self):

        self.orig_working_dir = os.getcwd()

    def tearDown(self):

        os.chdir(self.orig_working_dir)

    def test_field_order(self):
        """
        Make sure we get the fields in the order we added them. This is main for custom record
        where you can have multiple text types in the standard fields.
        """

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(config=FileKeyValueStorage(config_file_location=fh.name))

                res = mock.Response()

                one = res.add_record(title="")
                one.field("login", "My Login 1")
                one.field("password", "My Password 1")
                one.field("text", "Random Text")
                one.custom_field("My Custom 1", "custom1")
                one.custom_field("My Custom 2", "custom2")

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res)

                records = secrets_manager.get_secrets()
                self.assertEqual(len(records), 1, "didn't get 1 records")
                record = records[0]
                fields = record.dict.get("fields", [])
                self.assertEqual(3, len(fields), "did not find 3 standard fields")
                self.assertEqual("login", fields[0].get("type"))
                self.assertEqual("password", fields[1].get("type"))
                self.assertEqual("text", fields[2].get("type"))
                customs = record.dict.get("custom", [])
                self.assertEqual(2, len(customs), "did not find 3 standard fields")
                self.assertEqual("My Custom 1", customs[0].get("label"))
                self.assertEqual("My Custom 2", customs[1].get("label"))

        finally:
            try:
                os.unlink(fh.name)
            except IOError:
                pass
