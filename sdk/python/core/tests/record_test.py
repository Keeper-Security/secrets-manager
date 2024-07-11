import os
import tempfile
import unittest
import logging

from keeper_secrets_manager_core.storage import FileKeyValueStorage
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.dto.dtos import helpers, RecordField


class RecordTest(unittest.TestCase):

    def setUp(self):

        self.orig_working_dir = os.getcwd()

        logger = logging.getLogger("ksm")
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        while logger.hasHandlers():
            logger.removeHandler(logger.handlers[0])
        handler = logging.StreamHandler()
        logger.addHandler(handler)
        formatter = logging.Formatter(f'%(asctime)s %(name)s  %(levelname)s: %(message)s')
        handler.setFormatter(formatter)

        logger.debug("Start test logging")


    def tearDown(self):

        os.chdir(self.orig_working_dir)

    def test_the_login_record_password(self):
        """ If the record type is login, the password will be placed
            in the instance attribute.
        """

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name))

                # A good record.
                # 'fields':[{'type': 'password', 'value': ['My Password']}...]
                good_res = mock.Response()
                good = good_res.add_record(
                    title="Good Record", record_type='login')
                good.field("login", "My Login")
                good.field("password", "My Password")

                # A bad record. This would be like if someone removed
                # a password text from an existing field.
                # 'fields': [...{'type': 'password', 'value': []}...]
                bad_res = mock.Response()
                bad = bad_res.add_record(
                    title="Bad Record", record_type='login')
                bad.field("login", "My Login")
                bad.field("password", [])

                # An ugly record. The application didn't even add the field.
                # We need to set flags to prune empty fields.
                # 'fields': [...]
                ugly_res = mock.Response(flags={"prune_empty_fields": True})
                ugly = ugly_res.add_record(
                    title="Ugly Record", record_type='login')
                ugly.field("login", "My Login")

                # this will be removed from the fields array.
                ugly.field("password", [])

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(good_res)
                res_queue.add_response(bad_res)
                res_queue.add_response(ugly_res)

                records = secrets_manager.get_secrets()
                self.assertEqual(
                    1, len(records), "didn't get 1 record for the good")
                self.assertEqual(
                    "My Password", records[0].password,
                    "did not get correct password for the good")

                records = secrets_manager.get_secrets()
                self.assertEqual(
                    1, len(records), "didn't get 1 record for the bad")
                self.assertIsNone(records[0].password,
                                  "password is defined for the bad")

                records = secrets_manager.get_secrets()
                self.assertEqual(
                    1, len(records), "didn't get 1 record for the ugly")
                self.assertIsNone(records[0].password,
                                  "password is defined for the ugly")
        finally:
            try:
                os.unlink(fh.name)
            except OSError:
                pass

    def test_record_field(self):

        rf = RecordField(field_type="login", value="test", label="Test",
                         required=True, enforceGeneration=False,
                         privacyScreen=True, complexity={"foo": "bar"})

        value = helpers.obj_to_dict(rf)
        self.assertEqual("login", value.get("type"), "type is not correct")
        self.assertEqual(["test"], value.get("value"), "value is not correct")
        self.assertEqual("Test", value.get("label"), "label is not correct")
        self.assertTrue(value.get("required"), "required is not correct")
        self.assertFalse(value.get("enforceGeneration"),
                         "enforceGeneration is not correct")
        self.assertTrue(value.get("privacyScreen"),
                        "privacyScreen is not correct")
        self.assertIsNotNone(value.get("complexity"),
                             "complexity is not correct")

        rf = RecordField(field_type="login", value="test", privacyScreen=None)

        value = helpers.obj_to_dict(rf)
        self.assertEqual("login", value.get("type"), "type is not correct")
        self.assertEqual(["test"], value.get("value"), "value is not correct")
        self.assertIsNone(value.get("label"), "label is not correct")
        self.assertIsNone(value.get("required"), "required is not correct")
        self.assertIsNone(value.get("enforceGeneration"),
                          "enforceGeneration is not correct")
        assert "privacyScreen" not in value, "privacyScreen exists in dictionary"
        self.assertIsNone(value.get("privacyScreen"),
                          "privacyScreen is not correct")
        self.assertIsNone(value.get("complexity"), "complexity is not correct")

    def test_add_custom_field_by_param(self):

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(config=FileKeyValueStorage(config_file_location=fh.name))

                res = mock.Response()
                mock_record = res.add_record(title="Good Record", record_type='login')
                mock_record.field("login", "My Login")
                mock_record.field("password", "My Password")

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res)

                records = secrets_manager.get_secrets()
                record = records[0]

                record.add_custom_field(
                    field_type='text',
                    label="My Label",
                    value="My Value"
                )
                new_value = record.get_custom_field("My Label")
                self.assertEqual("text", new_value.get("type"))
                self.assertEqual("My Label", new_value.get("label"))
                self.assertEqual(['My Value'], new_value.get("value"))
        finally:
            try:
                os.unlink(fh.name)
            except OSError:
                pass

    def test_add_custom_field_by_field_type(self):

        class FieldType:

            def __init__(self, field_type, label, value):
                self.field_type = field_type
                self.label = label
                self.value = value

            def to_dict(self):
                return {
                    "type": self.field_type,
                    "label": self.label,
                    "value": self.value
                }

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(config=FileKeyValueStorage(config_file_location=fh.name))

                res = mock.Response()
                mock_record = res.add_record(title="Good Record", record_type='login')
                mock_record.field("login", "My Login")
                mock_record.field("password", "My Password")

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res)

                records = secrets_manager.get_secrets()
                record = records[0]

                field = FieldType(
                    field_type="text",
                    label="My Label",
                    value=["My Value"]
                )

                record.add_custom_field(field=field)

                new_value = record.get_custom_field("My Label")
                self.assertEqual("text", new_value.get("type"))
                self.assertEqual("My Label", new_value.get("label"))
                self.assertEqual(['My Value'], new_value.get("value"))
        finally:
            try:
                os.unlink(fh.name)
            except OSError:
                pass

    def test_missing_fields_section(self):
        """ Test for clients that may set "fields": null in JSON data """

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name))

                res = mock.Response()
                rec = res.add_record(title="MyLogin", record_type='login')
                res.records[rec.uid]._fields = None
                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res)

                records = secrets_manager.get_secrets()
                self.assertEqual(
                    1, len(records), "didn't get 1 record for MyLogin")
                self.assertEqual([], records[0].dict.get('fields'))
        finally:
            try:
                os.unlink(fh.name)
            except OSError:
                pass

    def test_record_bad_encryption(self):
        """ Test for clients that may set "fields": null in JSON data """

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name),
                    log_level=logging.INFO
                )

                res = mock.Response()

                good_record = res.add_record(title="Good Record", record_type='login')
                good_record.field("login", "My Login")
                good_record.field("password", "My Password")

                res.add_record(title="MyLogin", record_type='login', has_bad_encryption=True)

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res)

                records = secrets_manager.get_secrets()
                self.assertEqual(1, len(records), "did not get 1 record")

        finally:
            try:
                os.unlink(fh.name)
            except OSError:
                pass

    def test_folder_bad_encryption(self):
        """ Test for clients that may set "fields": null in JSON data """

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name),
                    log_level=logging.DEBUG
                )

                res = mock.Response()

                good_folder = res.add_folder()

                good_record = good_folder.add_record(title="Good Record", record_type='login')
                good_record.field("login", "My Login")
                good_record.field("password", "My Password")

                bad_folder = res.add_folder(has_bad_encryption=True)
                bad_folder.add_record(title="MyLogin", record_type='login')

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res)

                records = secrets_manager.get_secrets()
                self.assertEqual(1, len(records), "didn't get any records")

        finally:
            try:
                os.unlink(fh.name)
            except OSError:
                pass

    def test_file_bad_encryption(self):
        """ Test for clients that may set "fields": null in JSON data """

        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name),
                    log_level=logging.INFO
                )

                res = mock.Response()

                good_record = res.add_record(title="Good Record", record_type='login')
                good_record.field("login", "My Login")
                good_record.field("password", "My Password")

                ok_record = res.add_record(title="MyLogin", record_type='login')
                ok_record.add_file(name="BAD FILE", has_bad_encryption=True)

                res_queue = mock.ResponseQueue(client=secrets_manager)
                res_queue.add_response(res)

                records = secrets_manager.get_secrets()
                self.assertEqual(1, len(records), "did not get 1 record")
        finally:
            try:
                os.unlink(fh.name)
            except OSError:
                pass
