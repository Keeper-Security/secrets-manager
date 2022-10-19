import unittest

from keeper_secrets_manager_core.dto.dtos import RecordCreate, RecordField
from keeper_secrets_manager_core.exceptions import KeeperError


class RecordTest(unittest.TestCase):

    def test_create_login_record(self):

        login_record_create = RecordCreate('CUSTOM TYPE', "Test record 1")
        login_record_create.fields = [
            RecordField(field_type='login', value='username@email.com'),
            RecordField(field_type='password', value='password1')
        ]
        login_record_create.notes = 'This is a Python\nrecord creation example'

        login_record_create_dict = login_record_create.to_dict()

        self.assertEqual("CUSTOM TYPE", login_record_create_dict.get('type'), "type didn't match")
        self.assertEqual("Test record 1", login_record_create_dict.get('title'), "title didn't match")

        self.assertEqual('login',                login_record_create_dict.get('fields')[0].get('type'), "type of the first field didn't match")
        self.assertEqual(['username@email.com'], login_record_create_dict.get('fields')[0].get('value'), "value of the first field didn't match")

        self.assertEqual('password',                login_record_create_dict.get('fields')[1].get('type'), "type of the second field didn't match")
        self.assertEqual(['password1'], login_record_create_dict.get('fields')[1].get('value'), "value of the second field didn't match")

        self.assertEqual('This is a Python\nrecord creation example', login_record_create_dict.get('notes'), "notes section didn't match")

    def test_wrong_notes_section_exception(self):
        login_record_create = RecordCreate('login', "Test record 1")
        login_record_create.notes = ['This is a Python', 'record creation example']

        self.assertRaises(KeeperError, login_record_create.to_dict)

    def test_wrong_fields_exception(self):
        login_record_create = RecordCreate('login', "Test record 1")
        login_record_create.notes = 'This is a test'

        login_record_create.fields = [
            RecordField(field_type='unknown1', value='username@email.com'),
            RecordField(field_type='unknown2', value=['value1']),
            RecordField(field_type='password', value='password1')
        ]

        self.assertRaises(KeeperError, login_record_create.to_dict)

    def test_notes_none(self):
        login_record_create = RecordCreate('CUSTOM TYPE', "Test record 1")
        login_record_create.fields = [
            RecordField(field_type='login', value='username@email.com'),
            RecordField(field_type='password', value='password1')
        ]
        login_record_create.notes = None

        login_record_create_dict = login_record_create.to_dict()

        self.assertEqual("CUSTOM TYPE", login_record_create_dict.get('type'), "type didn't match")
