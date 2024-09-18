# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2023 Keeper Security Inc.
# Contact: sm@keepersecurity.com
import json
import mimetypes
import os
from datetime import datetime
from pathlib import Path

import requests
from keeper_secrets_manager_core import utils, helpers
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.exceptions import KeeperError


class Record:

    def __init__(self, record_dict, secret_key, folder_uid = ''):
        self.uid = ''
        self.title = ''
        self.type = ''
        self.files = []
        self.raw_json = None
        self.dict = {}
        self.password = None
        self.revision = None
        self.is_editable = None
        self.folder_uid = ''
        self.inner_folder_uid = ''

        self.uid = record_dict.get('recordUid')

        if 'recordKey' in record_dict and record_dict.get('recordKey'):
            # Folder Share
            record_key_encrypted_str = record_dict.get('recordKey')
            record_key_encrypted_bytes = utils.base64_to_bytes(record_key_encrypted_str) if \
                record_key_encrypted_str else None

            self.record_key_bytes = CryptoUtils.decrypt_aes(record_key_encrypted_bytes, secret_key)
        else:
            # Single Record Share
            self.record_key_bytes = secret_key

        record_encrypted_data = record_dict.get('data')
        record_data_json = CryptoUtils.decrypt_record(record_encrypted_data, self.record_key_bytes)

        self.raw_json = record_data_json
        self.dict = utils.json_to_dict(self.raw_json)
        if self.dict and self.dict.get('fields') is None:
            self.dict['fields'] = []
        self.title = self.dict.get('title')
        self.type = self.dict.get('type')
        self.revision = record_dict.get('revision')
        self.is_editable = record_dict.get("isEditable")
        self.folder_uid = record_dict.get("folderUid", "") or folder_uid
        self.inner_folder_uid = record_dict.get("innerFolderUid")

        # files
        if record_dict.get('files'):
            for f in record_dict.get('files'):

                try:
                    file = KeeperFile(f, self.record_key_bytes)
                    self.files.append(file)
                except Exception as err:
                    msg = f"{err.__class__.__name__}, {str(err)}"
                    raise Exception(f"attached file caused exception: {msg}")

        # password (if `login` type)
        if self.type == 'login':

            fields = self.dict.get('fields')

            password_field = next((item for item in fields if item["type"] == "password"), None)

            # If the password field exists and there is a value in the array, then set the password.
            if password_field is not None and len(password_field.get('value', [])) > 0:
                self.password = password_field.get('value')[0]

    def find_file_by_title(self, title):
        """Finds file by file title"""

        found_file = next((f for f in self.files if f.title == title), None)

        return found_file

    def download_file_by_title(self, title, path):

        found_file = self.find_file_by_title(title)

        if not found_file:
            raise KeeperError("File %s not found" % title)

        found_file.save_file(path)

    def __str__(self):
        return '[Record: uid=%s, type: %s, title: %s, files count: %s]' % (self.uid, self.type, self.title,
                                                                           str(len(self.files)))

    def _update(self):

        """ Take the values in the diction and update the attributes and raw JSON
        """

        self.dict["title"] = self.title
        self.dict["type"] = self.type

        # Find the password in the field and update the password attribute
        password_field = next((item for item in self.dict["fields"] if item["type"] == "password"), None)
        if password_field is not None and len(password_field.get('value', [])) > 0:
            self.password = password_field.get('value')[0]

        self.raw_json = utils.dict_to_json(self.dict)

    @staticmethod
    def _value(values, single):

        if single is True:
            if values is None or len(values) == 0:
                return None
            return values[0]
        return values

    @staticmethod
    def _field_search(fields, field_key):

        """ This is a generic field search that returns the field

        It will work for for both standard and custom fields. It
        returns the field as a dictionary.
        """

        # First check in the field_key matches any labels. Label matching is case sensitive.
        found_item = None
        for item in fields:
            if item.get("label") is not None and item.get("label") == field_key:
                found_item = item
                break
        # If the label was not found, check the field type. Field type is case insensitive.
        if found_item is None:
            for item in fields:
                if item.get("type").lower() == field_key.lower():
                    found_item = item
                    break

        return found_item

    def get_standard_field(self, field_type):
        return self._field_search(fields=self.dict.get('fields', []), field_key=field_type)

    def get_standard_field_value(self, field_type, single=False):
        field = self.get_standard_field(field_type)
        if field is None:
            raise ValueError("Cannot find standard field {} in record".format(field_type))
        return Record._value(field.get("value", []), single)

    def set_standard_field_value(self, field_type, value):
        field = self.get_standard_field(field_type)
        if field is None:
            raise ValueError("Cannot find standard field {} in record".format(field_type))
        if type(value) is not list:
            value = [value]
        field["value"] = value
        self._update()

    def get_custom_field(self, field_type):
        return self._field_search(fields=self.dict.get('custom', []), field_key=field_type)

    def get_custom_field_value(self, field_type, single=False):
        field = self.get_custom_field(field_type)
        if field is None:
            raise ValueError("Cannot find custom field {} in record".format(field_type))
        return Record._value(field.get("value", []), single)

    def set_custom_field_value(self, field_type, value):
        field = self.get_custom_field(field_type)
        if field is None:
            raise ValueError("Cannot find custom field {} in record".format(field_type))
        if type(value) is not list:
            value = [value]
        field["value"] = value
        self._update()

    def add_custom_field(self, field=None, field_type=None, label=None, value=None) -> bool:
        if self.dict.get('custom', None) is None:
            self.dict['custom'] = []
        custom = self.dict['custom']

        # Make backward compatible. Assumes keeper_secrets_manager_helper.v#.field_type.FieldType is passed in.
        if field is not None:
            if field.__class__.__name__ != "FieldType":
                raise ValueError("The field is not an instance of FieldType")
            fdict = field.to_dict()
            custom.append(fdict)
        else:
            if field_type is None:
                return False
            if isinstance(value, list) is False:
                value = [value]
            field_dict = {
                "type": field_type,
                "value": value
            }
            if label is not None:
                field_dict["label"] = label
            custom.append(field_dict)

        self._update()
        return True

    # TODO: Deprecate this for better getter and setters
    def field(self, field_type, value=None, single=False):

        """ Getter and setter for standard fields

        A getter operation is performed when the 'value' parameter is not passed. For example, this would
        return the value.

            record.field("login")

        A setter operation is performed when a 'value'  parameter is passed. For example, this would set
        the value in the field.

            record.field("login", value="My New Value")
        """

        field = self._field_search(fields=self.dict.get('fields', []), field_key=field_type)

        if field is None:
            raise ValueError("Cannot find the field for {}".format(field_type))

        if value is None:
            value = Record._value(field["value"], single)
        else:
            if type(value) is not list:
                value = [value]
            field["value"] = value
            self._update()

        return value

    # TODO: Deprecate this for better getter and setters
    def custom_field(self, label=None, value=None, field_type=None, single=False):

        custom_field = None
        if label is not None:
            custom_field = self._field_search(fields=self.dict.get('custom', []), field_key=label)
            if custom_field is None and field_type is not None:
                custom_field = self._field_search(fields=self.dict.get('custom', []), field_key=field_type)

        if custom_field is None:
            raise ValueError("Cannot find the custom field label='{}', field type='{}'.".format(label, field_type))

        if value is None:
            value = Record._value(custom_field["value"], single)
        else:
            if type(value) is not list:
                value = [value]
            custom_field["value"] = value
            self._update()

        return value

    def print(self):

        print("===")
        print("Title: {}".format(self.title))
        print("UID:   {}".format(self.uid))
        print("Type:  {}".format(self.type))
        print("")
        print("Fields")
        print("------")

        for item in self.dict.get('fields'):
            if item["type"] in ["fileRef", "oneTimeCode"]:
                continue
            print("{} : {}".format(item["type"], ", ".join(item["value"])))

        print("")
        print("Custom Fields")
        print("------")
        for item in self.dict.get('custom', []):
            print("{} ({}) : {}".format(item["label"], item["type"], ", ".join(item["value"])))


class KeeperFolder:
    def __init__(self, folder_key, folder_uid:str, parent_uid:str, name:str):
        self.folder_key = folder_key
        self.folder_uid = folder_uid
        self.parent_uid = parent_uid
        self.name = name


class Folder:

    def __init__(self, folder, secret_key):

        self.uid = ''
        self.records = []

        if not folder.get('folderUid'):
            raise Exception("Not a folder")

        folder_uid = folder.get('folderUid')
        folder_key_enc = folder.get('folderKey')
        folder_key = CryptoUtils.decrypt_aes(utils.base64_to_bytes(folder_key_enc), secret_key)
        folder_records = folder.get('records')

        self.key = folder_key
        self.uid = folder_uid
        self.parent_uid = folder.get('parentUid', '')
        self.name = folder.get('name', '')

        for r in folder_records:

            record = Record(r, folder_key, folder_uid)
            self.records.append(record)


class KeeperFile:

    def __init__(self, f, record_key_bytes):

        self.file_key = ''
        self.meta_dict = None

        self.file_data = None

        self.name = ''
        self.title = ''
        self.type = ''
        self.last_modified = 0
        self.size = 0

        self.f = f
        self.record_key_bytes = record_key_bytes

        # Set file metadata

        meta = self.__get_meta()

        self.title = meta.get('title')
        self.name = meta.get('name')
        self.type = meta.get('type')
        self.last_modified = meta.get('lastModified')
        self.size = meta.get('size')

    def __decrypt_file_key(self):
        file_key_encrypted_base64 = self.f.get('fileKey')
        file_key_encrypted = utils.base64_to_bytes(file_key_encrypted_base64)
        file_key = CryptoUtils.decrypt_aes(file_key_encrypted, self.record_key_bytes)
        return file_key

    def __get_meta(self):
        """
        Returns file metadata dictionary (file name, title, size, type, etc.)
        """
        if not self.meta_dict:
            file_key = self.__decrypt_file_key()

            meta_json = CryptoUtils.decrypt_aes(utils.base64_to_bytes(self.f.get('data')), file_key)

            self.meta_dict = utils.json_to_dict(meta_json)

        return self.meta_dict

    def get_file_data(self):
        """
        Return decrypted raw file data
        """
        if not self.file_data:    # cached if nothing
            file_key = self.__decrypt_file_key()
            file_url = self.f.get('url')

            rs = requests.get(file_url)

            file_encrypted_data = rs.content

            self.file_data = CryptoUtils.decrypt_aes(file_encrypted_data, file_key)

        return self.file_data

    def save_file(self, path, create_folders=False):
        """
        Save decrypted file data to the provided path
        """

        if create_folders:
            os.makedirs(os.path.dirname(path), exist_ok=True)

        file_data = self.get_file_data()

        dir_path = os.path.dirname(os.path.abspath(path))

        if not os.path.exists(dir_path):
            raise KeeperError("No such file or directory %s\nConsider adding `create_folders=True` to `save_file()` "
                              "method " % path)

        file = open(path, "wb")

        file.write(file_data)
        file.close()

        return True

    def __str__(self):
        return "[KeeperFile - name: %s, title: %s]" % (self.name, self.title)


class KeeperFileUpload:

    def __init__(self, name=None, title=None, mime_type=None, data=None):
        self.Name = name
        self.Title = title
        self.Type = mime_type
        self.Data = data

    @staticmethod
    def from_file(path, file_name=None, file_title=None, mime_type=None):

        """Helper method to get Keeper File Upload object from the file path"""
        file_name = file_name if file_name else Path(path).name
        file_title = file_title if file_title else file_name

        if not mime_type:
            mime_type = mimetypes.guess_type(path)[0]

            if not mime_type:
                # fall back to `application/octet-stream` if type was not determined
                mime_type = 'application/octet-stream'

        in_file = open(path, 'rb')  # opening for [r]eading as [b]inary
        file_bytes_data = in_file.read()

        file_upload = KeeperFileUpload(name=file_name, title=file_title, mime_type=mime_type, data=file_bytes_data)

        return file_upload


class KeeperFileData:

    def __init__(self):
        self.name = None
        self.size = None
        self.title = None
        self.lastModified = None
        self.type = None


VALID_RECORD_FIELDS = [
    'accountNumber', 'address', 'addressRef', 'appFiller', 'bankAccount',
    'birthDate', 'cardRef', 'checkbox', 'databaseType', 'date',
    'directoryType', 'dropdown', 'email', 'expirationDate', 'fileRef', 'host',
    'isSSIDHidden', 'keyPair', 'licenseNumber', 'login', 'multiline', 'name',
    'note', 'oneTimeCode', 'otp', 'pamHostname', 'pamRemoteBrowserSettings',
    'pamResources', 'pamSettings', 'passkey', 'password', 'paymentCard',
    'phone', 'pinCode', 'rbiUrl', 'recordRef', 'schedule', 'script', 'secret',
    'securityQuestion', 'text', 'trafficEncryptionSeed', 'url',
    'wifiEncryption'
]


class RecordField:

    def __init__(self, field_type=None, value=None, label=None, required=None, enforceGeneration=None,
                 privacyScreen=None, complexity=None):

        self.type = field_type

        if isinstance(value, list):
            self.value = value
        else:
            self.value = [value] if value else []

        if label:
            self.label = label
        if required:
            self.required = required
        if enforceGeneration:
            self.enforceGeneration = enforceGeneration
        if privacyScreen:
            self.privacyScreen = privacyScreen
        if complexity:
            self.complexity = complexity


class RecordCreate:

    def __init__(self, record_type, title):

        self.record_type = record_type
        self.title = title
        self.notes = None
        self.fields = None
        self.custom = None

    def _validate(self):

        # Validate title
        if not isinstance(self.title, str):
            raise KeeperError(f"Record title should be a string. Provided type {type(self.title)}")

        # Validate notes
        if self.notes and not isinstance(self.notes, str):
            raise KeeperError(f"Record notes should be a string. Provided type {type(self.notes)}")

        field_type_errors = []
        field_value_errors = []

        if self.fields:
            for field in self.fields:
                field_type = field.type
                if field_type not in VALID_RECORD_FIELDS:
                    field_type_errors.append(field_type)

                field_value = field.value
                if not isinstance(field_value, list):
                    field_value_errors.append(field_type)

            # Validate field types - only legit field type names
            if len(field_type_errors) > 0:
                raise KeeperError(f"Following field types are not allowed [{', '.join(field_type_errors)}]. "
                                  f"Allowed field types are [{', '.join(VALID_RECORD_FIELDS)}]")

            # Validate field values - arrays only
            if len(field_value_errors) > 0:
                raise KeeperError(f"Fields with the following types are of a list type [{', '.join(field_value_errors)}]. "
                                  f"Make sure that those fields have values as a list type")

    def to_dict(self):

        self._validate()

        rec_dict = {
            'type': self.record_type,
            'title': self.title,
            'fields': self.fields,
        }

        if self.notes:
            rec_dict['notes'] = self.notes

        if self.custom:
            rec_dict['custom'] = self.custom

        return helpers.obj_to_dict(rec_dict)

    def to_json(self):

        json_object = json.dumps(self.to_dict(), indent=4)
        return json_object


class AppData:
    """
    Application info
    """
    def __init__(self, title="", app_type=""):
        self.title = title
        self.app_type = app_type


class SecretsManagerResponse:

    """
    Server response contained details about the application and the records
    that were requested to be returned
    """
    def __init__(self):
        self.appData = None
        # self.encryptedAppKey = None
        # self.appOwnerPublicKey = None
        self.folders = None
        self.records = None
        self.expiresOn = None
        self.warnings = None
        self.justBound = False
        self.bad_records = []
        self.bad_folders = []

    def expires_on_str(self, date_format='%Y-%m-%d %H:%M:%S'):
        """
        Retrieve string formatted expiration date
        """
        return datetime.fromtimestamp(self.expiresOn/1000).strftime(date_format)

    @property
    def had_bad_records(self):
        return len(self.bad_records) > 0

    @property
    def had_bad_folders(self):
        return len(self.bad_folders) > 0


class SecretsManagerAddFileResponse:

    def __init__(self):
        self.url = None
        self.parameters = None
        self.successStatusCode = None
