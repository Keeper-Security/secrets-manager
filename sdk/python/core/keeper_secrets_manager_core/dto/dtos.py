#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com

import os

import requests

from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.utils import base64_to_bytes, decrypt_aes, decrypt_record, json_to_dict, dict_to_json


class Record:

    def __init__(self, record_dict, secret_key):
        self.uid = ''
        self.title = ''
        self.type = ''
        self.files = []
        self.raw_json = None
        self.dict = {}
        self.password = None

        self.uid = record_dict.get('recordUid')

        if 'recordKey' in record_dict and record_dict.get('recordKey'):
            # Folder Share
            record_key_encrypted_str = record_dict.get('recordKey')
            record_key_encrypted_bytes = base64_to_bytes(record_key_encrypted_str) if record_key_encrypted_str else None

            self.record_key_bytes = decrypt_aes(record_key_encrypted_bytes, secret_key)
        else:
            # Single Record Share
            self.record_key_bytes = secret_key

        record_encrypted_data = record_dict.get('data')
        record_data_json = decrypt_record(record_encrypted_data, self.record_key_bytes)

        self.raw_json = record_data_json
        self.dict = json_to_dict(self.raw_json)
        self.title = self.dict.get('title')
        self.type = self.dict.get('type')

        # files
        if record_dict.get('files'):
            for f in record_dict.get('files'):

                file = KeeperFile(f, self.record_key_bytes)

                self.files.append(file)

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

    def download_file_by_title(self, title, path, ):

        found_file = self.find_file_by_title(title)

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
        self.password = password_field.get('value')[0]

        self.raw_json = dict_to_json(self.dict)

    @staticmethod
    def _value(values, single):

        if single is True:
            return values[0]
        return values

    def field(self, field_type, value=None, single=False):

        found_item = None
        for item in self.dict.get('fields'):
            if item["type"] == field_type.lower():
                found_item = item
                break
        if found_item is None:
            raise ValueError("Cannot find the field '{}'.".format(field_type))

        if value is None:
            value = Record._value(found_item["value"], single)
        else:
            if type(value) is not list:
                value = [value]
            found_item["value"] = value
            self._update()

        return value

    def custom_field(self, label, value=None, field_type=None, single=False):

        found_item = None
        for item in self.dict.get('custom', []):
            found = False

            # If the user doesn't set the label in the UI, and uses the default, the label will be missing :/
            # Set the label to the type.
            if item.get("label") is None:
                item["label"] = item["type"]

            if item["label"] == label:
                # We can have duplicate labels, so allow type to be used too.
                if field_type is not None:
                    if item["type"] == field_type.lower():
                        found = True
                else:
                    found = True
            if found is True:
                found_item = item
                break

        if found_item is None:
            raise ValueError("Cannot find the custom field label='{}', field type='{}'.".format(label, field_type))

        if value is None:
            value = Record._value(found_item["value"], single)
        else:
            if type(value) is not list:
                value = [value]
            found_item["value"] = value
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


class Folder:

    def __init__(self, folder, secret_key):

        self.uid = ''
        self.records = []

        if not folder.get('folderUid'):
            raise Exception("Not a folder")

        folder_uid = folder.get('folderUid')
        folder_key_enc = folder.get('folderKey')
        folder_key = decrypt_aes(base64_to_bytes(folder_key_enc), secret_key)
        folder_records = folder.get('records')

        self.uid = folder_uid
        for r in folder_records:

            record = Record(r, folder_key)
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
        file_key_encrypted = base64_to_bytes(file_key_encrypted_base64)
        file_key = decrypt_aes(file_key_encrypted, self.record_key_bytes)
        return file_key

    def __get_meta(self):
        """
        Returns file metadata dictionary (file name, title, size, type, etc.)
        """
        if not self.meta_dict:
            file_key = self.__decrypt_file_key()

            meta_json = decrypt_aes(base64_to_bytes(self.f.get('data')), file_key)

            self.meta_dict = json_to_dict(meta_json)

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

            self.file_data = decrypt_aes(file_encrypted_data, file_key)

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
