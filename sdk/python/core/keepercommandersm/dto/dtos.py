#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import os

import requests

from keepercommandersm.exceptions import KeeperError
from keepercommandersm.utils import base64_to_bytes, decrypt_aes, decrypt_record, base64_to_str, json_to_dict


class Record:

    def __init__(self, record_dict, secret_key):
        self.uid = ''
        self.title = ''
        self.type = ''
        self.files = []
        self.raw_json = None
        self.dict = {}
        self.password = None

        self.uid = base64_to_str(record_dict.get('recordUid'))

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

            self.password = password_field.get('value')[0]

    def __str__(self):
        return 'Record: uid=%s, type: %s, title: %s, files count: %s' % (self.uid, self.type, self.title, str(len(self.files)))


class Folder:

    def __init__(self, folder, secret_key):

        self.uid = ''
        self.records = []

        if not folder.get('folderUid'):
            raise Exception("Not a folder")

        folder_uid = base64_to_str(folder.get('folderUid'))
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