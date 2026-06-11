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
import base64
import json
import logging
import mimetypes
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import requests
from keeper_secrets_manager_core import utils, helpers
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.keeper_globals import logger_name


class Record:

    def __init__(self, record_dict, secret_key, folder_uid = ''):
        self.uid = ''
        self.title = ''
        self.type = ''
        self.files = []
        self.raw_json = None
        self.dict = {}
        self.links = []  # [{"recordUid":"", "data": null|base64, "path": null|string} ...]
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

    def get_links(self) -> List["KeeperRecordLink"]:
        """Return this record's linked-credential entries as typed KeeperRecordLink objects.

        Typed view over the raw `links` list (populated when secrets are fetched with
        `QueryOptions(..., request_links=True)`). The raw `links` list of dicts is kept
        unchanged for backward compatibility; entries without a `recordUid` string are
        skipped here.

        :return: List of KeeperRecordLink, empty when the record has no links
        """
        links = []
        for link_dict in self.links or []:
            if not isinstance(link_dict, dict):
                continue
            record_uid = link_dict.get("recordUid")
            if not record_uid or not isinstance(record_uid, str):
                continue
            links.append(KeeperRecordLink(link_dict))
        return links

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


class KeeperRecordLink:
    """Typed view over a single linked-credential entry of a record (`record.links`).

    A link entry carries `recordUid`, optional base64 `data`, and an optional `path`
    discriminator. Observed payload shapes (verified against the live backend):

    - path "meta" (self-link, recordUid == owning record): plain base64 JSON with
      `allowedSettings` (rotation, connections, portForwards, sessionRecording,
      typescriptRecording, aiEnabled, aiSessionTerminate, remoteBrowserIsolation),
      plus `rotateOnTermination`, `version` and `no_update_services`.
    - path None (credential link to another record): plain base64 JSON with
      `is_admin`, `is_launch_credential`, `is_iam_user`, `belongs_to` and
      `rotation_settings`; or no data at all (pure record reference).
    - path "ai_settings" / "jit_settings" (self-links): data is AES-256-GCM
      encrypted under the owning record's key — see get_decrypted_data().

    Accessors mirror the Java SDK's KeeperRecordLink API and never raise: parse,
    decode or decryption failures yield None/False. The original link dict is kept
    untouched in `raw`, and get_link_data() returns the complete parsed payload, so
    fields unknown to this SDK version are always preserved.
    """

    def __init__(self, link_dict):
        if not isinstance(link_dict, dict):
            link_dict = {}
        self.raw = dict(link_dict)
        self.record_uid = link_dict.get("recordUid")
        self.data = link_dict.get("data")
        self.path = link_dict.get("path")

    def __str__(self):
        return '[KeeperRecordLink: record_uid=%s, path=%s]' % (self.record_uid, self.path)

    def _parse_json_data(self) -> Optional[dict]:
        """Decode `data` and parse it as a JSON object, handling errors gracefully."""
        decoded = self.get_decoded_data()
        if decoded is None or not (decoded.startswith("{") or decoded.startswith("[")):
            # Not present, or likely encrypted/binary data - nothing to parse.
            return None
        try:
            parsed = json.loads(decoded)
        except ValueError as err:
            logging.getLogger(logger_name).debug(
                "KeeperRecordLink: failed to parse JSON link data - {}".format(err))
            return None
        if not isinstance(parsed, dict):
            logging.getLogger(logger_name).debug(
                "KeeperRecordLink: link data is not a JSON object (was JSON array or primitive)")
            return None
        return parsed

    def _get_boolean_value(self, key, check_allowed_settings=False) -> bool:
        """Read a strict boolean from the link data; missing or non-bool values are False.

        With check_allowed_settings=True the nested `allowedSettings` object is
        consulted when the key is absent at the top level (a top-level boolean wins).
        """
        parsed = self._parse_json_data()
        if parsed is None:
            return False
        value = parsed.get(key)
        if isinstance(value, bool):
            return value
        if check_allowed_settings:
            allowed_settings = parsed.get("allowedSettings")
            if isinstance(allowed_settings, dict):
                value = allowed_settings.get(key)
                if isinstance(value, bool):
                    return value
        return False

    def _get_int_value(self, key) -> Optional[int]:
        """Read a strict integer from the link data; strings and booleans yield None."""
        parsed = self._parse_json_data()
        value = parsed.get(key) if parsed else None
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        return None

    def is_admin_user(self) -> bool:
        """Whether the linked user is an admin (`is_admin`)."""
        return self._get_boolean_value("is_admin")

    def is_launch_credential(self) -> bool:
        """Whether this is a launch credential link (`is_launch_credential`)."""
        return self._get_boolean_value("is_launch_credential")

    def is_iam_user(self) -> bool:
        """Whether the linked user is an IAM user (`is_iam_user`)."""
        return self._get_boolean_value("is_iam_user")

    def belongs_to(self) -> bool:
        """Whether the linked credential belongs to the record (`belongs_to`)."""
        return self._get_boolean_value("belongs_to")

    def no_update_services(self) -> bool:
        """Whether service updates are disabled for this link (`no_update_services`)."""
        return self._get_boolean_value("no_update_services")

    def allows_rotation(self) -> bool:
        """Whether rotation is allowed (`rotation`, top-level or in `allowedSettings`)."""
        return self._get_boolean_value("rotation", check_allowed_settings=True)

    def allows_connections(self) -> bool:
        """Whether connections are allowed (`connections`, top-level or in `allowedSettings`)."""
        return self._get_boolean_value("connections", check_allowed_settings=True)

    def allows_port_forwards(self) -> bool:
        """Whether port forwards are allowed (`portForwards`, top-level or in `allowedSettings`)."""
        return self._get_boolean_value("portForwards", check_allowed_settings=True)

    def allows_session_recording(self) -> bool:
        """Whether session recording is enabled (`sessionRecording`, top-level or in `allowedSettings`)."""
        return self._get_boolean_value("sessionRecording", check_allowed_settings=True)

    def allows_typescript_recording(self) -> bool:
        """Whether typescript recording is enabled (`typescriptRecording`, top-level or in `allowedSettings`)."""
        return self._get_boolean_value("typescriptRecording", check_allowed_settings=True)

    def allows_remote_browser_isolation(self) -> bool:
        """Whether remote browser isolation is enabled (`remoteBrowserIsolation`, top-level or in `allowedSettings`)."""
        return self._get_boolean_value("remoteBrowserIsolation", check_allowed_settings=True)

    def ai_enabled(self) -> bool:
        """Whether AI features are enabled (`aiEnabled`, top-level or in `allowedSettings`)."""
        return self._get_boolean_value("aiEnabled", check_allowed_settings=True)

    def ai_session_terminate(self) -> bool:
        """Whether AI session termination is enabled (`aiSessionTerminate`, top-level or in `allowedSettings`)."""
        return self._get_boolean_value("aiSessionTerminate", check_allowed_settings=True)

    def rotates_on_termination(self) -> bool:
        """Whether rotation on termination is enabled (`rotateOnTermination`)."""
        return self._get_boolean_value("rotateOnTermination")

    def get_link_data_version(self) -> Optional[int]:
        """The link data schema version (`version`) when it is an integer, else None."""
        return self._get_int_value("version")

    def get_allowed_settings(self) -> dict:
        """The `allowedSettings` object from the link data (empty dict when absent)."""
        parsed = self._parse_json_data()
        allowed_settings = parsed.get("allowedSettings") if parsed else None
        return allowed_settings if isinstance(allowed_settings, dict) else {}

    def get_rotation_settings(self) -> Optional[dict]:
        """The `rotation_settings` object from the link data (schedule, pwd_complexity,
        disabled, noop, saas_record_uid_list), or None when absent."""
        parsed = self._parse_json_data()
        rotation_settings = parsed.get("rotation_settings") if parsed else None
        return rotation_settings if isinstance(rotation_settings, dict) else None

    def get_decoded_data(self) -> Optional[str]:
        """Base64-decode `data` to a string (for debugging/advanced use), or None."""
        if self.data is None:
            return None
        try:
            decoded_bytes = base64.b64decode(self.data)
        except (ValueError, TypeError) as err:
            logging.getLogger(logger_name).debug(
                "KeeperRecordLink: failed to decode base64 data - {}".format(err))
            return None
        return decoded_bytes.decode("utf-8", errors="replace")

    def has_readable_data(self) -> bool:
        """Whether the link has readable JSON data (vs. encrypted/binary data)."""
        decoded = self.get_decoded_data()
        return decoded is not None and (decoded.startswith("{") or decoded.startswith("["))

    def might_be_encrypted(self) -> bool:
        """Whether this link's path indicates potentially encrypted data.

        Currently known encrypted paths: ai_settings, jit_settings. Other paths
        (including "meta") carry plain base64 JSON.
        """
        return self.path in ("ai_settings", "jit_settings")

    def has_encrypted_data(self) -> bool:
        """Whether the data appears encrypted, by inspecting the actual content
        (non-JSON and mostly non-printable) rather than path naming conventions."""
        decoded = self.get_decoded_data()
        if decoded is None:
            return False
        if decoded.startswith("{") or decoded.startswith("["):
            return False
        return not KeeperRecordLink._is_printable_text(decoded)

    def get_decrypted_data(self, record_key=None) -> Optional[str]:
        """Decrypt the link data with the owning record's key (AES-256-GCM).

        :param record_key: The record's encryption key bytes (record.record_key_bytes)
        :return: Decrypted string data, or None if data/key is missing or decryption fails
        """
        if self.data is None or record_key is None:
            return None
        try:
            encrypted_data = base64.b64decode(self.data)
            decrypted_bytes = CryptoUtils.decrypt_aes(encrypted_data, record_key)
            return decrypted_bytes.decode("utf-8", errors="replace")
        except Exception:
            # Wrong key, malformed base64 or data that is not encrypted.
            return None

    def get_link_data(self, record_key=None) -> Optional[dict]:
        """Get the complete link data payload, handling both plain and encrypted JSON.

        Plain base64 JSON parses without a key; encrypted data requires the owning
        record's key. The returned dict preserves all fields sent by the server,
        including ones this SDK version doesn't know about yet.

        :param record_key: Optional record key bytes for encrypted link data
        :return: Parsed payload as a dict, or None if parsing fails
        """
        decoded = self.get_decoded_data()
        if decoded is None:
            return None
        if decoded.startswith("{") or decoded.startswith("["):
            return KeeperRecordLink._parse_json_to_dict(decoded)
        decrypted = self.get_decrypted_data(record_key)
        if decrypted is None:
            return None
        return KeeperRecordLink._parse_json_to_dict(decrypted)

    def get_meta_data(self, record_key=None) -> Optional[dict]:
        """Get PAM settings data from this link - only when path == "meta".

        Meta links are self-links (recordUid == owning record) carrying the record's
        own PAM settings: `allowedSettings`, `rotateOnTermination`, `version`,
        `no_update_services`. Plain JSON today; the key is accepted for forward
        compatibility.
        """
        return self.get_settings_for_path("meta", record_key)

    def get_ai_settings_data(self, record_key) -> Optional[dict]:
        """Get AI settings data from this link - only when path == "ai_settings".

        Encrypted under the owning record's key. Known fields: `version` (string,
        e.g. "v1.0.0") and `riskLevels` (critical/high/medium/low, each with `tags`
        allow/deny lists and `aiSessionTerminate`). Additional fields may be present
        in newer versions; the returned dict preserves all of them.

        :param record_key: The record's encryption key bytes
        :return: Settings data as a dict, or None if not available
        """
        if self.path != "ai_settings":
            return None
        return self.get_link_data(record_key)

    def get_jit_settings_data(self, record_key) -> Optional[dict]:
        """Get JIT (Just-In-Time) settings data from this link - only when path == "jit_settings".

        Encrypted under the owning record's key. Known fields: `createEphemeral`,
        `elevate`, `elevationMethod`, `elevationString`, `baseDistinguishedName`.
        Additional fields may be present in newer versions; the returned dict
        preserves all of them.

        :param record_key: The record's encryption key bytes
        :return: Settings data as a dict, or None if not available
        """
        if self.path != "jit_settings":
            return None
        return self.get_link_data(record_key)

    def get_settings_for_path(self, settings_path, record_key=None) -> Optional[dict]:
        """Get settings data for any path, current or future.

        Automatically detects whether the data is plain or encrypted and handles
        it appropriately.

        :param settings_path: The path to match (e.g. "meta", "ai_settings")
        :param record_key: The record's encryption key bytes (required for encrypted data)
        :return: Settings data as a dict, or None if the path doesn't match or parsing fails
        """
        if self.path != settings_path:
            return None
        return self.get_link_data(record_key)

    @staticmethod
    def _parse_json_to_dict(json_str) -> Optional[dict]:
        """Parse a JSON string, returning a dict only for JSON objects."""
        try:
            parsed = json.loads(json_str)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None

    @staticmethod
    def _is_printable_text(text) -> bool:
        """Whether a string is mostly printable text (>90% of the first 100 chars),
        used to distinguish encrypted bytes from plain text."""
        if not text:
            return False
        sample = text[:100]
        printable_count = sum(1 for c in sample if ' ' <= c <= '~' or c in '\n\r\t')
        return (printable_count / len(sample)) > 0.9


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
            record.links = r.get('links') or []
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

    def get_file_data(self, verify_ssl_certs=True, proxy_url=None):
        """
        Return decrypted raw file data
        """
        if not self.file_data:    # cached if nothing
            file_key = self.__decrypt_file_key()
            file_url = self.f.get('url')

            proxies = {"https": proxy_url} if proxy_url else None
            rs = requests.get(file_url, verify=verify_ssl_certs, proxies=proxies)

            file_encrypted_data = rs.content

            self.file_data = CryptoUtils.decrypt_aes(file_encrypted_data, file_key)

        return self.file_data

    def save_file(self, path, create_folders=False, verify_ssl_certs=True, proxy_url=None):
        """
        Save decrypted file data to the provided path
        """

        if create_folders:
            os.makedirs(os.path.dirname(path), exist_ok=True)

        file_data = self.get_file_data(verify_ssl_certs=verify_ssl_certs, proxy_url=proxy_url)

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

        if self.custom is not None:
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
