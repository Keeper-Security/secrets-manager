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

import hmac
import json
import logging
import os
import re
import requests
import sys
from base64 import urlsafe_b64decode
from http import HTTPStatus
from typing import List, Tuple, Optional

from keeper_secrets_manager_core import utils, helpers
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.dtos import Folder, Record, \
    RecordCreate, SecretsManagerResponse, AppData, \
    KeeperFileUpload, KeeperFile, KeeperFolder
from keeper_secrets_manager_core.dto.payload import GetPayload, \
    CompleteTransactionPayload, UpdatePayload, TransmissionKey, \
    EncryptedPayload, KSMHttpResponse, CreatePayload, FileUploadPayload, \
    DeletePayload, CreateFolderPayload, UpdateFolderPayload, \
    DeleteFolderPayload, CreateOptions, QueryOptions
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.keeper_globals import keeper_public_keys, \
    keeper_secrets_manager_sdk_client_id, logger_name, keeper_servers
from keeper_secrets_manager_core.storage import FileKeyValueStorage, \
    KeyValueStorage, InMemoryKeyValueStorage
from keeper_secrets_manager_core.utils import base64_to_bytes, dict_to_json, \
    url_safe_str_to_bytes, bytes_to_base64, generate_random_bytes, \
    generate_uid_bytes, now_milliseconds, string_to_bytes, json_to_dict, \
    bytes_to_string, strtobool


def find_secrets_by_title(record_title, records):
    # Find all records with specified title
    records = records or []
    return [x for x in records if x.title == record_title]


def find_secret_by_title(record_title, records):
    # Find first record with specified title
    records = records or []
    return next((x for x in records if x.title == record_title), None)


# data class to represent parsed notation section
class NotationSection:
    def __init__(self, section: str):
        self.section: str = section     # section name - ex. prefix
        self.is_present: bool = False   # presence flag
        self.start_pos: int = -1        # section start pos in URI
        self.end_pos: int = -1          # section end pos in URI
        self.text: Optional[Tuple[str, str]] = None       # [unescaped, raw] text
        self.parameter: Optional[Tuple[str, str]] = None  # <field type>|<field label>|<file name>
        self.index1: Optional[Tuple[str, str]] = None     # numeric index [N] or []
        self.index2: Optional[Tuple[str, str]] = None     # property index - ex. field/name[0][middle]


class SecretsManager:

    notation_prefix = "keeper"
    default_key_id = "10"

    # Field types that can be inflated. Used for notation.
    inflate_ref_types = {
        "addressRef": ["address"],
        "cardRef": ["paymentCard", "text", "pinCode", "addressRef"]
    }

    def __init__(self,
                 token=None, hostname=None, verify_ssl_certs=True, config=None, log_level=None,
                 custom_post_function=None):

        # Make sure the Python is 3.6 or higher. We'll handle Python 4 in the future :)
        python_version = sys.version_info
        if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 6):
            raise Exception("KSM SDK requires Python 3.6 or greater")

        self.token = None
        self.hostname = None

        # If the config is not defined and the KSM_CONFIG env var exists, get the config from the env var.
        if config is None and os.environ.get("KSM_CONFIG") is not None:
            config = InMemoryKeyValueStorage(os.environ.get("KSM_CONFIG"))
        elif token:

            token = token.strip()
            token_parts = token.split(":")

            if len(token_parts) == 1:
                if not hostname:
                    raise ValueError('The hostname must be present in the token or provided as a parameter')

                self.token = token
                self.hostname = hostname
            else:
                token_host = keeper_servers.get(token_parts[0].upper())

                if token_host:
                    # meaning that token contained abbreviation:
                    #   ex. 'US:ONE_TIME_TOKEN'
                    self.hostname = token_host
                else:
                    # meaning that token contained url prefix:
                    #   ex. ksm.company.com:ONE_TIME_TOKEN
                    self.hostname = token_parts[0]

                self.token = token_parts[1]

        # Init the log, create a logger for the core.
        self._init_logger(log_level=log_level)
        self.logger = logging.getLogger(logger_name)

        # Accept the env var KSM_SKIP_VERIFY. Modules like 'requests' already use it.
        self.verify_ssl_certs = verify_ssl_certs
        if os.environ.get("KSM_SKIP_VERIFY") is not None:
            # We need to flip the value of KSM_SKIP_VERIFY, if true, we want verify_ssl_certs to be false.
            self.verify_ssl_certs = not bool(strtobool(os.environ.get("KSM_SKIP_VERIFY")))

        self.custom_post_function = custom_post_function

        if config is None:
            config = FileKeyValueStorage()

        # If the server or client key are set in the args, make sure they makes it's way into the config. They
        # will override what is already in the config if they exist.
        if self.token is not None:
            config.set(ConfigKeys.KEY_CLIENT_KEY, self.token)
        if self.hostname is not None:
            config.set(ConfigKeys.KEY_HOSTNAME, self.hostname)

        # Make sure our public key id is set and pointing an existing key.
        if config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID) is None:
            self.logger.debug("Setting public key id to the default: {}".format(SecretsManager.default_key_id))
            config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, SecretsManager.default_key_id)
        elif config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID) not in keeper_public_keys:
            self.logger.debug("Public key id {} does not exists, set to default : {}".format(
                config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID),
                SecretsManager.default_key_id))
            config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, SecretsManager.default_key_id)

        self.config: KeyValueStorage = config

        self._init()

    @staticmethod
    def _init_logger(log_level=None):

        logger = logging.getLogger(logger_name)

        # If the log level was passed in, then we want to set up the logging. If not, there is no logging.
        if log_level is not None:

            # If the log level is a string, get the enum value.
            if type(log_level) is str:
                valid_log_levels = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]
                if log_level not in valid_log_levels:
                    raise ValueError("Log level {} is invalid. Valid values are: {}".format(
                        log_level, ", ".join(valid_log_levels)))
                log_level = getattr(logging, log_level)

            logger.disabled = False
            logger.setLevel(log_level)

            # If we don't have my handlers, set the logger up with default settings. The handler and formatters
            # can be set outside of the SDK if an integration or company
            if len(logger.handlers) == 0:
                # Default to stderr
                sh = logging.StreamHandler()
                sh.setLevel(log_level)

                sh.setFormatter(logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s"))
                logger.addHandler(sh)
        else:
            logger.disabled = True

    def _init(self):

        if not self.verify_ssl_certs:
            self.logger.warning("WARNING: Running without SSL cert verification. "
                                "Execute 'SecretsManager(..., verify_ssl_certs=True)' or 'KSM_SKIP_VERIFY=FALSE' "
                                "to enable verification.")

        client_id = self.config.get(ConfigKeys.KEY_CLIENT_ID)

        unbound_token = False
        if self.token:
            unbound_token = True
            if client_id: # config is initialized
                client_key = self.token
                client_key_bytes = url_safe_str_to_bytes(client_key)
                client_key_hash = hmac.new(client_key_bytes, b'KEEPER_SECRETS_MANAGER_CLIENT_ID', 'sha512').digest()
                token_client_id = bytes_to_base64(client_key_hash)
                if token_client_id == client_id: # with same token - check if bound
                    app_key = self.config.get(ConfigKeys.KEY_APP_KEY)
                    if app_key: # and bound
                        unbound_token = False
                        self.logger.warning(f"The storage is already initialized with same token")
                    else: # not bound
                        self.logger.warning(f"The storage is already initialized but not bound")
                else: # initialized with different token
                    raise ValueError(f"The storage is already initialized with a different token - Client ID: {client_id}")

        if client_id and not unbound_token:
            self.logger.debug("Already bound")

            if self.config.get(ConfigKeys.KEY_CLIENT_KEY):
                self.config.delete(ConfigKeys.KEY_CLIENT_KEY)

        else:

            existing_secret_key = self.load_secret_key()

            if existing_secret_key is None:
                raise ValueError("Cannot locate One Time Token.")

            existing_secret_key_bytes = url_safe_str_to_bytes(existing_secret_key)
            digest = 'sha512'
            existing_secret_key_hash = bytes_to_base64(hmac.new(existing_secret_key_bytes,
                                                                      b'KEEPER_SECRETS_MANAGER_CLIENT_ID',
                                                                      digest).digest())

            self.config.delete(ConfigKeys.KEY_CLIENT_ID)
            self.config.delete(ConfigKeys.KEY_PRIVATE_KEY)
            if self.config.get(ConfigKeys.KEY_CLIENT_ID):
                self.config.delete(ConfigKeys.KEY_APP_KEY)

            self.config.set(ConfigKeys.KEY_CLIENT_ID, existing_secret_key_hash)

            private_key_str = self.config.get(ConfigKeys.KEY_PRIVATE_KEY)

            if not private_key_str:
                private_key_der = CryptoUtils.generate_private_key_der()
                self.config.set(ConfigKeys.KEY_PRIVATE_KEY, bytes_to_base64(private_key_der))

    def load_secret_key(self):

        """Returns client_id from the environment variable, config file, or in the code"""

        # Case 1: Environment Variable
        env_secret_key = os.getenv('KSM_TOKEN')

        current_secret_key = None

        if env_secret_key:
            current_secret_key = env_secret_key
            self.logger.info("Secret key found in environment variable")

        # Case 2: Code
        if not current_secret_key:
            code_secret_key = self.token

            if code_secret_key:
                current_secret_key = code_secret_key
                self.logger.info("Secret key found in code")

        # Case 3: Config storage
        if not current_secret_key:
            config_secret_key = self.config.get(ConfigKeys.KEY_CLIENT_KEY)

            if config_secret_key:
                current_secret_key = config_secret_key
                self.logger.info("Secret key found in configuration file")

        return current_secret_key

    @staticmethod
    def generate_transmission_key(key_id):
        transmission_key = utils.generate_random_bytes(32)

        if key_id not in keeper_public_keys:
            ValueError("The public key id {} does not exist.".format(key_id))

        server_public_raw_key_bytes = url_safe_str_to_bytes(keeper_public_keys[key_id])

        encrypted_key = CryptoUtils.public_encrypt(transmission_key, server_public_raw_key_bytes)

        return TransmissionKey(key_id, transmission_key, encrypted_key)

    @staticmethod
    def encrypt_and_sign_payload(storage, transmission_key, payload):

        if not (
                isinstance(payload, GetPayload) or
                isinstance(payload, UpdatePayload) or
                isinstance(payload, CreatePayload) or
                isinstance(payload, FileUploadPayload) or
                isinstance(payload, CompleteTransactionPayload) or
                isinstance(payload, DeletePayload) or
                isinstance(payload, CreateFolderPayload) or
                isinstance(payload, UpdateFolderPayload) or
                isinstance(payload, DeleteFolderPayload)):
            raise Exception('Unknown payload type "%s"' % payload.__class__.__name__)

        payload_json_str = dict_to_json(payload.__dict__)
        payload_bytes = utils.string_to_bytes(payload_json_str)

        encrypted_payload = CryptoUtils.encrypt_aes(payload_bytes, transmission_key.key)

        encrypted_key = transmission_key.encryptedKey
        signature_base = encrypted_key + encrypted_payload

        private_key = storage.get(ConfigKeys.KEY_PRIVATE_KEY)
        pk = CryptoUtils.der_base64_private_key_to_private_key(private_key)
        signature = CryptoUtils.sign(signature_base, pk)

        return EncryptedPayload(
            encrypted_payload,
            signature
        )

    @staticmethod
    def prepare_delete_payload(storage, record_uids):
        payload = DeletePayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)
        payload.recordUids = record_uids

        return payload

    @staticmethod
    def prepare_get_payload(storage, query_options:QueryOptions):
        payload = GetPayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)

        app_key_str = storage.get(ConfigKeys.KEY_APP_KEY)

        if not app_key_str:

            public_key_bytes = CryptoUtils.extract_public_key_bytes(storage.get(ConfigKeys.KEY_PRIVATE_KEY))
            public_key_base64 = bytes_to_base64(public_key_bytes)
            # passed once when binding
            payload.publicKey = public_key_base64

        if query_options:
            if query_options.records_filter:
                payload.requestedRecords = query_options.records_filter
            if query_options.folders_filter:
                payload.requestedFolders = query_options.folders_filter

        return payload

    @staticmethod
    def prepare_create_payload(storage, create_options: CreateOptions, record_data_json_str, folder_key):
        owner_public_key = storage.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY)

        if not owner_public_key:
            raise KeeperError('Unable to create record - owner key is missing.'
                              ' Looks like application was created using'
                              ' out of date client (Web Vault or Commander)')

        owner_public_key_bytes = url_safe_str_to_bytes(owner_public_key)

        if not folder_key:
            raise KeeperError('Unable to create record - folder key for ' + create_options.folder_uid + ' is missing')

        record_key = generate_random_bytes(32)
        record_uid = generate_uid_bytes()

        record_data_bytes = utils.string_to_bytes(record_data_json_str)
        record_data_encrypted = CryptoUtils.encrypt_aes(record_data_bytes, record_key)

        record_key_encrypted = CryptoUtils.public_encrypt(record_key, owner_public_key_bytes)

        folder_key_encrypted = CryptoUtils.encrypt_aes(record_key, folder_key)

        payload = CreatePayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)
        payload.recordUid = CryptoUtils.bytes_to_url_safe_str(record_uid)
        payload.recordKey = bytes_to_base64(record_key_encrypted)
        payload.folderUid = create_options.folder_uid
        payload.folderKey = bytes_to_base64(folder_key_encrypted)
        payload.data = bytes_to_base64(record_data_encrypted)
        payload.subFolderUid = create_options.subfolder_uid

        return payload

    @staticmethod
    def prepare_update_payload(storage, record, transaction_type=None):

        payload = UpdatePayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)

        # for update, uid of the record
        payload.recordUid = record.uid
        payload.revision = record.revision

        raw_json_bytes = utils.string_to_bytes(record.raw_json)
        encrypted_raw_json_bytes = CryptoUtils.encrypt_aes(raw_json_bytes, record.record_key_bytes)

        payload.data = bytes_to_base64(encrypted_raw_json_bytes)

        if transaction_type:
            payload.transactionType = transaction_type

        return payload

    @staticmethod
    def prepare_complete_transaction_payload(storage, record_uid):

        payload = CompleteTransactionPayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)
        payload.recordUid = record_uid

        return payload

    @staticmethod
    def prepare_file_upload_payload(storage, owner_record, file: KeeperFileUpload):

        owner_public_key = storage.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY)

        if not owner_public_key:
            raise KeeperError('Unable to upload file - owner key is missing. Looks like application was created '
                              'using out date client (Web Vault or Commander)')

        owner_public_key_bytes = url_safe_str_to_bytes(owner_public_key)

        file_record_dict = {
            'name': file.Name,
            'size': len(file.Data),
            'title': file.Title,
            'lastModified': now_milliseconds(),
            'type': file.Type
        }

        file_record_json_str = dict_to_json(file_record_dict)
        file_record_bytes = utils.string_to_bytes(file_record_json_str)

        file_record_key = generate_random_bytes(32)
        file_record_uid = generate_random_bytes(16)
        file_record_uid_str = CryptoUtils.bytes_to_url_safe_str(file_record_uid)

        encrypted_file_record_bytes = CryptoUtils.encrypt_aes(file_record_bytes, file_record_key)
        encrypted_file_record_key = CryptoUtils.public_encrypt(file_record_key, owner_public_key_bytes)
        encrypted_link_key_bytes = CryptoUtils.encrypt_aes(file_record_key, owner_record.record_key_bytes)

        encrypted_file_data = CryptoUtils.encrypt_aes(file.Data, file_record_key)

        # Add fileRef here
        rec_dict = owner_record.dict
        fields = rec_dict.get('fields')

        file_refs = [f for f in fields if f['type'] == 'fileRef']

        if not file_refs:
            fields.append({'type': 'fileRef', 'value': [file_record_uid_str]})
        else:
            file_uid_list = file_refs[0].get('value')
            file_uid_list.append(file_record_uid_str)

        owner_record.raw_json = utils.dict_to_json(rec_dict)

        owner_record_bytes = string_to_bytes(owner_record.raw_json)

        encrypted_owner_record_bytes = CryptoUtils.encrypt_aes(owner_record_bytes, owner_record.record_key_bytes)
        encrypted_owner_record_str = CryptoUtils.bytes_to_url_safe_str(encrypted_owner_record_bytes)

        payload = FileUploadPayload()
        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)
        payload.fileRecordUid = file_record_uid_str
        payload.fileRecordData = CryptoUtils.bytes_to_url_safe_str(encrypted_file_record_bytes)
        payload.fileRecordKey = bytes_to_base64(encrypted_file_record_key)
        payload.ownerRecordUid = owner_record.uid

        payload.ownerRecordData = encrypted_owner_record_str

        payload.linkKey = bytes_to_base64(encrypted_link_key_bytes)

        payload.fileSize = len(encrypted_file_data)
        return {
            'payload': payload,
            'encryptedFileData': encrypted_file_data
        }

    @staticmethod
    def prepare_create_folder_payload(storage, create_options, folder_name, shared_folder_key):

        payload = CreateFolderPayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)
        payload.sharedFolderUid = create_options.folder_uid
        payload.parentUid = create_options.subfolder_uid

        folder_uid = generate_uid_bytes()
        payload.folderUid = CryptoUtils.bytes_to_url_safe_str(folder_uid)

        folder_key = generate_random_bytes(32)
        encrypted_folder_key = CryptoUtils.encrypt_aes_cbc(folder_key, shared_folder_key)
        payload.sharedFolderKey = CryptoUtils.bytes_to_url_safe_str(encrypted_folder_key)

        folder_json = dict_to_json({"name": folder_name})
        folder_data_bytes = string_to_bytes(folder_json)
        encrypted_folder_data = CryptoUtils.encrypt_aes_cbc(folder_data_bytes, folder_key)
        payload.data = CryptoUtils.bytes_to_url_safe_str(encrypted_folder_data)

        return payload

    @staticmethod
    def prepare_update_folder_payload(storage, folder_uid, folder_name, folder_key):

        payload = UpdateFolderPayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)
        payload.folderUid = folder_uid

        folder_json = dict_to_json({"name": folder_name})
        folder_data_bytes = utils.string_to_bytes(folder_json)
        encrypted_folder_data = CryptoUtils.encrypt_aes_cbc(folder_data_bytes, folder_key)
        payload.data = CryptoUtils.bytes_to_url_safe_str(encrypted_folder_data)

        return payload

    @staticmethod
    def prepare_delete_folder_payload(storage, folder_uids, force_deletion):

        payload = DeleteFolderPayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)
        payload.folderUids = folder_uids
        payload.forceDeletion = force_deletion

        return payload

    def _post_query(self, path, payload):

        keeper_server = helpers.get_server(self.hostname, self.config)
        url = "https://%s/api/rest/sm/v1/%s" % (keeper_server, path)

        while True:

            transmission_key_id = self.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID)
            transmission_key = self.generate_transmission_key(transmission_key_id)
            encrypted_payload_and_signature = self.encrypt_and_sign_payload(self.config, transmission_key, payload)

            if self.custom_post_function and path == 'get_secret':
                ksm_rs = self.custom_post_function(url, transmission_key, encrypted_payload_and_signature, self.verify_ssl_certs)
            else:
                ksm_rs = self.post_function(url, transmission_key, encrypted_payload_and_signature, self.verify_ssl_certs)

            # If we are ok, then break out of the while loop
            if ksm_rs.status_code == 200:
                break

            # Handle the error. Handling will throw an exception if it doesn't want us to retry.
            self.handler_http_error(ksm_rs.http_response)

        if ksm_rs.data:
            return CryptoUtils.decrypt_aes(ksm_rs.data, transmission_key.key)
        else:
            return ksm_rs.data

    @staticmethod
    def post_function(url, transmission_key, encrypted_payload_and_signature, verify_ssl_certs=True):

        request_headers = {
            'Content-Type': 'application/octet-stream',
            'Content-Length': str(len(encrypted_payload_and_signature.encrypted_payload)),
            'PublicKeyId': str(transmission_key.publicKeyId),
            'TransmissionKey': bytes_to_base64(transmission_key.encryptedKey),
            'Authorization': 'Signature %s' % bytes_to_base64(encrypted_payload_and_signature.signature)
        }

        rs = requests.post(
            url,
            headers=request_headers,
            data=encrypted_payload_and_signature.encrypted_payload,
            verify=verify_ssl_certs
        )

        ksm_rs = KSMHttpResponse(rs.status_code, rs.content, rs)

        return ksm_rs

    @staticmethod
    def __upload_file_function(url, upload_parameters, encrypted_file_data):
        """Upload file to the server"""
        files = {'file': encrypted_file_data}

        rs = requests.post(url,
                           data=upload_parameters,
                           files=files,
                           )

        rs_status_code = rs.status_code
        rs_data = rs.text

        return {
            'isOk': rs.ok,
            'statusCode': rs_status_code,
            'data': rs_data
        }

    def handler_http_error(self, rs):

        log_level = logging.ERROR
        try:
            # Decode the JSON content, throw exception if not JSON
            response_dict = utils.json_to_dict(rs.text)
            if response_dict is None:
                raise json.JSONDecodeError("Not JSON", "NONE", 0)

            # Try to get the error from result_code, then from error.
            error = response_dict.get('result_code', response_dict.get('error'))

            if error == 'invalid_client_version':
                self.logger.error("Client version {} was not registered in the backend".format(
                    keeper_secrets_manager_sdk_client_id))
                msg = response_dict.get('additional_info')

            # The server wants us to use a different public key.
            elif error == 'key':
                key_id = response_dict.get("key_id")
                self.logger.info("Server has requested we use public key {}".format(key_id))

                if key_id is None:
                    raise ValueError("The public key is blank from the server")
                elif str(key_id) not in keeper_public_keys:
                    raise ValueError("The public key at {} does not exist in the SDK".format(key_id))

                self.config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, str(key_id))

                # This is not an error, it's info. Make it so the 'finally' display info about the
                # key change.
                log_level = logging.DEBUG

                # The only non-exception exit from this method
                return True
            else:
                msg = "Error: {}, message={}".format(error, response_dict.get('message', "NA"))

            raise KeeperError(msg)

        except json.JSONDecodeError as _:
            # The content wasn't JSON. Let the catch-all exception at the end handle it.
            pass
        except KeeperError as err:
            # This was one of our exceptions, just rethrow it.
            raise err
        finally:
            self.logger.log(log_level, "Error: {} (http error code {}): {}".format(
                rs.reason,
                rs.status_code,
                rs.text
            ))

        # This is a unknown error, not one of ours, just throw a HTTPError
        reason = f", Reason: {str(rs.reason)}" if rs.reason else ""
        message = f", Message: {str(rs.text)}" if rs.text else ""
        raise requests.HTTPError(f"Status Code: {rs.status_code}{reason}{message}")

    @staticmethod
    def get_shared_folder_key(folders: list, response_folders: list, parent: str):
        folders = folders or []
        response_folders = response_folders or []
        while True:
            parent_folder = next((x for x in response_folders if x.get('folderUid', None) == parent), None)
            if parent_folder is None:
                return None
            if not parent_folder.get('parent', ''):
                shared_folder = next((x for x in folders if x.folder_uid == parent_folder.get('folderUid', None)), None)
                if shared_folder is None:
                    return None
                else:
                    return shared_folder.folder_key
            parent = parent_folder.get('parent', '')

    def fetch_and_decrypt_folders(self):
        payload = SecretsManager.prepare_get_payload(self.config, [])
        decrypted_response_bytes = self._post_query('get_folders', payload)
        decrypted_response_str = utils.bytes_to_string(decrypted_response_bytes)
        decrypted_response_dict = utils.json_to_dict(decrypted_response_str) or {}

        app_key = base64_to_bytes(self.config.get(ConfigKeys.KEY_APP_KEY))
        response_folders = decrypted_response_dict.get("folders", []) or []
        if not response_folders:
            return []

        folders = []
        for folder in response_folders:
            folder_key = folder.get('folderKey')
            folder_parent = folder.get('parent', '') or ''
            if not folder_parent:
                folder_key = CryptoUtils.decrypt_aes(utils.base64_to_bytes(folder_key), app_key)
            else:
                shared_folder_key = SecretsManager.get_shared_folder_key(folders, response_folders, folder_parent)
                folder_key = CryptoUtils.decrypt_aes_cbc(utils.base64_to_bytes(folder_key), shared_folder_key)

            folder_name = ''
            folder_data = folder.get('data', '')
            if folder_data:
                folder_data_json = CryptoUtils.decrypt_aes_cbc(utils.base64_to_bytes(folder_data), folder_key)
                folder_data_dict = json.loads(folder_data_json.decode())
                folder_name = folder_data_dict.get('name', '') or ''
            fldr = KeeperFolder(folder_key,
                                folder.get('folderUid', '') or '',
                                folder_parent,
                                folder_name)
            folders.append(fldr)
        return folders


    def fetch_and_decrypt_secrets(self, query_options: QueryOptions):
        payload = SecretsManager.prepare_get_payload(self.config, query_options=query_options)

        decrypted_response_bytes = self._post_query(
            'get_secret',
            payload
        )

        decrypted_response_str = utils.bytes_to_string(decrypted_response_bytes)
        decrypted_response_dict = utils.json_to_dict(decrypted_response_str) or {}

        records = []
        shared_folders = []

        just_bound = False

        if decrypted_response_dict.get('encryptedAppKey'):
            just_bound = True

            encrypted_master_key = url_safe_str_to_bytes(decrypted_response_dict.get('encryptedAppKey'))
            client_key = url_safe_str_to_bytes(self.config.get(ConfigKeys.KEY_CLIENT_KEY))
            secret_key = CryptoUtils.decrypt_aes(encrypted_master_key, client_key)
            self.config.set(ConfigKeys.KEY_APP_KEY, bytes_to_base64(secret_key))

            self.config.delete(ConfigKeys.KEY_CLIENT_KEY)

            if decrypted_response_dict.get('appOwnerPublicKey'):
                appOwnerPublicKeyBytes = url_safe_str_to_bytes(decrypted_response_dict.get('appOwnerPublicKey'))
                self.config.set(ConfigKeys.KEY_OWNER_PUBLIC_KEY, bytes_to_base64(appOwnerPublicKeyBytes))

        else:
            secret_key = base64_to_bytes(self.config.get(ConfigKeys.KEY_APP_KEY))

        records_resp = decrypted_response_dict.get('records')
        folders_resp = decrypted_response_dict.get('folders')

        self.logger.debug("Individual record count: {}".format(len(records_resp or [])))
        self.logger.debug("Folder count: {}".format(len(folders_resp or [])))

        sm_response = SecretsManagerResponse()

        if records_resp:
            for r in records_resp:
                try:
                    record = Record(r, secret_key)
                    records.append(record)
                except Exception as err:
                    msg = f"{err.__class__.__name__}, {str(err)}"
                    sm_response.bad_records.append({
                        "r": r,
                        "err": msg
                    })

        if folders_resp:
            for f in folders_resp:
                try:
                    folder = Folder(f, secret_key)
                    records.extend(folder.records)
                    shared_folders.append(folder)
                except Exception as err:
                    msg = f"{err.__class__.__name__}, {str(err)}"
                    sm_response.bad_folders.append({
                        "f": f,
                        "err": msg
                    })

        self.logger.debug("Total record count: {}".format(len(records)))

        if 'appData' in decrypted_response_dict:
            app_data_json = CryptoUtils.decrypt_aes(
                url_safe_str_to_bytes(decrypted_response_dict['appData']),
                base64_to_bytes(self.config.get(ConfigKeys.KEY_APP_KEY))
            )

            app_data_dict = utils.json_to_dict(app_data_json)

            sm_response.appData = AppData(title=app_data_dict['title'], app_type=app_data_dict['type'])
        else:
            sm_response.appData = AppData()

        if 'expiresOn' in decrypted_response_dict:
            sm_response.expiresOn = decrypted_response_dict.get('expiresOn')

        if 'warnings' in decrypted_response_dict:
            sm_response.warnings = decrypted_response_dict.get('warnings')

        sm_response.records = records
        sm_response.folders = shared_folders
        sm_response.justBound = just_bound

        return sm_response

    def get_secrets(self, uids=None, full_response=False):
        """
        Retrieve all records associated with the given application
        optionally filtered by record uids
        """

        if isinstance(uids, str):
            uids = [uids]

        query_options = QueryOptions(records_filter=uids, folders_filter=None)
        return self.get_secrets_with_options(query_options, full_response)

    def get_secrets_with_options(self, query_options=None, full_response=False):
        """
        Retrieve records associated with the given application
        optionally filtered by the query options
        """

        records_resp = self.fetch_and_decrypt_secrets(query_options)

        if records_resp.justBound:
            records_resp = self.fetch_and_decrypt_secrets(query_options)

        # Log warnings we got from the server
        # Will only be displayed if logging is enabled:
        if records_resp.warnings:
            for warning in records_resp.warnings:
                self.logger.warning(warning)

        if records_resp.had_bad_records:
            for error in records_resp.bad_records:
                uid = error.get('r').get("recordUid")
                err = error.get('err')
                self.logger.error(f"Record {uid} skipped due to error: {err}")

        if records_resp.had_bad_folders:
            for error in records_resp.bad_folders:
                uid = error.get('f').get("folderUid")
                err = error.get('err')
                self.logger.error(f"Folder {uid} skipped due to error: {err}")
        if full_response:
            return records_resp
        else:
            records: list = records_resp.records or []

            return records

    def get_folders(self):
        # Retrieve all folders
        return self.fetch_and_decrypt_folders()

    def get_secrets_by_title(self, record_title):
        """
        Retrieve all records with specified title
        """

        recs = self.get_secrets()
        records = [x for x in recs if x.title == record_title]

        return records

    def get_secret_by_title(self, record_title):
        """
        Retrieve first record with specified title
        """

        records = self.get_secrets_by_title(record_title) or []
        return next((iter(records)), None)

    def delete_secret(self, record_uids):
        """
        Delete secret records with specified uids
        """

        if isinstance(record_uids, str):
            record_uids = [record_uids]

        payload = SecretsManager.prepare_delete_payload(self.config, record_uids=record_uids)
        response = self._post_query('delete_secret', payload)
        response_str = bytes_to_string(response)
        response_dict = json_to_dict(response_str)

        return response_dict.get('records')

    def create_secret(self, folder_uid, record_data):

        #   Backend only need a JSON string of the record, so we have different ways of handing data:
        #       - providing data as JSON string
        #       - providing data as dictionary
        #       - providing data as CreateRecord object
        #
        #   For now we will only allow CreateRecord objects

        record_data_json_str = None

        if isinstance(record_data, RecordCreate):
            record_data_json_str = record_data.to_json()
        else:
            raise KeeperError('New record data has to be a valid ' + RecordCreate.__name__ + ' object')

        # if isinstance(record_data, RecordV3):
        #     record_data_json_str = record_data.to_json()
        # elif isinstance(record_data, dict):
        #     record_data_json_str = dict_to_json(record_data)
        # elif isinstance(record_data, str):
        #     if not is_json(record_data):
        #         raise KeeperError('Record data has to be a valid JSON string.')
        #
        #     record_data_json_str = record_data

        # Since we don't know folder's key where this record will be
        # placed in, currently we have to retrieve all data that is share to
        # this device/client and look for the folder's key in the returned
        # folder data

        records_and_folders_response = self.get_secrets(full_response=True)

        found_folder = helpers.get_folder_key(folder_uid=folder_uid, secrets_and_folders=records_and_folders_response)

        if not found_folder:
            raise KeeperError('Folder uid=' + folder_uid + ' was not retrieved. If you are creating a record to a '
                              'folder folder that you know exists, make sure that at least one record is present in '
                              'the prior to adding a record to the folder.')

        create_options = CreateOptions(folder_uid, None)
        payload = SecretsManager.prepare_create_payload(self.config, create_options, record_data_json_str, found_folder.key)
        self._post_query('create_secret', payload)

        return payload.recordUid

    def create_secret_with_options(self, create_options: CreateOptions, record_data: RecordCreate, folders: list = []):
        if not isinstance(record_data, RecordCreate):
            raise KeeperError('New record data has to be a valid ' + RecordCreate.__name__ + ' object')
        record_data_json_str = record_data.to_json()

        if not folders:
            folders = self.get_folders()

        shared_folder = next((x for x in folders if x.folder_uid == create_options.folder_uid), None)
        if shared_folder is None or not shared_folder.folder_key:
            raise KeeperError(f'Unable to create record - folder key for {create_options.folder_uid} not found')

        payload = SecretsManager.prepare_create_payload(self.config, create_options, record_data_json_str, shared_folder.folder_key)
        self._post_query('create_secret', payload)

        return payload.recordUid

    def create_folder(self, create_options: CreateOptions, folder_name: str, folders=None):
        """
        Create new folder using the provided options.

        If folders is None that will force downloading all folders metadata with every request.
        Folders metadata could be retrieved from get_folders() cached and reused
        as long as it is not modified externally or internally.

        create_options.folder_uid is required and must be a parent shared folder

        create_options.subfolder_uid could be many levels deep under its parent.
        If subfolder_uid is empty - new folder is created under parent folder_uid
        """

        if not folders:
            folders = self.get_folders()

        shared_folder = next((x for x in folders if x.folder_uid == create_options.folder_uid), None)
        if shared_folder is None or not shared_folder.folder_key:
            raise KeeperError(f'Unable to create folder - folder key for {create_options.folder_uid} not found')

        payload = SecretsManager.prepare_create_folder_payload(self.config, create_options, folder_name, shared_folder.folder_key)
        _ = self._post_query('create_folder', payload)
        return payload.folderUid

    def update_folder(self, folder_uid: str, folder_name: str, folders=None):
        """
        Update folder changes the folder metadata - currently folder name only
        """

        if not folders:
            folders = self.get_folders()

        shared_folder = next((x for x in folders if x.folder_uid == folder_uid), None)
        if shared_folder is None or not shared_folder.folder_key:
            raise KeeperError(f'Unable to update folder - folder key for {folder_uid} not found')

        payload = SecretsManager.prepare_update_folder_payload(self.config, folder_uid, folder_name, shared_folder.folder_key)
        _ = self._post_query('update_folder', payload)

    def delete_folder(self, folder_uids, force_deletion=False):
        """
        Delete folders with specified folder_uids
        Use force_deletion flag to delete non-empty folders.
        Note! When using force_deletion avoid sending parent with its children folder UIDs.
        Depending on the delete order you may get an error ex. if parent force-deleted child first.
        There's no guarantee that list will always be processed in FIFO order.
        Note! Any folder_uids missing from the vault or not shared to the KSM application
        will not result in error.
        """

        if isinstance(folder_uids, str):
            folder_uids = [folder_uids]

        payload = SecretsManager.prepare_delete_folder_payload(self.config, folder_uids, force_deletion)
        response = self._post_query('delete_folder', payload)
        response_str = bytes_to_string(response)
        response_dict = json_to_dict(response_str)

        return response_dict.get('folders', {}) if isinstance(response_dict, dict) else {}

    def upload_file(self, owner_record, file: KeeperFileUpload):
        """
        Upload file using provided file upload object
        """

        self.logger.info(f"Uploading file: {file.Name} to record uid {owner_record.uid}")

        self.logger.debug(f"Preparing upload payload. owner_record.uid=[{owner_record.uid}], file name: [{file.Name}], file size: [{len(file.Data)}]")

        upload_payload = self.prepare_file_upload_payload(self.config, owner_record, file)
        payload = upload_payload.get('payload')
        encrypted_file_data = upload_payload.get('encryptedFileData')

        self.logger.debug(f"Posting prepare data")
        response_data = self._post_query('add_file', payload)

        response_json_str = bytes_to_string(response_data)
        response_dict = json_to_dict(response_json_str)
        upload_url = response_dict.get('url')
        parameters_json_str = response_dict.get('parameters')
        parameters_dict = json_to_dict(parameters_json_str)

        self.logger.debug(f"Uploading file data: upload url=[{upload_url}], file name: [{file.Name}], encrypted file size: [{len(encrypted_file_data)}]")
        upload_result = SecretsManager.__upload_file_function(upload_url, parameters_dict, encrypted_file_data)

        self.logger.debug(f"Finished uploading file data. Status code: {upload_result.get('statusCode')}, response data: {upload_result.get('data')}")

        if not upload_result.get('isOk'):
            raise KeeperError('Failed to upload a file')
        else:
            return payload.fileRecordUid

    def upload_file_path(self, owner_record, file_path):
        """
        Upload file using provided file path
        """

        file_to_upload = KeeperFileUpload.from_file(file_path)

        return self.upload_file(owner_record, file_to_upload)

    def save(self, record, transaction_type=None):
        """
        Save updated secret values
        """

        self.logger.info("Updating record uid: %s" % record.uid)

        payload = SecretsManager.prepare_update_payload(self.config, record, transaction_type)

        self._post_query(
            'update_secret',
            payload
        )

        return True

    def complete_transaction(self, record_uid: str, rollback: bool = False):
        """
        Complete transaction - commit or rollback
        """

        self.logger.info("Closing transaction for record uid: %s" % record_uid)

        payload = SecretsManager.prepare_complete_transaction_payload(self.config, record_uid)
        route = "rollback_secret_update" if rollback else "finalize_secret_update"

        self._post_query(
            route,
            payload
        )

        return True

    def get_notation(self, url):

        """Simple string notation to get a value

        * A system of figures or symbols used in a specialized field to represent numbers, quantities, tones,
          or values.

        <uid>/<field|custom_field|file>/<label|type>[INDEX][FIELD]

        Example:

            RECORD_UID/field/password                => MyPassword
            RECORD_UID/field/password[0]             => MyPassword
            RECORD_UID/field/password[]              => ["MyPassword"]
            RECORD_UID/custom_field/name[first]      => John
            RECORD_UID/custom_field/name[last]       => Smith
            RECORD_UID/custom_field/phone[0][number] => "555-5555555"
            RECORD_UID/custom_field/phone[1][number] => "777-7777777"
            RECORD_UID/custom_field/phone[]          => [{"number": "555-555...}, { "number": "777.....}]
            RECORD_UID/custom_field/phone[0]         => [{"number": "555-555...}]

        """

        parsed_notation = self.parse_notation(url, True) # prefix, record, selector, footer
        if len(parsed_notation) < 3:
            raise ValueError(f"Invalid notation '{url}'")

        if parsed_notation[1].text is None:
            raise ValueError(f"Invalid notation '{url}' - UID/Title is missing in the keeper url.")
        record_token = parsed_notation[1].text[0] # UID or Title
        if parsed_notation[2].text is None:
            raise ValueError(f"Invalid notation '{url}' - field type/selector is missing in the keeper url.")
        selector = parsed_notation[2].text[0] # type|title|notes or file|field|custom_field

        # legacy compat mode:
        # index1 is always the numeric index, and index2 is property name string
        # parse_notation() in legacy mode converts ex. name[last] to name[][last]
        # but legacy get_notation() would pick first field only ex. name[0][last]
        if (parsed_notation[2].index1 and parsed_notation[2].index2 and
            parsed_notation[2].index1[1] == "[]" and parsed_notation[2].index2[1] != "[]"):
            parsed_notation[2].index1 = ("0", "[0]")

        parameter = parsed_notation[2].parameter[0] if parsed_notation[2].parameter else None
        index1 = parsed_notation[2].index1[0] if parsed_notation[2].index1 else None
        index2 = parsed_notation[2].index2[0] if parsed_notation[2].index2 else None
        selectors_with_params = ("file", "field", "custom_field")
        if (parameter is None and selector in selectors_with_params):
            raise ValueError(f"Invalid notation '{url}' - field key/parameter is missing in the keeper url.")
        if (parameter is not None and selector not in selectors_with_params):
            raise ValueError(f"Invalid notation '{url}' - field key/parameter is required only for fields/file.")

        # Legacy to new parser mapping:
        # (uid, field_data_type, key[index][dict_key]) == (record_token, selector, parameter[index1][index2])

        # By default, we want to return a single value, which is the first item in the array
        return_single = True
        index = 0
        dict_key = None

        if parameter is not None:
            # Is the first predicate an index into an array?
            if (index1 or "").isdigit() is True:
                index = int(index1 or "")
            # Is the first predicate a key to a dictionary?
            elif index1 != "":
                dict_key = index1
            # Else it was an array indicator. Return all the values.
            else:
                return_single = False

            if index2 is not None:
                if return_single is False:
                    raise ValueError("If the second [] is a dictionary key, the first [] needs to have any index.")
                if (index2 or "").isdigit() is True:
                    raise ValueError("The second [] can only by a key for the dictionary. It cannot be an index.")
                # Is the second predicate a key to a dictionary?
                elif index2 != "":
                    dict_key = index2
                else:
                    raise ValueError("The second [] must have key for the dictionary. Cannot be blank.")

        # to minimize traffic - if it looks like a Record UID try to pull a single record
        records = []
        if re.fullmatch(r"^[A-Za-z0-9_-]{22}$", record_token):
            secrets = self.get_secrets([record_token])
            records = secrets if isinstance(secrets, list) else []
            if len(records) > 1:
                raise ValueError(f"Notation error - found multiple records with same UID '{record_token}'")

        # If RecordUID is not found - pull all records and search by title
        if len(records) < 1:
            secrets = self.get_secrets() or []
            if isinstance(secrets, list) and len(secrets) > 0:
                records = [x for x in secrets if x.title == record_token]

        if len(records) < 1:
                raise ValueError(f"Notation error - no records match record UID/Title: '{record_token}'")
        if len(records) > 1:
                raise ValueError(f"Notation error - multiple records match record UID/Title: '{record_token}'")

        record = records[0]

        if selector.lower() == "type":
            return record.type
        elif selector.lower() == "title":
            return record.title
        elif selector.lower() == "notes":
            return record.dict.get("notes", None)
        elif selector.lower() == "file":
            if parameter is None:
                raise ValueError(f"Notation error - Missing required parameter 'filename' or 'fileUID' for files in record '{record_token}'")
            if not isinstance(record.files, list) or len(record.files) < 1:
                raise ValueError(f"Notation error - Record {record_token} has no file attachments.")
            files = record.files or []
            files = [x for x in files if parameter == x.name or parameter == x.title or parameter == x.f.get("fileUid", "")]
            # file searches do not use indexes and rely on unique file names or fileUid
            if len(files) > 1:
                raise ValueError(f"Notation error - Record {record_token} has multiple files matching the search criteria '{parameter}'")
            if len(files) < 1:
                raise ValueError(f"Notation error - Record {record_token} has no files matching the search criteria '{parameter}'")
            if isinstance(files[0], KeeperFile):
                return files[0].get_file_data()
            else:
                raise ValueError(f"Notation error - Record {record_token} has corrupted KeeperFile data.")
        elif selector.lower() in ("field", "custom_field"):
            field_kind = "standard" if selector.lower() == "field" else "custom"
            field = (record.get_standard_field(parameter)
                     if field_kind == "standard"
                     else record.get_custom_field(parameter))
            if field is None:
                raise ValueError(f"Cannot find {field_kind} field '{parameter}'")
            value = field.get("value")
            field_type = field.get("type")

            # Inflate the value if its part of list of types to inflate.
            # This will request additional records from secrets manager.
            if field_type in SecretsManager.inflate_ref_types:
                value = self.inflate_field_value(value, SecretsManager.inflate_ref_types[field_type])

            ret = value
            if return_single is True and type(value) is list:
                if len(value) == 0:
                    return None
                try:
                    ret = value[index]
                    if dict_key is not None:
                        if dict_key not in ret:
                            raise ValueError(f"Cannot find the dictionary key {dict_key} in the value")
                        ret = ret[dict_key]
                except IndexError:
                    raise ValueError(f"The value at index {index} does not exist for {url}.")
            return ret
        else:
            raise ValueError(f"Invalid notation {url} - Bad selector '{selector}'")

    @staticmethod
    def __parse_subsection(text: str, pos: int, delimiters: str, escaped: bool=False) -> Optional[Tuple[str, str]]:
        escape_char = "\\"
        escape_chars = "/[]\\" # /[]\ -> \/ ,\[, \], \\
        # escape the characters in plaintext sections only - title, label or filename

        # raw string excludes start delimiter (if '/') but includes end delimiter or both (if '[',']')
        if text is None or text == "" or pos < 0 or pos >= len(text):
            return None
        if not delimiters or len(delimiters) > 2:
            raise ValueError(f"Notation parser: Internal error - Incorrect delimiters count. Delimiters: '{delimiters}'")

        token = ""
        raw = ""
        while pos < len(text):
            if escaped and escape_char == text[pos]:
                # notation cannot end in single char incomplete escape sequence
                # and only escape_chars should be escaped
                if (((pos + 1) >= len(text)) or
                    (text[pos+1] not in escape_chars)):
                    raise ValueError(f"Notation parser: Incorrect escape sequence at position {pos}")
                # copy the properly escaped character
                token += text[pos+1]
                raw += text[pos] + text[pos+1]
                pos += 2
            else: # escaped == False or escape_char != text[pos]
                raw += text[pos] # delimiter is included in raw text
                if len(delimiters) == 1:
                    if text[pos] == delimiters[0]:
                        break
                    else:
                        token += text[pos]
                else: # 2 delimiters
                    if raw[0] != delimiters[0]:
                        raise ValueError("Notation parser error: Index sections must start with '['")
                    if (len(raw) > 1 and text[pos] == delimiters[0]):
                        raise ValueError("Notation parser error: Index sections do not allow extra '[' inside.")
                    if text[pos] not in delimiters:
                        token += text[pos]
                    elif text[pos] == delimiters[1]:
                        break
                pos += 1

        # pos = len(text)-1 if (pos >= len(text)) else pos
        if (len(delimiters) == 2 and (
            (len(raw) < 2 or raw[0] != delimiters[0] or raw[-1] != delimiters[1]) or
            (escaped and raw[-2] == escape_char))):
            raise ValueError("Notation parser error: Index sections must be enclosed in '[' and ']'")

        return (token, raw)

    @staticmethod
    def __parse_section(notation: str, section: str, pos: int) -> NotationSection:
        if not notation:
            raise ValueError("Keeper notation parsing error - missing notation URI")

        section_name = (section or "").lower()
        sections = ("prefix", "record", "selector", "footer")
        if section_name not in sections:
            raise ValueError(f"Keeper notation parsing error - unknown section: {section_name}")

        result = NotationSection(section)
        result.start_pos = pos

        # prefix "keeper://" is not mandatory
        if section_name == "prefix":
            uri_prefix = SecretsManager.notation_prefix + "://"
            if notation.lower().startswith(uri_prefix.lower()):
                result.is_present = True
                result.start_pos = 0
                result.end_pos = len(uri_prefix)-1
                result.text = (notation[:len(uri_prefix)], notation[:len(uri_prefix)])

        # footer should not be present - used only for verification
        elif section_name == "footer":
            result.is_present = True if pos < len(notation) else False
            if result.is_present:
                result.start_pos = pos
                result.end_pos = len(notation)-1
                result.text = (notation[pos:], notation[pos:])

        # record is always present - either UID or title
        elif section_name == "record":
            result.is_present = True if pos < len(notation) else False
            if result.is_present:
                parsed = SecretsManager.__parse_subsection(notation, pos, "/", True)
                if parsed is not None:
                    result.start_pos = pos
                    result.end_pos = pos + len(parsed[1]) - 1
                    result.text = parsed

        # selector is always present - type|title|notes | field|custom_field|file
        elif section_name == "selector":
            result.is_present = True if pos < len(notation) else False
            if result.is_present:
                parsed = SecretsManager.__parse_subsection(notation, pos, "/", False)
                if parsed is not None:
                    result.start_pos = pos
                    result.end_pos = pos + len(parsed[1]) - 1
                    result.text = parsed

                    # selector.parameter - <field type>|<field label> | <file name>
                    # field/name[0][middle], custom_field/my label[0][middle], file/my file[0]
                    longSelectors = ("field", "custom_field", "file")
                    if parsed[0].lower() in longSelectors:
                        # TODO: File metadata extraction: ex. filename[1][size] - that requires filename to be escaped
                        parsed = SecretsManager.__parse_subsection(notation, result.end_pos+1, "[", True)
                        if parsed is not None:
                            result.parameter = parsed # <field type>|<field label> | <filename>
                            plen = len(parsed[1]) - (1 if (parsed[1][-1:] == "[" and parsed[1][-2:] != "\\[") else 0)
                            result.end_pos += plen
                            parsed = SecretsManager.__parse_subsection(notation, result.end_pos+1, "[]", True)
                            if parsed is not None:
                                result.index1 = parsed # selector.index1 [int] or []
                                result.end_pos += len(parsed[1])
                                parsed = SecretsManager.__parse_subsection(notation, result.end_pos+1, "[]", True)
                                if parsed is not None:
                                    result.index2 = parsed # selector.index2 [str]
                                    result.end_pos += len(parsed[1])
        else:
            raise ValueError(f"Keeper notation parsing error - unknown section '{section_name}'")

        return result

    @staticmethod
    def parse_notation(notation: str, legacy_mode: bool = False) -> List[NotationSection]:
        if not (notation and isinstance(notation, str)):
            raise ValueError(f"Keeper notation is missing or invalid. Notation: '{notation}'")

        # Notation is either plaintext keeper URI format or URL safe base64 string (UTF8)
        # auto detect format - '/' is not part of base64 URL safe alphabet
        if "/" not in notation:
            try:
                plaintext = urlsafe_b64decode(notation)
                notation = plaintext.decode()
            except:
                raise ValueError("Invalid format of Keeper notation - plaintext URI or URL safe base64 string "
                                 "expected.")

        prefix = SecretsManager.__parse_section(notation, "prefix", 0)  # keeper://
        pos = prefix.end_pos+1 if prefix.is_present else 0 # prefix is optional
        record = SecretsManager.__parse_section(notation, "record", pos)  # <UID> or <Title>
        pos = record.end_pos+1 if record.is_present else len(notation) # record is required
        selector = SecretsManager.__parse_section(notation, "selector", pos)  # type|title|notes | field|custom_field|file
        pos = selector.end_pos+1 if selector.is_present else len(notation) # selector is required, indexes are optional
        footer = SecretsManager.__parse_section(notation, "footer", pos)  # Any text after the last section

        # verify parsed query
        # prefix is optional, record UID/Title and selector are mandatory
        short_selectors = ("type", "title", "notes")
        full_selectors = ("field", "custom_field", "file")
        selectors = ("type", "title", "notes", "field", "custom_field", "file")
        if not record.is_present or not selector.is_present:
            raise ValueError("Keeper notation URI missing information about the uid, file, field type, or field key.")
        if footer.is_present:
            raise ValueError("Keeper notation is invalid - extra characters after last section.")
        if not selector.text or selector.text[0].lower() not in selectors:
            raise ValueError("Keeper notation is invalid - bad selector, must be one of (type, title, notes, field, custom_field, file).")
        if selector.text and selector.text[0].lower() in short_selectors and selector.parameter:
            raise ValueError("Keeper notation is invalid - selectors (type, title, notes) do not have parameters.")
        if selector.text and selector.text[0].lower() in full_selectors:
            if selector.parameter is None:
                raise ValueError("Keeper notation is invalid - selectors (field, custom_field, file) require parameters.")
            if selector.text[0].lower() == "file" and not(selector.index1 is None and selector.index2 is None):
                raise ValueError("Keeper notation is invalid - file selectors don't accept indexes.")
            if selector.text[0].lower() != "file" and selector.index1 is None and selector.index2 is not None:
                raise ValueError("Keeper notation is invalid - two indexes required.")
            if selector.index1 is not None and not re.fullmatch(r"^\[\d*\]$", selector.index1[1]):
                if not legacy_mode:
                    raise ValueError("Keeper notation is invalid - first index must be numeric: [n] or []")
                # in legacy mode convert /name[middle] to name[][middle]
                if selector.index2 is None:
                    selector.index2 = selector.index1
                    selector.index1 = ("", "[]")

        return [prefix, record, selector, footer]

    def try_get_notation_results(self, notation: str) -> List[str]:
        """
        Returns a string list with all values specified by the notation or empty list on error.
        It simply logs any errors and continue returning an empty string list on error.
        """
        try:
            return self.get_notation_results(notation)
        except Exception as e:
            self.logger.error(e)
        return []

    # Notation:
    # keeper://<uid|title>/<field|custom_field>/<type|label>[INDEX][PROPERTY]
    # keeper://<uid|title>/file/<filename|fileUID>
    # Record title, field label, filename sections need to escape the delimiters /[]\ -> \/ \[ \] \\
    #
    # GetNotationResults returns selection of the value(s) from a single field as a string list.
    # Multiple records or multiple fields found results in error.
    # Use record UID or unique record titles and field labels so that notation finds a single record/field.
    #
    # If field has multiple values use indexes - numeric INDEX specifies the position in the value list
    # and PROPERTY specifies a single JSON object property to extract (see examples below for usage)
    # If no indexes are provided - whole value list is returned (same as [])
    # If PROPERTY is provided then INDEX must be provided too - even if it's empty [] which means all
    #
    # Extracting two or more but not all field values simultaneously is not supported - use multiple notation requests.
    #
    # Files are returned as URL safe base64 encoded string of the binary content
    #
    # Note: Integrations and plugins usually return single string value - result[0] or ""
    #
    # Examples:
    #  RECORD_UID/file/filename.ext             => ["URL Safe Base64 encoded binary content"]
    #  RECORD_UID/field/url                     => ["127.0.0.1", "127.0.0.2"] or [] if empty
    #  RECORD_UID/field/url[]                   => ["127.0.0.1", "127.0.0.2"] or [] if empty
    #  RECORD_UID/field/url[0]                  => ["127.0.0.1"] or error if empty
    #  RECORD_UID/custom_field/name[first]      => Error, numeric index is required to access field property
    #  RECORD_UID/custom_field/name[][last]     => ["Smith", "Johnson"]
    #  RECORD_UID/custom_field/name[0][last]    => ["Smith"]
    #  RECORD_UID/custom_field/phone[0][number] => "555-5555555"
    #  RECORD_UID/custom_field/phone[1][number] => "777-7777777"
    #  RECORD_UID/custom_field/phone[]          => ["{\"number\": \"555-555...\"}", "{\"number\": \"777...\"}"]
    #  RECORD_UID/custom_field/phone[0]         => ["{\"number\": \"555-555...\"}"]

    def get_notation_results(self, notation: str) -> List[str]:
        """
        Returns a string list with all values specified by the notation or throws an error.
        Use try_get_notation_results to just log errors and continue returning an empty string list on error.
        """

        result: List[str] = []

        parsed_notation = self.parse_notation(notation) # [prefix, record, selector, footer]
        if len(parsed_notation) < 3:
            raise ValueError(f"Invalid notation '{notation}'")

        if parsed_notation[2].text is None:
            raise ValueError(f"Invalid notation '{notation}'")
        selector = parsed_notation[2].text[0] # type|title|notes or file|field|custom_field
        if parsed_notation[1].text is None:
            raise ValueError(f"Invalid notation '{notation}'")
        record_token = parsed_notation[1].text[0] # UID or Title

        # to minimize traffic - if it looks like a Record UID try to pull a single record
        records = []
        if re.fullmatch(r"^[A-Za-z0-9_-]{22}$", record_token):
            secrets = self.get_secrets([record_token])
            records = secrets if isinstance(secrets, list) else []
            if len(records) > 1:
                raise ValueError(f"Notation error - found multiple records with same UID '{record_token}'")

        # If RecordUID is not found - pull all records and search by title
        if len(records) < 1:
            secrets = self.get_secrets() or []
            if isinstance(secrets, list) and len(secrets) > 0:
                records = [x for x in secrets if x.title == record_token]

        if len(records) > 1:
                raise ValueError(f"Notation error - multiple records match record '{record_token}'")
        if len(records) < 1:
                raise ValueError(f"Notation error - no records match record '{record_token}'")

        record = records[0]
        parameter = parsed_notation[2].parameter[0] if parsed_notation[2].parameter else None
        index1 = parsed_notation[2].index1[0] if parsed_notation[2].index1 else None
        index2 = parsed_notation[2].index2[0] if parsed_notation[2].index2 else None

        if selector.lower() == "type":
            if record.type is not None: result.append(record.type)
        elif selector.lower() == "title":
            if record.title is not None: result.append(record.title)
        elif selector.lower() == "notes":
            if record.dict.get("notes", None) is not None: result.append(record.dict.get("notes", ""))
        elif selector.lower() == "file":
            if parameter is None:
                raise ValueError(f"Notation error - Missing required parameter: filename or file UID for files in record '{record_token}'")
            if not isinstance(record.files, list) or len(record.files) < 1:
                raise ValueError(f"Notation error - Record {record_token} has no file attachments.")
            files = record.files or []
            files = [x for x in files if parameter == x.name or parameter == x.title or parameter == x.f.get("fileUid", "")]
            # file searches do not use indexes and rely on unique file names or fileUid
            if len(files) > 1:
                raise ValueError(f"Notation error - Record {record_token} has multiple files matching the search criteria '{parameter}'")
            if len(files) < 1:
                raise ValueError(f"Notation error - Record {record_token} has no files matching the search criteria '{parameter}'")
            if isinstance(files[0], KeeperFile):
                contents = files[0].get_file_data()
                text = CryptoUtils.bytes_to_url_safe_str(contents)
                result.append(text)
            else:
                raise ValueError(f"Notation error - Record {record_token} has corrupted KeeperFile data.")
        elif selector.lower() in ("field", "custom_field"):
            if parameter is None:
                raise ValueError(f"Notation error - Missing required parameter for the field (type or label): ex. /field/type or /custom_field/MyLabel")

            fields = record.dict.get("fields", [])
            if selector.lower() == "custom_field":
                fields = record.dict.get("custom", [])
            fields = fields or []

            flds = [x for x in fields if parameter == x.get("type", None) or parameter == x.get("label", None)]
            if len(flds) > 1:
                    raise ValueError(f"Notation error - Record {record_token} has multiple fields matching the search criteria '{parameter}'")
            if len(flds) < 1:
                    raise ValueError(f"Notation error - Record {record_token} has no fields matching the search criteria '{parameter}'")
            field = flds[0]
            fieldType = field.get("type", "")

            idx = -1 # // -1 == full value
            try: idx = int(str(index1))
            except: idx = -1
            # valid only if [] or missing - ex. /field/phone or /field/phone[]
            if idx == -1 and not(parsed_notation[2].index1 is None or parsed_notation[2].index1[1] == "" or parsed_notation[2].index1[1] == "[]"):
                raise ValueError(f"Notation error - Invalid field index '{idx}'")

            values = []
            if isinstance(field.get("value", []), list):
                values = field.get("value", [])
            if idx >= len(values):
                raise ValueError(f"Notation error - Field index out of bounds {idx} >= {len(values)} for field '{parameter}'")
            if idx >= 0: # single index
                values = [values[idx]]

            fullObjValue = parsed_notation[2].index2 is None or parsed_notation[2].index2[1] == "" or parsed_notation[2].index2[1] == "[]"
            objPropertyName = parsed_notation[2].index2[0] if parsed_notation[2].index2 is not None else ""

            res: List[str] = []
            for fldValue in values:
                # Do not throw here to allow for ex. field/name[][middle] to pull [middle] only where present
                # NB! Not all properties of a value are always required even when the field is marked as required
                # ex. On a required `name` field only "first" and "last" properties are required but not "middle"
                # so missing property in a field value is not always an error
                if fldValue is None:
                    self.logger.error(f"Notation error - Empty field value for field '{parameter}'") # raise?

                if fullObjValue:
                    v = fldValue if isinstance(fldValue, str) else json.dumps(fldValue)
                    res.append(v)
                elif fldValue is not None and isinstance(fldValue, dict):
                    if objPropertyName in fldValue:
                        prop = fldValue.get(objPropertyName, None)
                        v = prop if isinstance(prop, str) else json.dumps(prop)
                        res.append(v)
                    else:
                        self.logger.error(f"Notation error - value object has no property '{objPropertyName}'") # skip
                else:
                    self.logger.error(f"Notation error - Cannot extract property '{objPropertyName}' from null value.")
            if len(res) != len(values):
                self.logger.error(f"Notation warning - extracted {len(res)} out of {len(values)} values for '{objPropertyName}' property.")
            if len(res) > 0:
                result.extend(res)
        else:
            raise ValueError(f"Invalid notation {notation}")

        return result

    @staticmethod
    def get_inflate_ref_types(field_type):
        return SecretsManager.inflate_ref_types.get(field_type, [])

    def inflate_field_value(self, uids, replace_fields):

        # The replacement value
        value = []

        # Get the record and make a lookup for them.
        lookup = {}
        records = self.get_secrets(uids)
        for record in records:
            lookup[record.uid] = record

        for uid in uids:
            record = lookup.get(uid)
            new_value = None
            if record is not None:
                for replacement_key in replace_fields:
                    # Replacement are always in the standard fields.
                    real_field = record.get_standard_field(replacement_key)

                    # If we can't find it, move onto the next type. There might be a problem with the record.
                    if real_field is None:
                        self.logger.debug("Cannot find {} in the fields in record UID {} for inflation. Skipping". \
                                          format(replacement_key, uid))
                        continue
                    real_values = real_field.get("value", [])
                    if len(real_values) > 0:
                        real_value = real_values[0]
                        if real_value is not None:

                            # Do we need to replace a value in our real value?
                            if replacement_key in SecretsManager.inflate_ref_types:
                                real_value = self.inflate_field_value([real_value], SecretsManager.inflate_ref_types[
                                    replacement_key])
                                if real_value is not None:
                                    real_value = real_value[0]

                            # If we don't have value, just use the real value. It might be a str or a dict. We
                            # do this because the value of the real_value might be the final value. So it might
                            # be a str or dict, just leave it that way for now.
                            if new_value is None:
                                new_value = real_value
                            else:
                                # If we need to add a new key/value use the label and fall back the the type
                                label = real_field.get("label", real_field.get("type"))

                                # Since we have more than 1 value, convert the value to a dict if it is not already
                                # one.
                                if type(new_value) is not dict:
                                    new_value = {
                                        label: new_value
                                    }
                                # If the real_value is a dict, then copy the k/v pair into the value
                                if type(real_value) is dict:
                                    for k, v in real_value.items():
                                        new_value[k] = v
                                # Else the real_value is str, use the label/type as a key
                                else:
                                    new_value[label] = real_value
            if new_value is not None:
                value.append(new_value)

        return value


class KSMCache:
    # Allow the directory that will contain the cache to be set with environment variables. If not set, the
    # cache file will be create in the current working directory.
    kms_cache_file_name = os.path.join(os.environ.get("KSM_CACHE_DIR", ""), 'ksm_cache.bin')

    @staticmethod
    def save_cache(data):
        cache_file = open(KSMCache.kms_cache_file_name, 'wb')
        cache_file.write(data)
        cache_file.close()

    @staticmethod
    def get_cached_data():
        cache_file = open(KSMCache.kms_cache_file_name, 'rb')
        cache_data = cache_file.read()
        cache_file.close()
        return cache_data

    @staticmethod
    def remove_cache_file():
        if os.path.exists(KSMCache.kms_cache_file_name) is True:
            os.unlink(KSMCache.kms_cache_file_name)

    @staticmethod
    def caching_post_function(url, transmission_key, encrypted_payload_and_signature, verify_ssl_certs=True):

        try:

            ksm_rs = SecretsManager.post_function(url, transmission_key, encrypted_payload_and_signature, verify_ssl_certs)

            if ksm_rs.status_code == 200:
                KSMCache.save_cache(transmission_key.key + ksm_rs.data)
                return ksm_rs
        except:
            cached_data = KSMCache.get_cached_data()
            cached_transmission_key = cached_data[:32]
            transmission_key.key = cached_transmission_key
            data = cached_data[32:len(cached_data)]

            ksm_rs = KSMHttpResponse(HTTPStatus.OK, data, None)

        return ksm_rs
