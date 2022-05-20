#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com

import hmac
import logging
import os
from distutils.util import strtobool
import re
import json
from http import HTTPStatus

import requests

from keeper_secrets_manager_core import utils, helpers
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.dtos import Folder, Record, RecordCreate, SecretsManagerResponse, AppData, \
    KeeperFileUpload
from keeper_secrets_manager_core.dto.payload import GetPayload, UpdatePayload, TransmissionKey, \
    EncryptedPayload, KSMHttpResponse, CreatePayload, FileUploadPayload
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.keeper_globals import keeper_secrets_manager_sdk_client_id, keeper_public_keys, \
    logger_name, keeper_servers
from keeper_secrets_manager_core.storage import FileKeyValueStorage, KeyValueStorage, InMemoryKeyValueStorage
from keeper_secrets_manager_core.utils import base64_to_bytes, dict_to_json, \
    url_safe_str_to_bytes, bytes_to_base64, generate_random_bytes, now_milliseconds, string_to_bytes, json_to_dict, \
    bytes_to_string


def find_secrets_by_title(record_title, records):
    # Find all records with specified title
    records = records or []
    return [x for x in records if x.title == record_title]

def find_secret_by_title(record_title, records):
    # Find first record with specified title
    records = records or []
    return next((x for x in records if x.title == record_title), None)

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

        client_id = self.config.get(ConfigKeys.KEY_CLIENT_ID)

        if client_id:
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

        if not self.verify_ssl_certs:
            self.logger.warning("WARNING: Running without SSL cert verification. "
                                "Execute 'SecretsManager(..., verify_ssl_certs=True)' or 'KSM_SKIP_VERIFY=FALSE' "
                                "to enable verification.")

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
                isinstance(payload, FileUploadPayload)):
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
    def prepare_get_payload(storage, records_filter):

        payload = GetPayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)

        app_key_str = storage.get(ConfigKeys.KEY_APP_KEY)

        if not app_key_str:

            public_key_bytes = CryptoUtils.extract_public_key_bytes(storage.get(ConfigKeys.KEY_PRIVATE_KEY))
            public_key_base64 = bytes_to_base64(public_key_bytes)
            # passed once when binding
            payload.publicKey = public_key_base64

        if records_filter:
            payload.requestedRecords = records_filter

        return payload

    @staticmethod
    def prepare_create_payload(storage, folder_uid, record_data_json_str, folder_key):

        owner_public_key = storage.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY)

        if not owner_public_key:
            raise KeeperError('Unable to create record - owner key is missing. Looks like application was created '
                              'using out date client (Web Vault or Commander)')

        owner_public_key_bytes = url_safe_str_to_bytes(owner_public_key)

        if not folder_key:
            raise KeeperError('Unable to create record - folder key for ' + folder_uid + ' is missing')

        record_bytes = ""
        record_key = generate_random_bytes(32)
        record_uid = generate_random_bytes(16)

        record_data_bytes = utils.string_to_bytes(record_data_json_str)
        record_data_encrypted = CryptoUtils.encrypt_aes(record_data_bytes, record_key)

        record_key_encrypted = CryptoUtils.public_encrypt(record_key, owner_public_key_bytes)

        folder_key_encrypted = CryptoUtils.encrypt_aes(record_key, folder_key)

        payload = CreatePayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)
        payload.recordUid = CryptoUtils.bytes_to_url_safe_str(record_uid)
        payload.recordKey = bytes_to_base64(record_key_encrypted)
        payload.folderUid = folder_uid
        payload.folderKey = bytes_to_base64(folder_key_encrypted)
        payload.data = bytes_to_base64(record_data_encrypted)

        return payload

    @staticmethod
    def prepare_update_payload(storage, record):

        payload = UpdatePayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = storage.get(ConfigKeys.KEY_CLIENT_ID)

        # for update, uid of the record
        payload.recordUid = record.uid
        payload.revision = record.revision

        raw_json_bytes = utils.string_to_bytes(record.raw_json)
        encrypted_raw_json_bytes = CryptoUtils.encrypt_aes(raw_json_bytes, record.record_key_bytes)

        payload.data = bytes_to_base64(encrypted_raw_json_bytes)

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
        raise requests.HTTPError(rs.text)

    def fetch_and_decrypt_secrets(self, record_filter=None):

        payload = SecretsManager.prepare_get_payload(self.config, records_filter=record_filter)

        decrypted_response_bytes = self._post_query(
            'get_secret',
            payload
        )

        decrypted_response_str = utils.bytes_to_string(decrypted_response_bytes)
        decrypted_response_dict = utils.json_to_dict(decrypted_response_str)

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

        if records_resp:
            for r in records_resp:
                record = Record(r, secret_key)
                records.append(record)

        if folders_resp:
            for f in folders_resp:
                folder = Folder(f, secret_key)
                records.extend(folder.records)
                shared_folders.append(folder)

        self.logger.debug("Total record count: {}".format(len(records)))

        sm_response = SecretsManagerResponse()

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
        """

        if isinstance(uids, str):
            uids = [uids]

        records_resp = self.fetch_and_decrypt_secrets(uids)

        if records_resp.justBound:
            records_resp = self.fetch_and_decrypt_secrets(uids)

        # Log warnings we got from the server
        # Will only be displayed if logging is enabled:
        if records_resp.warnings:
            for warning in records_resp.warnings:
                self.logger.warning(warning)

        if full_response:
            return records_resp
        else:
            records = records_resp.records or []

            return records

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

        payload = SecretsManager.prepare_create_payload(self.config, folder_uid, record_data_json_str, found_folder.key)

        self._post_query('create_secret', payload)

        return payload.recordUid

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

    def save(self, record):
        """
        Save updated secret values
        """

        self.logger.info("Updating record uid: %s" % record.uid)

        payload = SecretsManager.prepare_update_payload(self.config, record)

        self._post_query(
            'update_secret',
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

        # If the URL starts with keeper:// we want to remove it.
        if url.startswith(SecretsManager.notation_prefix) is True:
            url_parts = url.split('//')
            try:
                url = url_parts[1]
                if url is None:
                    # Get the except below handle it
                    raise ValueError()
            except IndexError:
                raise ValueError("Keeper url missing information about the uid, field type, and field key.")

        try:
            (uid, file_data_type, key) = url.split('/')
        except Exception as _:
            raise ValueError("Could not parse the notation {}. Is it valid?".format(url))

        if uid is None:
            raise ValueError("UID is missing the in the keeper url.")
        if file_data_type is None:
            raise ValueError("file type is missing the in the keeper url.")
        if key is None:
            raise ValueError("file key is missing the in the keeper url.")

        # By default, we want to return a single value, which is the first item in the array
        return_single = True
        index = 0
        dict_key = None

        # Check it see if the key has a predicate, possibly with an index.
        predicate = re.search(r'\[.*]', key)
        if predicate is not None:

            # If we do, get the predicate and remove the brackets, to get the index if one exists
            match = predicate.group()

            predicate_parts = match.split("]")
            while "" in predicate_parts:
                predicate_parts.remove("")

            if len(predicate_parts) == 0:
                raise ValueError("The predicate of the notation appears to be invalid. Syntax error?")
            if len(predicate_parts) > 2:
                raise ValueError("The predicate of the notation appears to be invalid. Too many [], max 2 allowed.")

            # This will remove the preceding '['
            first_predicate = predicate_parts[0][1:]
            if first_predicate is not None:
                # Is the first predicate an index into an array?
                if first_predicate.isdigit() is True:
                    index = int(first_predicate)
                # Is the first predicate a key to a dictionary?
                elif re.match(r'^[a-zA-Z0-9_]+$', first_predicate):
                    dict_key = first_predicate
                # Else it was an array indicator. Return all the values.
                else:
                    return_single = False

            if len(predicate_parts) == 2:
                if return_single is False:
                    raise ValueError("If the second [] is a dictionary key, the first [] needs to have any index.")
                # Remove the preceding '['
                second_predicate = predicate_parts[1][1:]
                if second_predicate.isdigit() is True:
                    raise ValueError("The second [] can only by a key for the dictionary. It cannot be an index.")
                # Is the first predicate a key to a dictionary?
                elif re.match(r'^[a-zA-Z0-9_]+$', second_predicate):
                    dict_key = second_predicate
                else:
                    raise ValueError("The second [] must have key for the dictionary. Cannot be blank.")

            # Remove the predicate from the key, if it exists
            key = re.sub(r'\[.*', '', key)

        records = self.get_secrets([uid])
        if len(records) == 0:
            raise ValueError("Could not find a record with the UID {}".format(uid))

        record = records[0]

        field_type = None
        if file_data_type == "field":
            field = record.get_standard_field(key)
            if field is None:
                raise ValueError("Cannot find standard field {}".format(key))
            value = field.get("value")
            field_type = field.get("type")
        elif file_data_type == "custom_field":
            field = record.get_custom_field(key)
            if field is None:
                raise ValueError("Cannot find custom field {}".format(key))
            value = field.get("value")
            field_type = field.get("type")
        elif file_data_type == "file":
            file = record.find_file_by_title(key)
            if file is None:
                raise FileNotFoundError("Cannot find the file {} in record {}.".format(key, uid))
            value = file.get_file_data()
        else:
            raise ValueError("Field type of {} is not valid.".format(file_data_type))

        # Inflate the value if its part of list of types to inflate. This will request additional records
        # from secrets manager.
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
                        raise ValueError("Cannot find the dictionary key {} in the value".format(dict_key))
                    ret = ret[dict_key]
            except IndexError:
                raise ValueError("The value at index {} does not exist for {}.".format(index, url))
        return ret

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
