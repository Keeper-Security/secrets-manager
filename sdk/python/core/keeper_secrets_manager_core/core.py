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
import base64

import requests

from keeper_secrets_manager_core import utils, helpers
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.dtos import Folder, Record
from keeper_secrets_manager_core.dto.payload import GetPayload, UpdatePayload, TransmissionKey, \
    EncryptedPayload, KSMHttpResponse
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.keeper_globals import keeper_secrets_manager_sdk_client_id, keeper_public_keys, \
    logger_name
from keeper_secrets_manager_core.storage import FileKeyValueStorage, KeyValueStorage
from keeper_secrets_manager_core.utils import bytes_to_url_safe_str, base64_to_bytes, dict_to_json, \
    url_safe_str_to_bytes


class SecretsManager:

    notation_prefix = "keeper"
    default_key_id = "7"

    # Field types that can be inflated. Used for notation.
    inflate_ref_types = {
        "addressRef": ["address"],
        "cardRef": ["paymentCard", "text", "pinCode", "addressRef"]
    }

    def __init__(self,
                 token=None, hostname=None, verify_ssl_certs=True, config=None, log_level=None,
                 custom_post_function=None):

        self.token = token
        self.hostname = hostname

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
        if token is not None:
            config.set(ConfigKeys.KEY_CLIENT_KEY, token)
        if hostname is not None:
            config.set(ConfigKeys.KEY_HOSTNAME, hostname)

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
            existing_secret_key_hash = bytes_to_url_safe_str(hmac.new(existing_secret_key_bytes,
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
                self.config.set(ConfigKeys.KEY_PRIVATE_KEY, bytes_to_url_safe_str(private_key_der))

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

        if not (isinstance(payload, GetPayload) or isinstance(payload, UpdatePayload)):
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
        client_id_bytes = base64_to_bytes(storage.get(ConfigKeys.KEY_CLIENT_ID))
        payload.clientId = bytes_to_url_safe_str(client_id_bytes) + "="

        app_key_str = storage.get(ConfigKeys.KEY_APP_KEY)

        if not app_key_str:

            public_key_bytes = CryptoUtils.extract_public_key_bytes(storage.get(ConfigKeys.KEY_PRIVATE_KEY))
            public_key_base64 = bytes_to_url_safe_str(public_key_bytes)
            # passed once when binding
            payload.publicKey = public_key_base64 + "="

        if records_filter:
            payload.requestedRecords = records_filter

        return payload

    @staticmethod
    def prepare_update_payload(storage, record):

        payload = UpdatePayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        client_id_bytes = base64_to_bytes(storage.get(ConfigKeys.KEY_CLIENT_ID))
        payload.clientId = bytes_to_url_safe_str(client_id_bytes) + "="

        # for update, uid of the record
        payload.recordUid = record.uid
        payload.revision = record.revision

        # TODO: This is where we need to get JSON of the updated Record
        raw_json_bytes = utils.string_to_bytes(record.raw_json)
        encrypted_raw_json_bytes = CryptoUtils.encrypt_aes(raw_json_bytes, record.record_key_bytes)
        encrypted_raw_json_bytes_str = bytes_to_url_safe_str(encrypted_raw_json_bytes)

        # for create and update, the record data
        payload.data = encrypted_raw_json_bytes_str

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
            'TransmissionKey': bytes_to_url_safe_str(transmission_key.encryptedKey),
            'Authorization': 'Signature %s' % bytes_to_url_safe_str(encrypted_payload_and_signature.signature)
        }

        rs = requests.post(
            url,
            headers=request_headers,
            data=encrypted_payload_and_signature.encrypted_payload,
            verify=verify_ssl_certs
        )

        ksm_rs = KSMHttpResponse(rs.status_code, rs.content, rs)

        return ksm_rs

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

        just_bound = False

        if decrypted_response_dict.get('encryptedAppKey'):
            just_bound = True

            encrypted_master_key = url_safe_str_to_bytes(decrypted_response_dict.get('encryptedAppKey'))
            client_key = self.config.get(ConfigKeys.KEY_CLIENT_KEY)
            client_key = base64.urlsafe_b64decode(client_key + "==")
            secret_key = CryptoUtils.decrypt_aes(encrypted_master_key, client_key)
            self.config.set(ConfigKeys.KEY_APP_KEY, bytes_to_url_safe_str(secret_key))

            self.config.delete(ConfigKeys.KEY_CLIENT_KEY)

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

        self.logger.debug("Total record count: {}".format(len(records)))

        return {
            'records': records,
            'justBound': just_bound
        }

    def get_secrets(self, uids=None):
        """
        Retrieve all records associated with the given application
        """

        if isinstance(uids, str):
            uids = [uids]

        records_resp = self.fetch_and_decrypt_secrets(uids)

        just_bound = records_resp.get('justBound')

        if just_bound:
            records_resp = self.fetch_and_decrypt_secrets(uids)

        records = records_resp.get('records') or []

        return records

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

            EG6KdJaaLG7esRZbMnfbFA/field/password                => MyPasswprd
            EG6KdJaaLG7esRZbMnfbFA/field/password[0]             => MyPassword
            EG6KdJaaLG7esRZbMnfbFA/field/password[]              => ["MyPassword"]
            EG6KdJaaLG7esRZbMnfbFA/custom_field/name[first]      => John
            EG6KdJaaLG7esRZbMnfbFA/custom_field/name[last]       => Smitht
            EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[0][number] => "555-5555555"
            EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[1][number] => "777-7777777"
            EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[]          => [{"number": "555-555...}, { "number": "777.....}]
            EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[0]         => [{"number": "555-555...}]

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

        # By default we want to return a single value, which is the first item in the array
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
    kms_cache_file_name = 'ksm_cache.bin'

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
