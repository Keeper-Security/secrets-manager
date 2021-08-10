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

import requests
from requests import HTTPError

from keeper_secrets_manager_core import utils, helpers
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.dto.dtos import Folder, Record
from keeper_secrets_manager_core.dto.payload import GetPayload, UpdatePayload, Context, TransmissionKey
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.keeper_globals import keeper_secrets_manager_sdk_client_id, keeper_public_keys
from keeper_secrets_manager_core.storage import FileKeyValueStorage, KeyValueStorage
from keeper_secrets_manager_core.utils import bytes_to_url_safe_str, base64_to_bytes, sign, \
    extract_public_key_bytes, dict_to_json, url_safe_str_to_bytes, encrypt_aes, der_base64_private_key_to_private_key, \
    string_to_bytes, decrypt_aes, bytes_to_string, json_to_dict, \
    public_encrypt, generate_private_key_der


class SecretsManager:

    notation_prefix = "keeper"
    log_level = "DEBUG"
    default_key_id = "7"

    def __init__(self, token=None, hostname=None, verify_ssl_certs=True, config=None, log_level=None):

        self.token = token
        self.hostname = hostname

        # Accept the env var KSM_SKIP_VERIFY. Modules like 'requests' already use it.
        self.verify_ssl_certs = verify_ssl_certs
        if os.environ.get("KSM_SKIP_VERIFY") is not None:
            # We need to flip the value of KSM_SKIP_VERIFY, if true, we want verify_ssl_certs to be false.
            self.verify_ssl_certs = not bool(strtobool(os.environ.get("KSM_SKIP_VERIFY")))

        if config is None:
            config = FileKeyValueStorage()

        # If the server or client key are set in the args, make sure they makes it's way into the config. The
        # will override what is already in the config if they exist.
        if token is not None:
            config.set(ConfigKeys.KEY_CLIENT_KEY, token)
        if hostname is not None:
            config.set(ConfigKeys.KEY_HOSTNAME, hostname)

        # Make sure our public key id is set and pointing an existing key.
        if config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID) is None:
            logging.debug("Setting public key id to the default: {}".format(SecretsManager.default_key_id))
            config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, SecretsManager.default_key_id)
        elif config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID) not in keeper_public_keys:
            logging.debug("Public key id {} does not exists, set to default : {}".format(
                config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID),
                SecretsManager.default_key_id))
            config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, SecretsManager.default_key_id)

        self.config: KeyValueStorage = config

        self._init_logger(log_level=log_level)

        self._init()

    @staticmethod
    def _init_logger(log_level=None):
        # Configure logs

        if log_level is None:
            log_level = SecretsManager.log_level

        valid_log_levels = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]
        if log_level not in valid_log_levels:
            raise ValueError("Log level {} is invalid. Valid values are: {}".format(log_level,
                                                                                    ", ".join(valid_log_levels)))

        # basicConfig will not clobber a user's logging configuration, even the log level
        # "This function does nothing if the root logger already has handlers configured, unless the keyword argument
        # force is set to True."
        logging.basicConfig(
            format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
            level=getattr(logging, log_level)
        )

    def _init(self):

        existing_secret_key = self.load_secret_key()

        if existing_secret_key is None:
            raise ValueError("Cannot find the client key in the configuration file.")

        existing_secret_key_bytes = url_safe_str_to_bytes(existing_secret_key)
        digest = 'sha512'
        existing_secret_key_hash = bytes_to_url_safe_str(hmac.new(existing_secret_key_bytes,
                                                                  b'KEEPER_SECRETS_MANAGER_CLIENT_ID',
                                                                  digest).digest())

        client_id = self.config.get(ConfigKeys.KEY_CLIENT_ID)

        if not existing_secret_key_hash:
            # Secret key was not supplied (Probably already bound and client id is present?)
            if not client_id:
                # Instruct user how to bound using commander or web ui
                raise Exception("Not bound")

        elif existing_secret_key_hash == client_id:
            # Already bound
            logging.debug("Already bound")
        else:
            self.config.delete(ConfigKeys.KEY_CLIENT_ID)
            self.config.delete(ConfigKeys.KEY_PRIVATE_KEY)
            self.config.delete(ConfigKeys.KEY_APP_KEY)

            self.config.set(ConfigKeys.KEY_CLIENT_KEY, existing_secret_key)
            self.config.set(ConfigKeys.KEY_CLIENT_ID, existing_secret_key_hash)

            private_key_str = self.config.get(ConfigKeys.KEY_PRIVATE_KEY)

            if not private_key_str:
                private_key_der = generate_private_key_der()
                self.config.set(ConfigKeys.KEY_PRIVATE_KEY, bytes_to_url_safe_str(private_key_der))

        if not self.verify_ssl_certs:
            logging.warning("WARNING: Running without SSL cert verification. "
                            "Execute 'SecretsManager(..., verify_ssl_certs=True)' or 'KSM_SKIP_VERIFY=FALSE' "
                            "to enable verification.")

    def load_secret_key(self):

        """Returns client_id from the environment variable, config file, or in the code"""

        # Case 1: Environment Variable
        env_secret_key = os.getenv('KSM_TOKEN')

        current_secret_key = None

        if env_secret_key:
            current_secret_key = env_secret_key
            logging.info("Secret key found in environment variable")

        # Case 2: Code
        if not current_secret_key:
            code_secret_key = self.token

            if code_secret_key:
                current_secret_key = code_secret_key
                logging.info("Secret key found in code")

        # Case 3: Config storage
        if not current_secret_key:
            config_secret_key = self.config.get(ConfigKeys.KEY_CLIENT_KEY)

            if config_secret_key:
                current_secret_key = config_secret_key
                logging.info("Secret key found in configuration file")

        return current_secret_key

    @staticmethod
    def generate_transmission_key(key_id):
        transmission_key = utils.generate_random_bytes(32)

        if key_id not in keeper_public_keys:
            ValueError("The public key id {} does not exist.".format(key_id))

        server_public_raw_key_bytes = url_safe_str_to_bytes(keeper_public_keys[key_id])

        encrypted_key = public_encrypt(transmission_key, server_public_raw_key_bytes)

        return TransmissionKey(key_id, transmission_key, encrypted_key)

    def prepare_context(self):

        # Get the index of the public get we need to use. If not set, set it the default and
        # save it back into the config
        key_id = self.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID)
        if key_id is None:
            key_id = SecretsManager.default_key_id
            self.config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, str(key_id))

        # Generate the transmission key using the public key at the key id index
        transmission_key = SecretsManager.generate_transmission_key(key_id)
        client_id = self.config.get(ConfigKeys.KEY_CLIENT_ID)
        secret_key = None

        # While not use in the normal operations, it's used for mocking unit tests.
        app_key = self.config.get(ConfigKeys.KEY_APP_KEY)
        if app_key is not None:
            secret_key = base64_to_bytes(app_key)

        if not client_id:
            raise Exception("Client ID is missing from the configuration")

        client_id_bytes = base64_to_bytes(client_id)

        return Context(
                    transmission_key,
                    client_id_bytes,
                    secret_key
                )

    def encrypt_and_sign_payload(self, context, payload):

        if not (isinstance(payload, GetPayload) or isinstance(payload, UpdatePayload)):
            raise Exception('Unknown payload type "%s"' % payload.__class__.__name__)

        payload_json_str = dict_to_json(payload.__dict__)
        payload_bytes = string_to_bytes(payload_json_str)

        encrypted_payload = encrypt_aes(payload_bytes, context.transmissionKey.key)

        encrypted_key = context.transmissionKey.encryptedKey
        signature_base = encrypted_key + encrypted_payload

        pk = der_base64_private_key_to_private_key(self.config.get(ConfigKeys.KEY_PRIVATE_KEY))
        signature = sign(signature_base, pk)

        return {
            'payload':  encrypted_payload,
            'signature': signature
        }

    def prepare_get_payload(self, context, records_filter):

        payload = GetPayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = bytes_to_url_safe_str(context.clientId) + "="

        app_key_str = self.config.get(ConfigKeys.KEY_APP_KEY)

        if not app_key_str:

            public_key_bytes = extract_public_key_bytes(self.config.get(ConfigKeys.KEY_PRIVATE_KEY))
            public_key_base64 = bytes_to_url_safe_str(public_key_bytes)
            # passed once when binding
            payload.publicKey = public_key_base64 + "="

        if records_filter:
            payload.requestedRecords = records_filter

        return self.encrypt_and_sign_payload(context, payload)

    def prepare_update_payload(self, context, record):
        payload = UpdatePayload()

        payload.clientVersion = keeper_secrets_manager_sdk_client_id
        payload.clientId = bytes_to_url_safe_str(context.clientId) + "="

        if not context.clientKey:
            raise KeeperError("To save and update, client must be authenticated by device token only")

        # for update, uid of the record
        payload.recordUid = record.uid

        # TODO: This is where we need to get JSON of the updated Record
        raw_json_bytes = string_to_bytes(record.raw_json)
        encrypted_raw_json_bytes = encrypt_aes(raw_json_bytes, record.record_key_bytes)
        encrypted_raw_json_bytes_str = bytes_to_url_safe_str(encrypted_raw_json_bytes)

        # for create and update, the record data
        payload.data = encrypted_raw_json_bytes_str

        return self.encrypt_and_sign_payload(context, payload)

    def _post_query(self, path, context, payload_and_signature):

        keeper_server = helpers.get_server(self.hostname, self.config)

        transmission_key = context.transmissionKey
        payload = payload_and_signature.get('payload')
        signature = payload_and_signature.get('signature')

        request_headers = {
            'Content-Type': 'application/octet-stream', 'Content-Length': str(len(payload)),
            'PublicKeyId': str(transmission_key.publicKeyId),
            'TransmissionKey': bytes_to_url_safe_str(transmission_key.encryptedKey),
            'Authorization': 'Signature %s' % bytes_to_url_safe_str(signature)
        }

        rs = requests.post(
            'https://%s/api/rest/sm/v1/%s' % (keeper_server, path),
            headers=request_headers,
            data=payload,
            verify=self.verify_ssl_certs
        )

        return rs

    def handler_http_error(self, rs):

        log_level = logging.ERROR
        try:
            # Decode the JSON content, throw exception if not JSON
            response_dict = json_to_dict(rs.text)
            if response_dict is None:
                raise json.JSONDecodeError("Not JSON", "NONE", 0)

            # Try to get the error from result_code, then from error.
            error = response_dict.get('result_code', response_dict.get('error'))

            if error == 'invalid_client_version':
                logging.error("Client version {} was not registered in the backend".format(
                    keeper_secrets_manager_sdk_client_id))
                msg = response_dict.get('additional_info')

            # The server wants us to use a different public key.
            elif error == 'key':
                key_id = response_dict.get("key_id")
                logging.info("Server has requested we use public key {}".format(key_id))

                if key_id is None:
                    raise ValueError("The public key is blank from the server")
                elif str(key_id) not in keeper_public_keys:
                    raise ValueError("The public key at {} does not exist in the SDK".format(key_id))

                self.config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID, str(key_id))

                # This is not an error, it's info. Make it so the 'finally' display info about the
                # key change.
                log_level = logging.INFO

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
            logging.log(log_level, "Error: {} (http error code {}): {}".format(
                rs.reason,
                rs.status_code,
                rs.text
            ))

        # This is a unknown error, not one of ours, just throw a HTTPError
        raise HTTPError(rs.text)

    def fetch(self, record_filter=None):

        while True:

            context = self.prepare_context()
            payload_and_signature = self.prepare_get_payload(context, records_filter=record_filter)

            rs = self._post_query(
                'get_secret',
                context,
                payload_and_signature
            )

            # If we are ok, then break out of the while loop
            if rs.ok:
                break

            # Handle the error. Handling will throw an exception if it doesn't want us to retry.
            self.handler_http_error(rs)

        decrypted_response_bytes = decrypt_aes(rs.content, context.transmissionKey.key)
        decrypted_response_str = bytes_to_string(decrypted_response_bytes)
        decrypted_response_dict = json_to_dict(decrypted_response_str)

        records = []

        just_bound = False

        if decrypted_response_dict.get('encryptedAppKey'):
            just_bound = True

            encrypted_master_key = url_safe_str_to_bytes(decrypted_response_dict.get('encryptedAppKey'))
            secret_key = decrypt_aes(encrypted_master_key, self.config.get(ConfigKeys.KEY_CLIENT_KEY))
            self.config.set(ConfigKeys.KEY_APP_KEY, bytes_to_url_safe_str(secret_key))
        else:
            secret_key = base64_to_bytes(self.config.get(ConfigKeys.KEY_APP_KEY))

        records_resp = decrypted_response_dict.get('records')
        folders_resp = decrypted_response_dict.get('folders')

        logging.debug("Individual record count: {}".format(len(records_resp or [])))
        logging.debug("Folder count: {}".format(len(folders_resp or [])))

        if records_resp:
            for r in records_resp:
                record = Record(r, secret_key)
                records.append(record)

        if folders_resp:
            for f in folders_resp:
                folder = Folder(f, secret_key)
                records.extend(folder.records)

        logging.debug("Total record count: {}".format(len(records)))

        return {
            'records': records,
            'justBound': just_bound
        }

    def get_secrets(self, uids=None):
        """
        Retrieve all records associated with the given application
        """
        records_resp = self.fetch(uids)

        just_bound = records_resp.get('justBound')

        if just_bound:
            records_resp = self.fetch(uids)

        # TODO: Erase client key because we are already bound

        records = records_resp.get('records') or []

        return records

    def save(self, record):
        """
        Save updated secret values
        """

        logging.info("Updating record uid: %s" % record.uid)

        while True:

            context = self.prepare_context()
            payload_and_signature = self.prepare_update_payload(context, record)

            rs = self._post_query(
                'update_secret',
                context,
                payload_and_signature
            )

            # If we are ok, then break out of the while loop
            if rs.ok:
                break

            # Handle the error. Handling will throw an exception if it doesn't want us to retry.
            self.handler_http_error(rs)

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
            (uid, file_type, key) = url.split('/')
        except Exception as _:
            raise ValueError("Could not parse the notation {}. Is it valid?".format(url))

        if uid is None:
            raise ValueError("UID is missing the in the keeper url.")
        if file_type is None:
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

        if file_type == "field":
            value = record.field(key, single=False)
        elif file_type == "custom_field":
            value = record.custom_field(key, single=False)
        elif file_type == "file":
            file = record.find_file_by_title(key)
            if file is None:
                raise FileNotFoundError("Cannot find the file {} in record {}.".format(key, uid))
            value = file.get_file_data()
        else:
            raise ValueError("Field type of {} is not value.".format(file_type))

        ret = value
        if return_single is True and type(value) is list:
            if len(value) == 0:
                return None
            try:
                ret = value[index]
                if dict_key is not None:
                    if dict_key not in ret:
                        raise ValueError("Cannot find the dictionary key {} in the valuye".format(dict_key))
                    ret = ret[dict_key]
            except IndexError:
                raise ValueError("The value at index {} does not exist for {}.".format(index, url))
        return ret
