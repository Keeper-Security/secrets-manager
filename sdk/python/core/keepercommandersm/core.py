import hmac
import logging
import os

import requests
from requests import HTTPError

from keepercommandersm import utils, helpers
from keepercommandersm.configkeys import ConfigKeys
from keepercommandersm.dto.dtos import Folder, Record
from keepercommandersm.dto.payload import GetPayload, UpdatePayload, Context, TransmissionKey
from keepercommandersm.exceptions import KeeperError, KeeperAccessDenied
from keepercommandersm.keeper_globals import keeper_server_public_key_raw_string, keeper_commander_sm_client_id
from keepercommandersm.storage import FileKeyValueStorage, KeyValueStorage
from keepercommandersm.utils import bytes_to_url_safe_str, base64_to_bytes, sign, \
    extract_public_key_bytes, dict_to_json, url_safe_str_to_bytes, encrypt_aes, der_base64_private_key_to_private_key, \
    string_to_bytes, decrypt_aes, bytes_to_string, json_to_dict, \
    public_encrypt, generate_private_key_der


class Commander:

    def __init__(self, client_key=None, server=None, verify_ssl_certs=True, config=None):

        self.client_key = client_key
        self.server = server

        # Accept the env var PYTHONHTTPSVERIFY. Modules like 'requests' already use it.
        self.verify_ssl_certs = bool(os.environ.get("PYTHONHTTPSVERIFY", verify_ssl_certs))

        if config is None:
            config = FileKeyValueStorage()

        # If the server or client key are set in the args, make sure they makes it's way into the config. The
        # will override what is already in the config if they exist.
        if client_key is not None:
            config.set(ConfigKeys.KEY_CLIENT_KEY, server)
        if server is not None:
            config.set(ConfigKeys.KEY_SERVER, server)

        self.config: KeyValueStorage = config

        self._init_logger()

        self._init()

    @staticmethod
    def _init_logger():
        # Configure logs

        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s | %(name)s | %(levelname)s | %(message)s'
        )

    def _init(self):

        existing_secret_key = self.load_secret_key()

        if existing_secret_key is None:
            raise ValueError("Cannot find the client key in the configuration file.")

        existing_secret_key_bytes = url_safe_str_to_bytes(existing_secret_key)
        existing_secret_key_hash = bytes_to_url_safe_str(hmac.digest(existing_secret_key_bytes,
                                                                     b'KEEPER_SECRETS_MANAGER_CLIENT_ID', 'sha512'))

        client_id = self.config.get(ConfigKeys.KEY_CLIENT_ID)

        if not existing_secret_key_hash:
            # Secret key was not supplied (Probably already bound and client id is present?)
            if not client_id:
                # Instruct user how to bound using commander or web ui
                raise Exception("Not bound")

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
                            "Execute 'Commander(..., verify_ssl_certs=True)' or 'PYTHONHTTPSVERIFY=TRUE' "
                            "to enable verification.")

    def load_secret_key(self):

        """Returns client_id from the environment variable, config file, or in the code"""

        # Case 1: Environment Variable
        env_secret_key = os.getenv('KEEPER_SECRET_KEY')

        current_secret_key = None

        if env_secret_key:
            current_secret_key = env_secret_key
            logging.info("Secret key found in environment variable")

        # Case 2: Code
        if not current_secret_key:
            code_secret_key = self.client_key

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
    def generate_transmission_key(key_number=1):
        transmission_key = utils.generate_random_bytes(32)

        server_public_raw_key_bytes = url_safe_str_to_bytes(keeper_server_public_key_raw_string)

        encrypted_key = public_encrypt(transmission_key, server_public_raw_key_bytes)

        return TransmissionKey(key_number, transmission_key, encrypted_key)

    def prepare_context(self):

        transmission_key = Commander.generate_transmission_key()
        client_id = self.config.get(ConfigKeys.KEY_CLIENT_ID)

        # While not use in the normal operations, it's used for mocking unit tests.
        secret_key = base64_to_bytes(self.config.get(ConfigKeys.KEY_APP_KEY))

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

        payload.clientVersion = keeper_commander_sm_client_id
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

        payload.clientVersion = keeper_commander_sm_client_id
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

        keeper_server = helpers.get_server(self.server, self.config)

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

    def fetch(self, record_filter=None):

        context = self.prepare_context()
        payload_and_signature = self.prepare_get_payload(context, records_filter=record_filter)

        rs = self._post_query(
            'get_secret',
            context,
            payload_and_signature
        )

        if not rs.ok:
            if rs.status_code == 403:
                response_dict = json_to_dict(rs.text)

                if response_dict.get('result_code') == 'invalid_client_version':
                    logging.error("Client version %s was not registered in the backend" % keeper_commander_sm_client_id)
                    raise KeeperError(response_dict.get('additional_info'))
                elif 'error' in response_dict:
                    # Errors:
                    #     1. error: throttled,     message: Due to repeated attempts, your request has been throttled. Try again in 2 minutes.
                    #     2. error: access_denied, message: Unable to validate application access
                    #     3. error: access_denied, message: Signature is invalid
                    error = ("Error: %s, message=%s" % (
                        response_dict.get('error'), response_dict.get('message'))) if 'error' in response_dict else None

                    raise KeeperError(error)
                else:
                    logging.error("Error code: %s, additional info: %s" % (
                        (response_dict.get('result_code') or response_dict.get('error')),
                        (response_dict.get('additional_info') or response_dict.get('message'))
                    )
                                  )
                    raise KeeperAccessDenied("Access denied. One-Time Token cannot be reused.")
            elif rs.status_code == 400:
                # Example errors:
                #   - error: invalid,     message Invalid secrets manager payload
                #   - error: bad_request, message: unable to decrypt the payload
                raise KeeperError(rs.text)
            else:
                resp_dict = json_to_dict(rs.text)

                logging.error(
                    "Error: " + str(rs.reason) + " (http error code: " + str(rs.status_code) + ", raw: %s)" % resp_dict)

                raise HTTPError()

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

        if records_resp:
            for r in records_resp:
                record = Record(r, secret_key)
                records.append(record)

        if folders_resp:
            for f in folders_resp:
                folder = Folder(f, secret_key)
                records.extend(folder.records)

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

        context = self.prepare_context()

        payload_and_signature = self.prepare_update_payload(context, record)

        rs = self._post_query(
            'update_secret',
            context,
            payload_and_signature
        )

        if not rs.ok:
            if rs.status_code == 403:
                logging.error("Error: {} (http error code: {})".format(rs.reason, rs.status_code))
                return {}
            else:
                resp_dict = json_to_dict(rs.text)
                logging.error("Error: {} (http error code: {}, row: {}".format(rs.reason, rs.status_code, resp_dict))
                raise HTTPError()
        else:
            return True
