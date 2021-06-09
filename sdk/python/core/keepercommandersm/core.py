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

    client_key = None
    server = None
    verify_ssl_certs = True

    config: KeyValueStorage = None

    @staticmethod
    def _init_logger():
        # Configure logs

        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s | %(name)s | %(levelname)s | %(message)s'
        )

    @staticmethod
    def __init():

        Commander._init_logger()

        if not Commander.config:
            local_config = FileKeyValueStorage()    # TODO: Use In-Memory
        else:
            local_config = Commander.config

        existing_secret_key = Commander.load_secret_key(local_config)
        existing_secret_key_bytes = url_safe_str_to_bytes(existing_secret_key)
        existing_secret_key_hash = bytes_to_url_safe_str(hmac.digest(existing_secret_key_bytes, b'KEEPER_SECRETS_MANAGER_CLIENT_ID', 'sha512'))

        client_id = local_config.get(ConfigKeys.KEY_CLIENT_ID)


        if not existing_secret_key_hash:
            # Secret key was not supplied (Probably already bound and client id is present?)
            if not client_id:
                # Instruct user how to bound using commander or web ui
                raise Exception("Not bound")

        elif existing_secret_key_hash == client_id:
            # Already bound
            logging.debug("Already bound")
        else:
            local_config.delete(ConfigKeys.KEY_CLIENT_ID)
            local_config.delete(ConfigKeys.KEY_PRIVATE_KEY)
            local_config.delete(ConfigKeys.KEY_APP_KEY)

            local_config.set(ConfigKeys.KEY_CLIENT_KEY, existing_secret_key)
            local_config.set(ConfigKeys.KEY_CLIENT_ID, existing_secret_key_hash)

            private_key_str = local_config.get(ConfigKeys.KEY_PRIVATE_KEY)

            if not private_key_str:
                private_key_der = generate_private_key_der()
                local_config.set(ConfigKeys.KEY_PRIVATE_KEY, bytes_to_url_safe_str(private_key_der))

        if not Commander.verify_ssl_certs:
            logging.warning("WARNING: Running without SSL cert verification. "
                            "Execute 'Commander.verify_ssl_certs = True' to enable verification.")

        Commander.config = local_config

    @staticmethod
    def load_secret_key(local_config):

        """Returns client_id from the environment variable, config file, or in the code"""

        # Case 1: Environment Variable
        env_secret_key = os.getenv('KEEPER_SECRET_KEY')

        current_secret_key = None

        if env_secret_key:
            current_secret_key = env_secret_key
            logging.info("Secret key found in environment variable")

        # Case 2: Code
        if not current_secret_key:
            code_secret_key = Commander.client_key

            if code_secret_key:
                current_secret_key = code_secret_key
                logging.info("Secret key found in code")

        # Case 3: Config storage
        if not current_secret_key:
            config_secret_key = local_config.get(ConfigKeys.KEY_CLIENT_KEY)

            if config_secret_key:
                current_secret_key = config_secret_key
                logging.info("Secret key found in configuration file")

        # if not current_secret_key:

        return current_secret_key

    @staticmethod
    def generate_transmission_key(key_number=1):
        transmission_key = utils.generate_random_bytes(32)

        server_public_raw_key_bytes = url_safe_str_to_bytes(keeper_server_public_key_raw_string)

        encrypted_key = public_encrypt(transmission_key, server_public_raw_key_bytes)

        return TransmissionKey(key_number, transmission_key,  encrypted_key)

    @staticmethod
    def prepare_context(config_storage):

        transmission_key = Commander.generate_transmission_key()
        client_id = config_storage.get(ConfigKeys.KEY_CLIENT_ID)

        if not client_id:
            raise Exception("Client ID is missing from the configuration")

        client_id_bytes = base64_to_bytes(client_id)

        return Context(
                    transmission_key,
                    client_id_bytes
                )

    @staticmethod
    def encrypt_and_sign_payload(config_store, context, payload):

        if not (isinstance(payload, GetPayload) or isinstance(payload, UpdatePayload)):
            raise Exception('Unknown payload type "%s"' % payload.__class__.__name__)

        payload_json_str = dict_to_json(payload.__dict__)
        payload_bytes = string_to_bytes(payload_json_str)

        encrypted_payload = encrypt_aes(payload_bytes, context.transmissionKey.key)

        encrypted_key = context.transmissionKey.encryptedKey
        signature_base = encrypted_key + encrypted_payload

        pk = der_base64_private_key_to_private_key(config_store.get(ConfigKeys.KEY_PRIVATE_KEY))
        signature = sign(signature_base, pk)

        return {
            'payload':  encrypted_payload,
            'signature': signature
        }

    @staticmethod
    def prepare_get_payload(config_store, context, records_filter):

        payload = GetPayload()

        payload.clientVersion = keeper_commander_sm_client_id
        payload.clientId = bytes_to_url_safe_str(context.clientId) + "="

        app_key_str = config_store.get(ConfigKeys.KEY_APP_KEY)

        if not app_key_str:

            public_key_bytes = extract_public_key_bytes(config_store.get(ConfigKeys.KEY_PRIVATE_KEY))
            public_key_base64 = bytes_to_url_safe_str(public_key_bytes)
            payload.publicKey = public_key_base64 + "="     # passed once when binding

        if records_filter:
            payload.requestedRecords = records_filter

        return Commander.encrypt_and_sign_payload(config_store, context, payload)

    @staticmethod
    def prepare_update_payload(config_store, context, record):
        payload = UpdatePayload()

        payload.clientVersion = keeper_commander_sm_client_id
        payload.clientId = bytes_to_url_safe_str(context.clientId) + "="

        if not config_store.get(ConfigKeys.KEY_CLIENT_KEY):   # BAT
            raise KeeperError("To save and update, client must be authenticated by device token only")

        payload.recordUid = record.uid                       # for update, uid of the record

        raw_json_bytes = string_to_bytes(record.raw_json) # TODO: This is where we need to get JSON of the updated Record
        encrypted_raw_json_bytes = encrypt_aes(raw_json_bytes, record.record_key_bytes)
        encrypted_raw_json_bytes_str = bytes_to_url_safe_str(encrypted_raw_json_bytes)
        payload.data = encrypted_raw_json_bytes_str          # for create and update, the record data

        return Commander.encrypt_and_sign_payload(config_store, context, payload)

    @staticmethod
    def __post_query(path, transmission_key, payload_and_signature):

        keeper_server = helpers.get_server(Commander.server, Commander.config)

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
            verify=Commander.verify_ssl_certs
        )

        return rs

    @staticmethod
    def fetch(record_filter=None):

        Commander.__init()

        config = Commander.config
        context = Commander.prepare_context(config)
        payload_and_signature = Commander.prepare_get_payload(config, context, records_filter=record_filter)

        rs = Commander.__post_query(
            'get_secret',
            context.transmissionKey,
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
                    #     1. error: throttled, message: Due to repeated attempts, your request has been throttled. Try again in 2 minutes.
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
                #   - Error: invalid Invalid secrets manager payload
                raise KeeperError(rs.text)
            else:
                resp_dict = json_to_dict(rs.text)

                logging.error("Error: " + str(rs.reason) + " (http error code: " + str(rs.status_code) + ", raw: %s)" % resp_dict)

                raise HTTPError()

        decrypted_response_bytes = decrypt_aes(rs.content, context.transmissionKey.key)
        decrypted_response_str = bytes_to_string(decrypted_response_bytes)
        decrypted_response_dict = json_to_dict(decrypted_response_str)

        records = []

        just_bound = False

        if decrypted_response_dict.get('encryptedAppKey'):
            just_bound = True

            encrypted_master_key = url_safe_str_to_bytes(decrypted_response_dict.get('encryptedAppKey'))
            secret_key = decrypt_aes(encrypted_master_key, config.get(ConfigKeys.KEY_CLIENT_KEY))
            Commander.config.set(ConfigKeys.KEY_APP_KEY, bytes_to_url_safe_str(secret_key))
        else:
            secret_key = base64_to_bytes(config.get(ConfigKeys.KEY_APP_KEY))

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

    @staticmethod
    def get_secrets(uids=None):
        """
        Retrieve all records associated with the given application
        """
        records_resp = Commander.fetch(uids)

        just_bound = records_resp.get('justBound')

        if just_bound:
            records_resp = Commander.fetch(uids)

        # TODO: Erase client key because we are already bound

        records = records_resp.get('records') or []

        return records

    @staticmethod
    def save(record):
        """
        Save updated secret values
        """

        logging.info("Updating record uid: %s" % record.uid)

        config = Commander.config

        context = Commander.prepare_context(config)

        payload_and_signature = Commander.prepare_update_payload(config, context, record)

        rs = Commander.__post_query(
            'update_secret',
            context.transmissionKey,
            payload_and_signature
        )

        if not rs.ok:
            if rs.status_code == 403:

                logging.error("Error: " + str(rs.reason) + " (http error code: " + str(rs.status_code) + ")")
                return {}
            else:
                resp_dict = json_to_dict(rs.text)

                logging.error("Error: " + str(rs.reason) + " (http error code: " + str(rs.status_code) + ", raw: %s)" % resp_dict)

                raise HTTPError()
        else:
            return True
