import hashlib
import logging
import os

import requests
from requests import HTTPError

from keeper_globals import keeper_server_public_key_raw_string, keeper_commander_sm_client_id
from keepercommandersm import utils, helpers
from keepercommandersm.configkeys import ConfigKeys
from keepercommandersm.dto.dtos import Folder, Record
from keepercommandersm.exceptions import KeeperError, KeeperAccessDenied
from keepercommandersm.storage import FileKeyValueStorage, KeyValueStorage
from keepercommandersm.utils import bytes_to_url_safe_str, base64_to_bytes, sign, \
    extract_public_key_bytes, dict_to_json, url_safe_str_to_bytes, encrypt_aes, der_base64_private_key_to_private_key, \
    string_to_bytes, decrypt_aes, byte_to_string, json_to_dict, \
    public_encrypt, generate_private_key_der


class Commander:

    secret_key = None
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
    def init():

        Commander._init_logger()

        if not Commander.config:
            local_config = FileKeyValueStorage()    # TODO: Use In-Memory
        else:
            local_config = Commander.config

        existing_secret_key = Commander.load_secret_key(local_config)
        existing_secret_key_hash = bytes_to_url_safe_str(hashlib.sha256(url_safe_str_to_bytes(existing_secret_key)).digest())


        client_id = local_config.get(ConfigKeys.KEY_CLIENT_ID)
        private_key = local_config.get(ConfigKeys.KEY_PRIVATE_KEY)

        if not existing_secret_key_hash:
            # Secret key was not supplied (Probably already bound and private key and client id are present?)
            if not private_key or not client_id:
                # Instruct user how to bound using commander or web ui
                raise Exception("Not bound")

        elif existing_secret_key_hash == client_id:
            # Already bound
            logging.debug("Already bound")
        else:
            local_config.delete(ConfigKeys.KEY_CLIENT_ID)
            local_config.delete(ConfigKeys.KEY_PRIVATE_KEY)
            local_config.delete(ConfigKeys.KEY_MASTER_KEY)

            local_config.set(ConfigKeys.KEY_SECRET_KEY, existing_secret_key)
            local_config.set(ConfigKeys.KEY_CLIENT_ID, existing_secret_key_hash )

        if not Commander.verify_ssl_certs:
            logging.warning("WARNING: Running without SSL cert verification. "
                            "Execute 'Commander.verify_ssl_certs = True' to enable verification.")

        Commander.config = local_config

    @staticmethod
    def check_secret_key_against_current_client_id(current_client_id, secret_key):

        current_client_id_hash_str = bytes_to_url_safe_str(hashlib.sha256(url_safe_str_to_bytes(current_client_id)).digest())


    @staticmethod
    def load_secret_key(local_config):

        """Returns client_id from the environment variable, config file, or in the code"""

        # Case 1: Environment Variable
        env_secret_key = os.getenv('KEEPER_SECRET_KEY')

        current_secret_key = None

        if env_secret_key:
            current_secret_key= env_secret_key


        # Case 2: Code
        if not current_secret_key:
            code_secret_key = Commander.secret_key

            if code_secret_key:
                current_secret_key = code_secret_key

        # Case 3: Config storage
        if not current_secret_key:
            config_secret_key = local_config.get(ConfigKeys.KEY_SECRET_KEY)

            if config_secret_key:
                current_secret_key = config_secret_key

        return current_secret_key

    @staticmethod
    def generate_transmission_key(key_number=1):
        transmission_key = utils.generate_random_bytes(32)

        server_public_raw_key_bytes = url_safe_str_to_bytes(keeper_server_public_key_raw_string)

        encrypted_key = public_encrypt(transmission_key, server_public_raw_key_bytes)

        return {
            'publicKeyId': key_number,
            'key': transmission_key,
            'encryptedKey': encrypted_key
        }

    @staticmethod
    def prepare_context(config_storage):

        transmission_key = Commander.generate_transmission_key()

        client_id = config_storage.get(ConfigKeys.KEY_CLIENT_ID)

        if not client_id:
            raise Exception("Client ID is missing from the configuration")

        client_id_bytes = base64_to_bytes(client_id)

        # SECRET KEY

        is_bound = False
        master_key_str = config_storage.get(ConfigKeys.KEY_MASTER_KEY)

        if master_key_str:
            secret_key = base64_to_bytes(master_key_str)
            is_bound = True

        else:
            secret_key_str = config_storage.get(ConfigKeys.KEY_SECRET_KEY)

            if secret_key_str:
                secret_key = base64_to_bytes(secret_key_str)
            else:
                raise Exception("No decrypt keys are present")


        # PRIVATE KEY

        private_key_str = config_storage.get(ConfigKeys.KEY_PRIVATE_KEY)

        if private_key_str:
            private_key_der = base64_to_bytes(private_key_str)
        else:
            private_key_der = generate_private_key_der()
            config_storage.set(ConfigKeys.KEY_PRIVATE_KEY, bytes_to_url_safe_str(private_key_der))


        return {
            'transmissionKey': transmission_key,
            'clientId': client_id_bytes,
            'secretKey': secret_key,
            'isBound': is_bound,
            'privateKey': private_key_der
        }

    @staticmethod
    def encrypt_and_sign(context, payload):

        if isinstance(payload, str):
            payload_bytes = string_to_bytes(payload)
        elif isinstance(payload, dict):
            payload_json_str = dict_to_json(payload)
            payload_bytes = string_to_bytes(payload_json_str)
        else:
            payload_bytes = payload

        encrypted_payload = encrypt_aes(payload_bytes, context.get('transmissionKey').get('key'))

        encrypted_key = context.get('transmissionKey').get('encryptedKey')
        signature_base = encrypted_key + encrypted_payload
        signature = sign(signature_base, der_base64_private_key_to_private_key(context.get('privateKey')))

        return {
            'payload':  encrypted_payload,
            'signature': signature
        }

    @staticmethod
    def prepare_payload(context):

        payload_data = {
            'clientVersion': keeper_commander_sm_client_id,
            'clientId': bytes_to_url_safe_str(context['clientId']) + "="
        }

        if not context.get('isBound'):

            public_key_bytes = extract_public_key_bytes(context.get('privateKey'))
            public_key_base64 = bytes_to_url_safe_str(public_key_bytes)
            payload_data['publicKey'] = public_key_base64 + "="

        return Commander.encrypt_and_sign(context, payload_data)

    @staticmethod
    def prepare_update_payload(context, record):

        payload = {
            'clientVersion': keeper_commander_sm_client_id,
            'clientId': bytes_to_url_safe_str(context.get('clientId')) + "="
        }

        if not context.get('secretKey'):   # BAT
            raise KeeperError("To save, client must be authenticated by device token only")

        payload['recordUid'] = record.uid

        raw_json_bytes = string_to_bytes(record.raw_json) # TODO: This is where we need to get JSON of the updated Record
        encrypted_raw_json_bytes = encrypt_aes(raw_json_bytes, record.record_key_bytes)
        encrypted_raw_json_bytes_str = bytes_to_url_safe_str(encrypted_raw_json_bytes)
        payload['data'] = encrypted_raw_json_bytes_str

        return Commander.encrypt_and_sign(context, payload)

    @staticmethod
    def fetch():

        Commander.init()

        config = Commander.config
        context = Commander.prepare_context(config)
        payload = Commander.prepare_payload(context)

        payload_data = payload['payload']
        signature = payload['signature']

        request_headers = {}
        request_headers['Content-Type'] = 'application/octet-stream'
        request_headers['Content-Length'] = str(len(payload_data))
        request_headers['PublicKeyId'] = str(context.get('transmissionKey').get('publicKeyId'))
        request_headers['TransmissionKey'] = bytes_to_url_safe_str(context.get('transmissionKey').get('encryptedKey'))
        request_headers['Authorization'] = 'Signature %s' % bytes_to_url_safe_str(signature)

        keeper_server = helpers.get_server(Commander.server, config)

        rs = requests.post(
            'https://%s/api/rest/sm/v1/get_secret' % keeper_server,
            headers=request_headers,
            data=payload_data,
            verify=Commander.verify_ssl_certs
        )

        if not rs.ok:
            if rs.status_code == 403:

                logging.error("Error: " + str(rs.reason) + " (http error code: " + str(rs.status_code) + ")")
                raise KeeperAccessDenied("Access denied. One-Time Token cannot be reused.")
            else:
                resp_dict = json_to_dict(rs.text)

                logging.error("Error: " + str(rs.reason) + " (http error code: " + str(rs.status_code) + ", raw: %s)" % resp_dict)

                raise HTTPError()

        decrypted_response_bytes = decrypt_aes(rs.content, context.get('transmissionKey').get('key'))
        decrypted_response_str = byte_to_string(decrypted_response_bytes)
        decrypted_response_dict = json_to_dict(decrypted_response_str)

        records = []

        just_bound = False

        if decrypted_response_dict.get('encryptedMasterKey'):
            just_bound = True

            encrypted_master_key = url_safe_str_to_bytes(decrypted_response_dict.get('encryptedMasterKey'))
            secret_key = decrypt_aes(encrypted_master_key, context.get('secretKey'))
            Commander.config.set(ConfigKeys.KEY_MASTER_KEY, bytes_to_url_safe_str(secret_key))
        else:
            secret_key = context.get('secretKey')


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
    def get_all():

        records_resp = Commander.fetch()

        just_bound = records_resp.get('justBound')

        if just_bound:
            records_resp = Commander.fetch()

        records = records_resp.get('records') or []

        return records

    @staticmethod
    def save(record):
        """
        Create new or update a record
        """

        logging.info("Updating record uid: %s" % record.uid)

        config = Commander.config

        context = Commander.prepare_context(config)

        payload_and_signature = Commander.prepare_update_payload(context, record)

        payload_data = payload_and_signature.get('payload')
        signature = payload_and_signature.get('signature')

        keeper_server = helpers.get_server(Commander.server, config)

        request_headers = {}
        request_headers['PublicKeyId'] = str(context.get('transmissionKey').get('publicKeyId'))
        request_headers['TransmissionKey'] = bytes_to_url_safe_str(context.get('transmissionKey').get('encryptedKey'))
        request_headers['Authorization'] = 'Signature %s' % bytes_to_url_safe_str(signature)

        rs = requests.post(
            'https://%s/api/rest/sm/v1/update_secret' % keeper_server,
            headers=request_headers,
            data=payload_data,
            verify=Commander.verify_ssl_certs
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
