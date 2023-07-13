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
import errno
import hashlib
import json
import logging
import os

from json import JSONDecodeError
from keeper_secrets_manager_core.helpers import is_json

from keeper_secrets_manager_core.storage import KeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.utils import ENCODING

logger = logging.getLogger(logger_name)

try:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    from azure.keyvault.keys.crypto import CryptographyClient, KeyWrapAlgorithm
except ImportError as ie:
    logger.error("Missing Azure dependencies."
        " To install missing packages run: \r\n"
        "pip3 install azure-identity azure-keyvault-keys\r\n")
    raise Exception("Missing import dependencies: azure-identity azure-keyvault-keys")

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes
except ImportError as ie:
    logger.error("Missing Cryptodome dependency."
        " To install missing package run: \r\n"
        "pip3 install pycryptodomex\r\n")
    raise Exception("Missing import dependencies: pycryptodomex")

BLOB_HEADER = b"\xff\xff" # Encrypted BLOB Header: U+FFFF is a noncharacter

# Usage:
# from keeper_secrets_manager_core import SecretsManager
# from keeper_secrets_manager_storage.storage_azure_keyvault import AzureKeyValueStorage
# # key_id may include a version (in case the key is auto rotated)
# # key_id = 'https://ksmvault.vault.azure.net/keys/ksm2/fe4fdcab688c479a9aa80f01ffeac26'
# key_id = 'https://ksmvault.vault.azure.net/keys/ksm2'
# config = AzureKeyValueStorage(key_id, 'client-config.json') # auto encrypt
# secrets_manager = SecretsManager(config=config)
# all_records = secrets_manager.get_secrets()

class AzureSessionConfig():
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret


class AzureKeyValueStorage(KeyValueStorage):
    """Azure encrypted key-value storage"""

    default_config_file_location = "client-config.json"

    def __init__(self, key_id: str, config_file_location: str = "", az_session_config: AzureSessionConfig | None = None):
        """Initilaizes AzureKeyValueStorage

        key_id URI of the master key - if missing read from env KSM_AZ_KEY_ID
        key_id URI may also include version in case key has auto rotate enabled
        ex. key_id = "https://<your vault>.vault.azure.net/keys/<key name>/fe4fdcab688c479a9aa80f01ffeac26"
        The master key needs WrapKey, UnwrapKey privileges

        config_file_location provides custom config file location - if missing read from env KSM_CONFIG_FILE
        az_session_config optional az session config - if missing use default env variables
        https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential
        """

        self.default_config_file_location = config_file_location if config_file_location else os.environ.get("KSM_CONFIG_FILE",
            AzureKeyValueStorage.default_config_file_location)
        self.key_id = key_id if key_id else os.environ.get("KSM_AZ_KEY_ID", "") # Master Key ID

        has_az_session_config = (az_session_config
            and az_session_config.tenant_id
            and az_session_config.client_id
            and az_session_config.client_secret)

        if has_az_session_config:
            self.az_credential = ClientSecretCredential(
                tenant_id=az_session_config.tenant_id,
                client_id=az_session_config.client_id,
                client_secret=az_session_config.client_secret)
        else:
            self.az_credential = DefaultAzureCredential() # use default session/credentials

        self.crypto_client = CryptographyClient(self.key_id, credential=self.az_credential)

        self.last_saved_config_hash = ""
        self.config = {}
        self.__load_config()

    # Azure keyvault supports symmetric keys on Managed HSM only
    # generate and wrap temp AES (GCM) 256-bit keys
    def __encrypt_buffer(self, message: str) -> bytes:
        try:
            key = get_random_bytes(32)
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(message.encode())
            # response = self.crypto_client.encrypt(EncryptionAlgorithm.a256_gcm, message.encode()) # HSM Only
            try:
                response = self.crypto_client.wrap_key(KeyWrapAlgorithm.rsa_oaep, key)
            except Exception as err:
                logger.error("Azure crypto client failed to wrap key. %s", str(err))
                return b""

            blob = bytearray(BLOB_HEADER)
            for x in (response.encrypted_key, cipher.nonce, tag, ciphertext):
                blob.extend(len(x).to_bytes(2, byteorder='big'))
                blob.extend(x)
            return blob
        except Exception as err:
            logger.error("Azure KeyVault Storage failed to encrypt. %s", str(err))
            return b""

    def __decrypt_buffer(self, ciphertext: bytes) -> str:
        try:
            # response = self.crypto_client.decrypt(EncryptionAlgorithm.rsa_oaep, ciphertext) # HSM Only
            buf = ciphertext[:2]
            if buf != BLOB_HEADER:
                return ""

            pos = 2
            encrypted_key, nonce, tag, encrypted_text = (b'', b'', b'', b'')
            for x in range (1,5):
                buf = ciphertext[pos:pos+2] # chunks are size prefixed
                pos += len(buf)
                if len(buf) == 2:
                    buflen = int.from_bytes(buf, byteorder='big')
                    buf = ciphertext[pos:pos+buflen]
                    pos += len(buf)
                    if len(buf) == buflen:
                        if x == 1: encrypted_key = buf
                        elif x == 2: nonce = buf
                        elif x == 3: tag = buf
                        elif x == 4: encrypted_text = buf
                        else: logger.error("Azure KeyVault decrypt buffer contains extra data.")

            try:
                response = self.crypto_client.unwrap_key(KeyWrapAlgorithm.rsa_oaep, encrypted_key)
                key = response.key
            except Exception as err:
                logger.error("Azure crypto client failed to unwrap key. %s", str(err))
                return b""
            cipher = AES.new(key, AES.MODE_GCM, nonce)
            data = cipher.decrypt_and_verify(encrypted_text, tag)
            plaintext = data.decode('utf8')
            return plaintext
        except Exception as err:
            logger.error("Azure KeyVault Storage failed to decrypt. %s", str(err))
            return ""

    def __load_config(self, module=0):
        self.create_config_file_if_missing()

        try:
            # load config file contents
            contents: bytes = bytes()
            try:
                with open(self.default_config_file_location, "rb") as fh:
                    contents = fh.read()
            except Exception as e:
                logger.error("Failed to load config file " + self.default_config_file_location + "\n" + str(e))
                raise Exception("Failed to load config file " + self.default_config_file_location)

            if len(contents) == 0:
                logger.warning("Empty config file " + self.default_config_file_location)

            # try to read plain JSON (unencrypted)
            config = None
            if is_json(contents):
                with open(self.default_config_file_location, "r", encoding=ENCODING) as fh:
                    try:
                        config_data = fh.read()
                        config = json.loads(config_data)
                    except UnicodeDecodeError:
                        logger.error("Config file is not utf-8 encoded.")
                        raise Exception("{} is not a utf-8 encoded file".format(self.default_config_file_location))
                    except JSONDecodeError as err:
                        # If the JSON file was not empty, it's a legit JSON error. Throw an exception.
                        if config_data is not None and config_data.strip() != "":
                            raise Exception("{} may contain JSON format problems or is not utf-8 encoded"
                                            ": {}".format(self.default_config_file_location, err))
                        # If it was an empty file, overwrite with the JSON config
                        logger.warning("Looks like config file is empty.")
                        config = {}
                        self.save_storage(config)
                    except Exception as err:
                        logger.error("Config JSON has problems: {}".format(err))
                        if "codec" in str(err):
                            raise Exception("{} is not a utf-8 encoded file.".format(self.default_config_file_location))
                        raise err

            if config:
                # detected plaintext JSON config -> encrypt
                self.config = config
                self.__save_config() # save encrypted
                self.last_saved_config_hash = hashlib.md5(json.dumps(config, indent=4, sort_keys=True).encode()).hexdigest()
            else:
                # Try to decrypt binary blob
                config_json = self.__decrypt_buffer(contents)
                try:
                    config = json.loads(config_json)
                    self.config = config
                    self.last_saved_config_hash = hashlib.md5(json.dumps(config, indent=4, sort_keys=True).encode()).hexdigest()
                except Exception as err:
                    logger.error("Config JSON has problems: {}".format(err))
                    raise err
        except IOError:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), self.default_config_file_location)

    def __save_config(self, updated_config:dict = {}, module=0, force=False):
        config = self.config if self.config else {}
        config_json:str = json.dumps(config, indent=4, sort_keys=True)
        config_hash = hashlib.md5(config_json.encode()).hexdigest()

        if updated_config:
            ucfg_json:str = json.dumps(updated_config, indent=4, sort_keys=True)
            ucfg_hash = hashlib.md5(ucfg_json.encode()).hexdigest()
            if ucfg_hash != config_hash:
                config_hash = ucfg_hash
                config_json = ucfg_json
                self.config = dict(updated_config)
                # self.last_saved_config_hash = config_hash # update after save - to allow for retries

        if not force and config_hash == self.last_saved_config_hash:
            logger.warning("Skipped config JSON save. No changes detected.")
            return

        self.create_config_file_if_missing()
        blob = self.__encrypt_buffer(config_json)
        with open(self.default_config_file_location, "wb") as write_file:
            write_file.write(blob)
        self.last_saved_config_hash = config_hash

    def decrypt_config(self, autosave: bool = True) -> str:
        ciphertext: bytes = bytes()
        plaintext: str = ""
        try:
            with open(self.default_config_file_location, "rb") as fh:
                ciphertext = fh.read()
            if len(ciphertext) == 0:
                logging.getLogger(logger_name).warning("Empty config file " + self.default_config_file_location)
                return ""
        except Exception as e:
            logging.getLogger(logger_name).error("Failed to load config file " + self.default_config_file_location)
            raise Exception("Failed to load config file " + self.default_config_file_location)

        try:
            plaintext = self.__decrypt_buffer(ciphertext)
            if len(plaintext) == 0:
                logging.getLogger(logger_name).error("Failed to decrypt config file " + self.default_config_file_location)
            elif autosave:
                with open(self.default_config_file_location, "w") as fh:
                    fh.write(plaintext)
        except Exception as err:
            logging.getLogger(logger_name).error("Failed to write decrypted config file " + self.default_config_file_location)
            raise Exception("Failed to write decrypted config file " + self.default_config_file_location)
        return plaintext

    def change_key(self, new_key_id: str) -> bool:
        old_key_id = self.key_id
        old_crypto_client = self.crypto_client
        try:
            self.key_id = new_key_id
            self.crypto_client = CryptographyClient(self.key_id, credential=self.az_credential)
            self.__save_config(force=True)
        except Exception as e:
            self.key_id = old_key_id
            self.crypto_client = old_crypto_client
            logging.getLogger(logger_name).error(f"Failed to change the key to '{new_key_id}' for config '{self.default_config_file_location}'")
            raise Exception("Failed to change the key for " + self.default_config_file_location)
        return True

    def read_storage(self):
        if not self.config:
            self.__load_config()
        return dict(self.config)

    def save_storage(self, updated_config):
        self.__save_config(updated_config)

    def get(self, key: ConfigKeys):
        config = self.read_storage()
        return config.get(key.value)

    def set(self, key: ConfigKeys, value):
        config = self.read_storage()
        config[key.value] = value
        self.save_storage(config)
        return config

    def delete(self, key: ConfigKeys):
        config = self.read_storage()

        kv = key.value
        if kv in config:
            del config[kv]
            logger.debug("Removed key %s" % kv)
        else:
           logger.debug("No key %s was found in config" % kv)

        self.save_storage(config)
        return config

    def delete_all(self):
        self.read_storage()
        self.config.clear()
        self.save_storage(self.config)
        return dict(self.config)

    def contains(self, key: ConfigKeys):
        config = self.read_storage()
        return key.value in config

    def create_config_file_if_missing(self):
        if not os.path.exists(self.default_config_file_location):
            with open(self.default_config_file_location, "wb") as fh:
                blob = self.__encrypt_buffer("{}")
                fh.write(blob)

    def is_empty(self):
        config = self.read_storage()
        return not config
