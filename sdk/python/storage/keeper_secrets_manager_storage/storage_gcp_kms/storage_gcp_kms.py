#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com

from logging import Logger
import logging
import os
import hashlib
import json

from typing import Optional,Dict

from keeper_secrets_manager_core.storage import KeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys

from .constants import SUPPORTED_KEY_PURPOSE, KeyPurpose
from .utils import decrypt_buffer, encrypt_buffer
from .util_options import KMSClient
from .kms_client import GCPKMSClientConfig
from .kms_key_config import GCPKeyConfig


default_logger_name = "ksm"
class GCPKeyValueStorage(KeyValueStorage):
    
    default_config_file_location: str = "client-config.json"
    crypto_client: KMSClient
    config: Dict[str, str] = {}
    last_saved_config_hash: str
    logger: Logger
    gcp_key_config: GCPKeyConfig
    config_file_location: str
    gcp_session_config: GCPKMSClientConfig
    is_asymmetric: bool = False
    key_purpose_details: str
    
    def __init__(self, key_vault_config_file_location: str , gcp_key_config: GCPKeyConfig, gcp_session_config: GCPKMSClientConfig, logger: Logger = None):
        self.config_file_location = os.path.abspath(key_vault_config_file_location) or os.getenv('KSM_CONFIG_FILE') or os.path.abspath(self.default_config_file_location)
        self.set_logger(logger)
        
        self.gcp_session_config = gcp_session_config
        self.gcp_key_config = gcp_key_config
        self.crypto_client = self.gcp_session_config.get_crypto_client()
        
        self.last_saved_config_hash = ""
        self.get_key_details()
        self.load_config()
        
        self.logger.info(f"GCPKeyValueStorage initialized and loaded config from file {self.config_file_location}")
        
    def set_logger(self, logger: Optional[Logger]):
        if logger is not None:
            self.logger = logger
        else:
            self.logger = logging.getLogger(default_logger_name)
            
            
    def get_key_details(self):
        try:
            input = {
                "name": self.gcp_key_config.to_key_name(),
            }
            key = self.crypto_client.get_crypto_key(input)
            self.key_purpose_details = key.purpose
            self.encryption_algorithm = key.version_template.algorithm
            if self.key_purpose_details not in SUPPORTED_KEY_PURPOSE:
                self.logger.error("Unsupported Key Spec for GCP KMS Storage")
                raise Exception("Unsupported Key Spec for GCP KMS Storage")

            if self.key_purpose_details == KeyPurpose.ASYMMETRIC_DECRYPT:
                self.is_asymmetric = True
            else:
                self.is_asymmetric = False

        except Exception as err:
            self.logger.error(f"Failed to get key details: {err}")
            
            
    def create_config_file_if_missing(self):
        try:
            self.logger.info(f"config file path {self.config_file_location}")
            # Check if the config file already exists
            if not os.path.exists(self.config_file_location):
                # Ensure the directory structure exists
                dir_path = os.path.dirname(self.config_file_location)
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path, exist_ok=True)
                with open(self.config_file_location, 'wb') as config_file:
                    config_file.write(b"{}")
                    self.logger.info(f"Config file created at: {self.config_file_location}")
                token=None
                if self.key_purpose_details == KeyPurpose.RAW_ENCRYPT_DECRYPT:
                    token = self.gcp_session_config.getToken()
                # Encrypt an empty configuration and write to the file
                empty_config = "{}"
                blob = encrypt_buffer(
                    is_asymmetric=self.is_asymmetric,
                    message=empty_config,
                    crypto_client=self.crypto_client,
                    key_properties=self.gcp_key_config,
                    encryption_algorithm=self.encryption_algorithm,
                    token=token,
                    logger = self.logger
                )
                if len(blob) != 0:
                    with open(self.config_file_location, 'wb') as config_file:
                        config_file.write(blob)
            else:
                self.logger.info(f"Config file already exists at: {self.config_file_location}")
        except Exception as err:
            self.logger.error(f"Error creating config file: {err}")
            
    def decrypt_config(self, autosave: bool = True) -> str:
        ciphertext : bytes = bytes()
        plaintext : str= ""

        try:
            # Read the config file
            with open(self.config_file_location, 'rb') as config_file:
                ciphertext = config_file.read()
            if len(ciphertext) == 0:
                self.logger.warning(f"Empty config file {self.config_file_location}")
                return ""
        except Exception as err:
            self.logger.error(f"Failed to load config file {self.config_file_location}: {err}")
            raise Exception(f"Failed to load config file {self.config_file_location}")

        try:
            token=None
            if self.key_purpose_details == KeyPurpose.RAW_ENCRYPT_DECRYPT:
                token = self.gcp_session_config.getToken()
            # Decrypt the file contents
            plaintext = decrypt_buffer(
                is_asymmetric=self.is_asymmetric,
                ciphertext=ciphertext,
                crypto_client=self.crypto_client,
                key_properties=self.gcp_key_config,
                token=token,
                logger = self.logger
            )
            if len(plaintext) == 0:
                self.logger.error(f"Failed to decrypt config file {self.config_file_location}")
            elif autosave:
                # Optionally autosave the decrypted content
                with open(self.config_file_location, 'w') as config_file:
                    config_file.write(plaintext)
        except Exception as err:
            self.logger.error(f"Failed to write decrypted config file {self.config_file_location}: {err}")
            raise Exception(f"Failed to write decrypted config file {self.config_file_location}")

        return plaintext
    
    def __save_config(self, updated_config: Dict[str, str] = {}, force: bool = False) -> None:
        try:
            # Retrieve current config
            config = self.config or {}
            config_json = json.dumps(config, sort_keys=True, indent=4)
            config_hash = hashlib.md5(config_json.encode()).hexdigest()

            # Compare updated_config hash with current config hash
            if updated_config:
                updated_config_json = json.dumps(updated_config, sort_keys=True, indent=4)
                updated_config_hash = hashlib.md5(updated_config_json.encode()).hexdigest()

                if updated_config_hash != config_hash:
                    config_hash = updated_config_hash
                    config_json = updated_config_json
                    self.config = dict(updated_config)  # Update the current config

            # Check if saving is necessary
            if not force and config_hash == self.last_saved_config_hash:
                self.logger.warning("Skipped config JSON save. No changes detected.")
                return

            # Ensure the config file exists
            self.create_config_file_if_missing()

            # Encrypt the config JSON and write to the file
            stringified_value = json.dumps(self.config, sort_keys=True, indent=4)
            token=None
            if self.key_purpose_details == KeyPurpose.RAW_ENCRYPT_DECRYPT:
                token = self.gcp_session_config.getToken()
            blob = encrypt_buffer(
                is_asymmetric=self.is_asymmetric,
                message=stringified_value,
                crypto_client=self.crypto_client,
                key_properties=self.gcp_key_config,
                encryption_algorithm=self.encryption_algorithm,
                token=token,
                logger = self.logger
            )
            if len(blob)!=0:
                with open(self.config_file_location, 'wb') as config_file:
                    config_file.write(blob)

            # Update the last saved config hash
            self.last_saved_config_hash = config_hash

        except Exception as err:
            self.logger.error(f"Error saving config: {err}")
            
    def load_config(self) -> None:
        self.create_config_file_if_missing()

        try:
            # Read the config file
            contents: bytes = b""
            try:
                with open(self.config_file_location, 'rb') as config_file:
                    contents = config_file.read()
                self.logger.info(f"Loaded config file {self.config_file_location}")
            except Exception as err:
                self.logger.error(f"Failed to load config file {self.config_file_location}: {err}")
                raise Exception(f"Failed to load config file {self.config_file_location}")

            if len(contents) == 0:
                self.logger.warning(f"Empty config file {self.config_file_location}")
                contents = b"{}"

            # Check if the content is plain JSON
            config = None
            json_error = None
            decryption_error = False
            try:
                config_data = contents.decode()
                config = json.loads(config_data)
                # Encrypt and save the config if it's plain JSON
                if config:
                    self.config = config
                    self.__save_config(config)
                    self.last_saved_config_hash = hashlib.md5(
                        json.dumps(config, sort_keys=True, indent=4).encode()
                    ).hexdigest()
            except Exception as err:
                json_error = err

            if json_error:
                token=None
                if self.key_purpose_details == KeyPurpose.RAW_ENCRYPT_DECRYPT:
                    token = self.gcp_session_config.getToken()
                config_json = decrypt_buffer(
                    is_asymmetric=self.is_asymmetric,
                    ciphertext=contents,
                    crypto_client=self.crypto_client,
                    key_properties=self.gcp_key_config,
                    token=token,
                    logger= self.logger
                )
                try:
                    config = json.loads(config_json)
                    self.config = config or {}
                    self.last_saved_config_hash = hashlib.md5(
                        json.dumps(config, sort_keys=True, indent=4).encode()
                    ).hexdigest()
                except Exception as err:
                    decryption_error = True
                    self.logger.error(f"Failed to parse decrypted config file: {err}")
                    raise Exception(f"Failed to parse decrypted config file {self.config_file_location}")

            if json_error and decryption_error:
                self.logger.info(f"Config file is not a valid JSON file: {json_error}")
                raise Exception(f"{self.config_file_location} may contain JSON format problems")

        except Exception as err:
            self.logger.error(f"Error loading config: {err}")
            raise err
        
    def change_key(self, new_gcp_key_config: GCPKeyConfig) -> bool:
        old_key_configuration = self.gcp_key_config
        old_crypto_client = self.crypto_client

        try:
            # Update the key and reinitialize the CryptographyClient
            config = self.config
            if not config:
                self.load_config()
            self.gcp_key_config = new_gcp_key_config
            self.get_key_details()
            self.__save_config({}, force=True)
        except Exception as error:
            # Restore the previous key and crypto client if the operation fails
            self.gcp_key_config = old_key_configuration
            self.crypto_client = old_crypto_client
            self.logger.error(
                f"Failed to change the key to '{new_gcp_key_config.to_key_name()}' for config '{self.config_file_location}': {error}"
            )
            raise Exception(f"Failed to change the key for {self.config_file_location}")

        return True
    
    def read_storage(self) -> Dict[str, str]:
        if not self.config:
            self.load_config()
        return self.config
    
    def save_storage(self, updated_config: Dict[str, str]) -> None:
        self.__save_config(updated_config)
        
    def get(self, key: ConfigKeys) -> str:
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
            self.logger.debug("Removed key %s" % kv)
        else:
           self.logger.debug("No key %s was found in config" % kv)

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