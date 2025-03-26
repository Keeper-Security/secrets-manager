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
import uuid

from keeper_secrets_manager_core.storage import KeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys

from .utils import decrypt_buffer, encrypt_buffer
from .oci_kms_client import OciKmsClient
from .oci_session_config import OCISessionConfig
from oci.key_management import KmsCryptoClient,KmsManagementClient
from oci.key_management.models import KeyShape

default_logger_name = "ksm"
class OracleKeyValueStorage(KeyValueStorage):
    
    default_config_file_location: str = "client-config.json"
    crypto_client: KmsCryptoClient
    management_client : KmsManagementClient
    key_id: str
    key_version_id: str | None
    config: dict[str, str] = {}
    last_saved_config_hash: str
    logger: Logger
    config_file_location: str
    
    
    def __init__(self, key_id: str,
    key_version: str | None,
    config_file_location: str | None,
    oci_session_config: OCISessionConfig,
    logger: Logger | None):
        self.config_file_location = config_file_location or os.getenv('KSM_CONFIG_FILE') or self.default_config_file_location
        
        self.key_id = key_id
        self.key_version_id = key_version
        self.set_logger(logger)
        
        self.crypto_client =  OciKmsClient(oci_session_config).get_crypto_client()
        self.management_client = OciKmsClient(oci_session_config).get_management_client()
        
        self.last_saved_config_hash = ""
        self.get_key_details()
        self.load_config()
        
        self.logger.info(f"OracleKeyValueStorage initialized and loaded config from file {self.config_file_location}")
        
    def set_logger(self, logger: Logger|None):
        self.logger = logger if logger is not None else logging.getLogger(default_logger_name)
            
  
    def create_config_file_if_missing(self):
        try:
            # Check if the config file already exists
            if not os.path.exists(self.config_file_location):
                # Ensure the directory structure exists
                dir_path = os.path.dirname(self.config_file_location)
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path, exist_ok=True)

                # Encrypt an empty configuration and write to the file
                empty_config = "{}"
                blob = self.crypto_client.encrypt_buffer(
                    key_id=self.key_id,
                    message=empty_config,
                    crypto_client=self.crypto_client,
                    key_version_id=self.key_version_id,
                    is_asymmetric=self.is_asymmetric
                )
                with open(self.config_file_location, 'wb') as config_file:
                    config_file.write(blob)
                self.logger.info(f"Config file created at: {self.config_file_location}")
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
            # Decrypt the file contents
            plaintext = decrypt_buffer(
                key_id=self.key_id,
                ciphertext=ciphertext,
                crypto_client=self.crypto_client,
                key_version_id=self.key_version_id,
                is_asymmetric=self.is_asymmetric
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
    
    def __save_config(self, updated_config: dict[str, str] = {}, force: bool = False) -> None:
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
            blob = encrypt_buffer(
                key_id=self.key_id,
                message=stringified_value,
                crypto_client=self.crypto_client,
                key_version_id=self.key_version_id,
                is_asymmetric=self.is_asymmetric
            )
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
                config_json = decrypt_buffer(
                    key_id=self.key_id,
                    ciphertext=contents,
                    crypto_client=self.crypto_client,
                    key_version_id=self.key_version_id,
                    is_asymmetric=self.is_asymmetric
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
        
    def change_key(self, new_key_id: str, new_key_version_id: str=None) -> bool:
        old_key_id = self.key_id
        old_key_version_id = self.key_version_id
        old_crypto_client = self.crypto_client
        old_management_client = self.management_client

        try:
            # Update the key and reinitialize the CryptographyClient
            config = self.config
            if not config:
                self.load_config()
            self.key_id = new_key_id
            self.key_version_id = new_key_version_id
            self.get_key_details()
            self.__save_config({}, force=True)
        except Exception as error:
            # Restore the previous key and crypto client if the operation fails
            self.key_id = old_key_id
            self.key_version_id = old_key_version_id
            self.crypto_client = old_crypto_client
            self.management_client = old_management_client
            self.get_key_details()
            self.logger.error(
                f"Failed to change the key to '{new_key_id}' for config '{self.config_file_location}': {error}"
            )
            raise Exception(f"Failed to change the key for {self.config_file_location}")

        return True
    
    def get_key_details(self):
        
        opc_request_id = uuid.uuid4().hex.upper()
        
        key_details = self.management_client.get_key(key_id=self.key_id, opc_request_id=opc_request_id)
        
        algorithm = key_details.data.key_shape.algorithm
        
        if algorithm == KeyShape.ALGORITHM_RSA:
            self.is_asymmetric = True
        elif algorithm == KeyShape.ALGORITHM_AES:
            self.is_asymmetric = False
        else:
            raise Exception(f"Unsupported key algorithm for the given key: {algorithm}")
        
        
    
    def read_storage(self) -> dict[str, str]:
        if not self.config:
            self.load_config()
        return self.config
    
    def save_storage(self, updated_config: dict[str, str]) -> None:
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