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
import threading
import uuid

from keeper_secrets_manager_core.storage import KeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from typing import Optional, Dict

from .utils import decrypt_buffer, encrypt_buffer
from .oci_kms_client import OciKmsClient
from .oci_session_config import OCISessionConfig
from oci.key_management import KmsCryptoClient, KmsManagementClient
from oci.key_management.models import KeyShape

default_logger_name = "ksm"


class OracleKeyValueStorage(KeyValueStorage):

    default_config_file_location: str = "client-config.json"
    crypto_client: KmsCryptoClient
    management_client: KmsManagementClient
    key_id: str
    key_version_id: Optional[str]
    config: Optional[Dict[str, str]] = None
    last_saved_config_hash: str
    logger: Logger
    config_file_location: str
    is_asymmetric: bool = False
    _lock: threading.RLock

    def __init__(self, key_id: str,
                 key_version: Optional[str],
                 config_file_location: Optional[str],
                 oci_session_config: OCISessionConfig,
                 logger: Optional[Logger]):
        self.config_file_location = os.path.abspath(config_file_location) or os.getenv(
            'KSM_CONFIG_FILE') or os.path.abspath(self.default_config_file_location)

        self.key_id = key_id
        self.key_version_id = key_version
        self.set_logger(logger)

        oci_client = OciKmsClient(oci_session_config)
        self.crypto_client = oci_client.get_crypto_client()
        self.management_client = oci_client.get_management_client()

        self._lock = threading.RLock()
        self.last_saved_config_hash = ""
        self.get_key_details()
        self.load_config()

        self.logger.info(
            f"OracleKeyValueStorage initialized and loaded config from file {self.config_file_location}")

    def set_logger(self, logger: Optional[Logger]):
        self.logger = logger if logger is not None else logging.getLogger(
            default_logger_name)

    def get_key_details(self):
        try:
            opc_request_id = uuid.uuid4().hex.upper()
            key_details = self.management_client.get_key(
                key_id=self.key_id, opc_request_id=opc_request_id)
            algorithm = key_details.data.key_shape.algorithm

            if algorithm == KeyShape.ALGORITHM_RSA:
                self.is_asymmetric = True
            elif algorithm == KeyShape.ALGORITHM_AES:
                self.is_asymmetric = False
            else:
                raise Exception(
                    f"Unsupported key algorithm for the given key: {algorithm}")
        except Exception as err:
            self.logger.error(f"Failed to get key details: {err}")
            raise

    def create_config_file_if_missing(self):
        try:
            if os.path.exists(self.config_file_location):
                self.logger.info(
                    f"Config file already exists at: {self.config_file_location}")
                return

            # Ensure the directory structure exists
            dir_path = os.path.dirname(self.config_file_location)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)

            # Encrypt an empty configuration in memory before writing anything to
            # disk. Writing a plaintext "{}" first and then re-encrypting was
            # racy: a KMS failure or interrupted process would leave plaintext
            # credentials readable on disk.
            empty_config = "{}"
            blob = encrypt_buffer(
                key_id=self.key_id,
                message=empty_config,
                crypto_client=self.crypto_client,
                key_version_id=self.key_version_id,
                is_asymmetric=self.is_asymmetric,
                logger=self.logger,
            )
            with open(self.config_file_location, 'wb') as config_file:
                config_file.write(blob)
            self.logger.info(
                f"Config file created at: {self.config_file_location}")
        except Exception as err:
            self.logger.error(f"Error creating config file: {err}")
            raise

    def decrypt_config(self, autosave: bool = False) -> str:
        # Default is False so that a stray decrypt_config() call cannot silently
        # leak plaintext credentials onto disk. Pass autosave=True explicitly to
        # restore the previous behavior.
        with self._lock:
            ciphertext: bytes = bytes()
            plaintext: str = ""

            try:
                with open(self.config_file_location, 'rb') as config_file:
                    ciphertext = config_file.read()
                if len(ciphertext) == 0:
                    self.logger.warning(
                        f"Empty config file {self.config_file_location}")
                    return ""
            except Exception as err:
                self.logger.error(
                    f"Failed to load config file {self.config_file_location}: {err}")
                raise Exception(
                    f"Failed to load config file {self.config_file_location}")

            try:
                plaintext = decrypt_buffer(
                    key_id=self.key_id,
                    ciphertext=ciphertext,
                    crypto_client=self.crypto_client,
                    key_version_id=self.key_version_id,
                    is_asymmetric=self.is_asymmetric,
                    logger=self.logger,
                )
            except Exception as err:
                self.logger.error(
                    f"Failed to decrypt config file {self.config_file_location}: {err}")
                raise Exception(
                    f"Failed to decrypt config file {self.config_file_location}") from err

            if len(plaintext) == 0:
                self.logger.error(
                    f"Failed to decrypt config file {self.config_file_location}")
            elif autosave:
                try:
                    with open(self.config_file_location, 'w') as config_file:
                        config_file.write(plaintext)
                except Exception as err:
                    self.logger.error(
                        f"Failed to write decrypted config file {self.config_file_location}: {err}")
                    raise Exception(
                        f"Failed to write decrypted config file {self.config_file_location}") from err

            return plaintext

    def __save_config(self, updated_config: Optional[Dict[str, str]] = None, force: bool = False) -> None:
        try:
            # Retrieve current config
            config = self.config or {}
            config_json = json.dumps(config, sort_keys=True, indent=4)
            config_hash = hashlib.sha256(config_json.encode()).hexdigest()

            # Resolve the candidate config without mutating self.config yet.
            # self.config is only committed after the encrypted blob has been
            # written to disk so a KMS or I/O failure cannot leave in-memory
            # state ahead of the on-disk file. `updated_config is None` means
            # "re-encrypt the current self.config"; an empty dict {} is a
            # legitimate override (e.g. delete-of-last-key).
            if updated_config is not None:
                new_config = dict(updated_config)
                new_config_json = json.dumps(new_config, sort_keys=True, indent=4)
                new_config_hash = hashlib.sha256(new_config_json.encode()).hexdigest()
            else:
                new_config = config
                new_config_hash = config_hash

            if not force and new_config_hash == self.last_saved_config_hash:
                self.logger.warning(
                    "Skipped config JSON save. No changes detected.")
                return

            self.create_config_file_if_missing()

            stringified_value = json.dumps(new_config, sort_keys=True, indent=4)
            blob = encrypt_buffer(
                key_id=self.key_id,
                message=stringified_value,
                crypto_client=self.crypto_client,
                key_version_id=self.key_version_id,
                is_asymmetric=self.is_asymmetric,
                logger=self.logger,
            )
            with open(self.config_file_location, 'wb') as config_file:
                config_file.write(blob)

            # Commit the new state only after the disk write succeeded.
            self.config = new_config
            self.last_saved_config_hash = new_config_hash

        except Exception as err:
            self.logger.error(f"Error saving config: {err}")
            raise

    def load_config(self) -> None:
        self.create_config_file_if_missing()

        try:
            contents: bytes = b""
            try:
                with open(self.config_file_location, 'rb') as config_file:
                    contents = config_file.read()
                self.logger.info(
                    f"Loaded config file {self.config_file_location}")
            except Exception as err:
                self.logger.error(
                    f"Failed to load config file {self.config_file_location}: {err}")
                raise Exception(
                    f"Failed to load config file {self.config_file_location}")

            if len(contents) == 0:
                self.logger.warning(
                    f"Empty config file {self.config_file_location}")
                contents = b"{}"

            # Try plain JSON first (first-run migration path). Restrict to
            # JSON/Unicode errors only so KMS or filesystem failures don't
            # silently fall through to a decrypt attempt with bad data.
            config = None
            json_error = None
            try:
                config_data = contents.decode()
                config = json.loads(config_data)
                if config:
                    self.config = config
                    self.__save_config(config)
                    self.last_saved_config_hash = hashlib.sha256(
                        json.dumps(config, sort_keys=True, indent=4).encode()
                    ).hexdigest()
            except (json.JSONDecodeError, UnicodeDecodeError) as err:
                json_error = err

            # KSM-957: commit empty state when JSON parsed cleanly to {} so
            # subsequent read/set/delete don't crash on self.config = None.
            if self.config is None and not json_error:
                self.config = {}
                self.last_saved_config_hash = hashlib.sha256(
                    json.dumps({}, sort_keys=True, indent=4).encode()
                ).hexdigest()

            if json_error:
                config_json = decrypt_buffer(
                    key_id=self.key_id,
                    ciphertext=contents,
                    crypto_client=self.crypto_client,
                    key_version_id=self.key_version_id,
                    is_asymmetric=self.is_asymmetric,
                    logger=self.logger,
                )
                try:
                    config = json.loads(config_json)
                    self.config = config or {}
                    self.last_saved_config_hash = hashlib.sha256(
                        json.dumps(config, sort_keys=True, indent=4).encode()
                    ).hexdigest()
                except Exception as err:
                    self.logger.error(
                        f"Failed to parse decrypted config file: {err}")
                    raise Exception(
                        f"Failed to parse decrypted config file {self.config_file_location}")

        except Exception as err:
            self.logger.error(f"Error loading config: {err}")
            raise

    def change_key(self, new_key_id: str, new_key_version_id: str = None) -> bool:
        with self._lock:
            old_key_id = self.key_id
            old_key_version_id = self.key_version_id
            old_is_asymmetric = self.is_asymmetric

            try:
                config = self.config
                if config is None:
                    self.load_config()
                self.key_id = new_key_id
                self.key_version_id = new_key_version_id
                self.get_key_details()
                self.__save_config(force=True)
            except Exception as error:
                self.key_id = old_key_id
                self.key_version_id = old_key_version_id
                self.is_asymmetric = old_is_asymmetric
                self.logger.error(
                    f"Failed to change the key to '{new_key_id}' for config '{self.config_file_location}': {error}"
                )
                raise Exception(
                    f"Failed to change the key for {self.config_file_location}")

            return True

    def read_storage(self) -> Dict[str, str]:
        with self._lock:
            if self.config is None:
                self.load_config()
            return dict(self.config)

    def save_storage(self, updated_config: Dict[str, str]) -> None:
        with self._lock:
            self.__save_config(updated_config)

    def get(self, key: ConfigKeys) -> str:
        config = self.read_storage()
        return config.get(key.value)

    def set(self, key: ConfigKeys, value):
        with self._lock:
            config = self.read_storage()
            config[key.value] = value
            self.save_storage(config)
            return config

    def delete(self, key: ConfigKeys):
        with self._lock:
            kv = key.value
            new_config = dict(self.config or {})
            if kv in new_config:
                del new_config[kv]
                self.logger.debug("Removed key %s" % kv)
            else:
                self.logger.debug("No key %s was found in config" % kv)
            self.save_storage(new_config)
            return dict(self.config)

    def delete_all(self):
        with self._lock:
            if os.path.exists(self.config_file_location):
                os.remove(self.config_file_location)
            self.config = {}
            self.last_saved_config_hash = ""
            return {}

    def contains(self, key: ConfigKeys):
        config = self.read_storage()
        return key.value in config
