# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2022 Keeper Security Inc.
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
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    logger.error("Missing AWS SDK import dependencies."
                 " To install missing packages run: \r\n"
                 "pip3 install boto3\r\n")
    raise Exception("Missing import dependencies: boto3")


class AwsSessionConfig():
    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, region_name: str):
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.region_name = region_name
        # HSMs cannot change regions


# Usage:
# from keeper_secrets_manager_core import SecretsManager
# from keeper_secrets_manager_hsm.storage_aws_kms import AwsKmsKeyValueStorage
# key_id = 'c5ebe966-xxxx-yyyy-zzzz-9248e834c576'
# config = AwsKmsKeyValueStorage(key_id, 'client-config.json') # auto encrypt
# secrets_manager = SecretsManager(config=config)
# all_records = secrets_manager.get_secrets()

class AwsKmsKeyValueStorage(KeyValueStorage):
    """AWS KMS encrypted key-value storage"""

    default_config_file_location = "client-config.json"

    def __init__(self, key_id: str, config_file_location: str = "", aws_session_config: AwsSessionConfig | None = None):
        self.default_config_file_location = config_file_location if config_file_location else os.environ.get("KSM_CONFIG_FILE",
            AwsKmsKeyValueStorage.default_config_file_location)
        self.key_id = key_id if key_id else os.environ.get("KSM_KMS_KEY_ID", "")  # Master Key ID
        has_aws_session_config = (aws_session_config
            and aws_session_config.aws_access_key_id
            and aws_session_config.aws_secret_access_key
            and aws_session_config.region_name)
        if has_aws_session_config:
            self.kms_client = boto3.client('kms',
                aws_access_key_id=aws_session_config.aws_access_key_id,
                aws_secret_access_key=aws_session_config.aws_secret_access_key,
                region_name=aws_session_config.region_name)
        else:
            self.kms_client = boto3.client('kms')  # uses default session
        self.last_saved_config_hash = ""
        self.config = {}
        self.__load_config()

    def __encrypt_buffer(self, message: str) -> bytes:
        try:
            response = self.kms_client.encrypt(KeyId=self.key_id, Plaintext=message.encode())
            ciphertext = response['CiphertextBlob']
            return ciphertext
        except ClientError as err:
            logger.error("KMS client failed to encrypt plaintext. %s", err.response['Error']['Message'])
        return b""

    def __decrypt_buffer(self, ciphertext: bytes) -> str:
        try:
            response = self.kms_client.decrypt(KeyId=self.key_id, CiphertextBlob=ciphertext)
            plaintext = response['Plaintext']
            return plaintext.decode('utf8')
        except ClientError as err:
            logger.error("KMS client failed to decrypt ciphertext. %s", err.response['Error']['Message'])
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
                self.__save_config()  # save encrypted
                self.last_saved_config_hash = hashlib.md5(json.dumps(config, indent=4, sort_keys=True).encode()).hexdigest()
            else:
                # Try to decrypt binary blob
                config_json = self.__decrypt_buffer(contents)
                if len(config_json) == 0:
                    logging.getLogger(logger_name).error("Failed to decrypt config file " + self.default_config_file_location)
                else:
                    try:
                        config = json.loads(config_json)
                        self.config = config
                        self.last_saved_config_hash = hashlib.md5(json.dumps(config, indent=4, sort_keys=True).encode()).hexdigest()
                    except Exception as err:
                        logger.error("Config JSON has problems: {}".format(err))
                        raise err
        except IOError:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), self.default_config_file_location)

    def __save_config(self, updated_config: dict = {}, module=0, force=False):
        config = self.config if self.config else {}
        config_json: str = json.dumps(config, indent=4, sort_keys=True)
        config_hash = hashlib.md5(config_json.encode()).hexdigest()

        if updated_config:
            ucfg_json: str = json.dumps(updated_config, indent=4, sort_keys=True)
            ucfg_hash = hashlib.md5(ucfg_json.encode()).hexdigest()
            if ucfg_hash != config_hash:
                config_hash = ucfg_hash
                config_json = ucfg_json
                self.config = dict(updated_config)
                # update after save - to allow for retries
                # self.last_saved_config_hash = config_hash

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
        except Exception:
            logging.getLogger(logger_name).error("Failed to load config file " + self.default_config_file_location)
            raise Exception("Failed to load config file " + self.default_config_file_location)

        try:
            plaintext = self.__decrypt_buffer(ciphertext)
            if len(plaintext) == 0:
                logging.getLogger(logger_name).error("Failed to decrypt config file " + self.default_config_file_location)
            elif autosave:
                with open(self.default_config_file_location, "w") as fh:
                    fh.write(plaintext)
        except Exception:
            logging.getLogger(logger_name).error("Failed to write decrypted config file " + self.default_config_file_location)
            raise Exception("Failed to write decrypted config file " + self.default_config_file_location)
        return plaintext

    def change_key(self, new_key_id: str) -> bool:
        old_key_id = self.key_id
        try:
            self.key_id = new_key_id
            self.__save_config(force=True)
        except Exception:
            self.key_id = old_key_id
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
            logger.debug(f"Removed key {kv}")
        else:
            logger.debug(f"No key {kv} was found in config")

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
