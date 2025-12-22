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

import base64
import hashlib
import logging
import os
import json
import shutil
import subprocess

# An Interface for different storage types
import errno
from json import JSONDecodeError

from keeper_secrets_manager_core import exceptions, utils
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.utils import ENCODING, json_to_dict, set_config_mode, check_config_mode, is_base64, url_safe_str_to_bytes


class KeyValueStorage:
    """ Interface for the key value storage"""

    def read_storage(self):
        pass

    def save_storage(self, updated_config):
        pass

    def get(self, key: ConfigKeys):
        pass

    def set(self, key: ConfigKeys, value):
        pass

    def delete(self, key: ConfigKeys):
        pass

    def delete_all(self):
        pass

    def contains(self, key: ConfigKeys):
        pass

    def is_empty(self):
        pass


class FileKeyValueStorage(KeyValueStorage):
    """ File based implementation of the key value storage"""

    default_config_file_location = "client-config.json"

    def __init__(self, config_file_location=None):

        if config_file_location is None:
            config_file_location = os.environ.get("KSM_CONFIG_FILE",
                                                  FileKeyValueStorage.default_config_file_location)

        self.default_config_file_location = config_file_location

    def read_storage(self):

        self.create_config_file_if_missing()

        try:
            check_config_mode(self.default_config_file_location)

            with open(self.default_config_file_location, "r", encoding=ENCODING) as fh:
                config_data = None
                try:
                    config_data = fh.read()
                    config = json.loads(config_data)
                except UnicodeDecodeError:
                    logging.getLogger(logger_name).error("Config file is not utf-8 encoded.")
                    raise Exception("{} is not a utf-8 encoded file".format(self.default_config_file_location))
                except JSONDecodeError as err:

                    # If the JSON file was not empty, it's a legit JSON error. Throw an exception.
                    if config_data is not None and config_data.strip() != "":
                        raise Exception("{} may contain JSON format problems or is not utf-8 encoded"
                                        ": {}".format(self.default_config_file_location, err))

                    # If it was an empty file, overwrite with the JSON config
                    logging.getLogger(logger_name).warning("Looks like config file is empty.")
                    config = {}
                    self.save_storage(config)
                except Exception as err:
                    logging.getLogger(logger_name).error("Config JSON has problems: {}".format(err))
                    if "codec" in str(err):
                        raise Exception("{} is not a utf-8 encoded file.".format(self.default_config_file_location))
                    raise err

        # PermissionError is an IOError child. Handle before IOError.
        except PermissionError as err:
            raise err
        except IOError:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), self.default_config_file_location)

        return config

    def save_storage(self, updated_config):

        self.create_config_file_if_missing()

        with open(self.default_config_file_location, "w") as write_file:
            json.dump(updated_config, write_file, indent=4, sort_keys=True)

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
            logging.getLogger(logger_name).debug("Removed key %s" % kv)
        else:
            logging.getLogger(logger_name).debug("No key %s was found in config" % kv)

        self.save_storage(config)

        return config

    def delete_all(self):
        config = self.read_storage()
        config.clear()

        self.save_storage(config)

        return config

    def contains(self, key: ConfigKeys):
        config = self.read_storage()

        return key.value in config

    def create_config_file_if_missing(self):
        if not os.path.exists(self.default_config_file_location):

            # Create file with secure permissions (0600) atomically
            fd = os.open(self.default_config_file_location, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(json.dumps({}))

            # Ensure permissions are correct (defensive)
            set_config_mode(self.default_config_file_location)

    def is_empty(self):
        config = self.read_storage()

        return not config


class InMemoryKeyValueStorage(KeyValueStorage):
    """ File based implementation of the key value storage"""

    def __init__(self, config=None):

        self.config = {}

        if config is None:
            config = {}

        elif isinstance(config, str):

            if InMemoryKeyValueStorage.is_base64(config):
                # Decode if config json was provided as base64 string
                config = utils.base64_to_string(config)

            config = json_to_dict(config)
            if not config:
                raise exceptions.KeeperError("Could not load config data. Json text size: %s" % str(len(config)))

        for key in config:
            self.config[ConfigKeys.get_enum(key)] = config[key]

    def read_storage(self):

        # To match what FileKeyValueStorage does, we need to return the enum values as keys instead
        # of the enum keys
        dict_config = {}
        for enum_key in self.config:
            dict_config[enum_key.value] = self.config[enum_key]
        return dict_config

    def save_storage(self, updated_config):
        pass

    def get(self, key: ConfigKeys):
        return self.config.get(key)

    def set(self, key: ConfigKeys, value):
        self.config[key] = value

    def delete(self, key: ConfigKeys):
        self.config.pop(key, None)

    def delete_all(self):
        self.config = {}

    def contains(self, key: ConfigKeys):
        return key in self.config

    @staticmethod
    def is_base64(s):
        try:
            return base64.b64encode(base64.b64decode(s)) == str.encode(s)
        except (Exception,):
            return False

class KeyringUtilityStorage(KeyValueStorage):
    """OS Keyring Storage extends the key value storage interface.

    Uses Python keyring library for cross-platform support:
    - macOS: Keychain
    - Windows: Credential Manager  
    - Linux: Secret Service (or lkru utility as fallback)
    """



    logger = logging.getLogger(logger_name)

    @classmethod
    def __fatal(cls, message: str, error: Exception = None):
        message = f"{cls.__name__}: {message}"
        if error:
            cls.logger.error(message, exc_info=error)
        else:
            cls.logger.error(message)
        raise exceptions.KeeperError(message, error)

    def __init__(
        self,
        secret_name: str,
        keyring_application_name: str = None,
        keyring_collection_name: str = None,
        keyring_utility: str = "lkru",
        keyring_utility_path: str = None,
    ):
        if not secret_name:
            self.__fatal("Keyring Storage requires a secret name")

        self.secret_name = secret_name
        self.keyring_application_name = keyring_application_name or "keeper-secrets-manager"
        self.keyring_collection_name = keyring_collection_name
        
        # Try to use Python keyring library (works on macOS, Windows, Linux)
        self.use_python_keyring = False
        self.keyring_utility_path = None
        
        try:
            import keyring
            self.use_python_keyring = True
            self.logger.debug(f"Using Python keyring library for OS-native storage")
        except ImportError:
            if keyring_utility_path:
                if p := os.path.abspath(keyring_utility_path).strip():
                    if os.path.exists(p):
                        self.keyring_utility_path = p
                        self.logger.debug(f"Using lkru utility at: {self.keyring_utility_path}")
                else:
                    self.__fatal(f"Invalid keyring utility path: {keyring_utility_path}")
            elif p := os.getenv("KSM_CONFIG_KEYRING_UTILITY_PATH"):
                if os.path.exists(p):
                    self.keyring_utility_path = p
                    self.logger.debug(f"Using lkru from KSM_CONFIG_KEYRING_UTILITY_PATH: {p}")
                else:
                    self.__fatal(f"Invalid path in KSM_CONFIG_KEYRING_UTILITY_PATH: {p}")
            elif p := shutil.which(keyring_utility):
                self.keyring_utility_path = p
                self.logger.debug(f"Using lkru utility at: {self.keyring_utility_path}")
            else:
                self.__fatal("No keyring backend available. Install: pip install keyring")

        self.config = {}
        self.config_hash = None
        self.__load_config()

    def __get_keyring_value(self, key: str) -> str:
        """Get value from keyring (Python library or lkru utility)."""
        if self.use_python_keyring:
            import keyring
            value = keyring.get_password(self.keyring_application_name, key)
            return value if value else ""
        else:
            return self.__run_keyring_utility(["get", key])
    
    def __set_keyring_value(self, key: str, value: str) -> None:
        """Set value in keyring (Python library or lkru utility)."""
        if self.use_python_keyring:
            import keyring
            keyring.set_password(self.keyring_application_name, key, value)
        else:
            self.__run_keyring_utility(["set", key, value])

    def __run_keyring_utility(self, args: list[str]) -> str:
        """Run lkru utility (Linux only fallback)."""
        try:
            match args[0]:
                case "get" | "set":
                    args.append("-b")

            if self.keyring_application_name:
                args.insert(1, self.keyring_application_name)
                args.insert(1, "-a")

            if self.keyring_collection_name:
                args.insert(1, self.keyring_collection_name)
                args.insert(1, "-c")

            args.insert(0, self.keyring_utility_path)

            self.logger.debug(f"Running keyring utility as: {args}")

            return (
                subprocess.run(
                    args,
                    capture_output=True,
                    check=True,
                    executable=self.keyring_utility_path,
                )
                .stdout.decode()
                .strip()
            )
        except subprocess.CalledProcessError as e:
            message = f"Keyring utility exited with {e.returncode}"
            if e.stderr:
                message += f" with error output '{e.stderr.decode().strip()}'"
            self.__fatal(message, e)


    def __load_config(self):
        try:
            from keeper_secrets_manager_core.helpers import is_json
            
            contents = self.__get_keyring_value(self.secret_name)
            if not contents:
                self.config = {}
                return
                
            if is_base64(contents):
                contents = url_safe_str_to_bytes(contents)

            if is_json(contents):
                self.config = json.loads(contents)
                self.config_hash = hashlib.md5(
                    json.dumps(self.config, indent=4, sort_keys=True).encode()
                ).hexdigest()
            else:
                self.__fatal(
                    f"Unable to parse keyring output as JSON: '{contents}'"
                )
        except Exception as e:
            self.logger.debug(f"No existing config in keyring: {str(e)}")

    def __save_config(self, updated_config: dict = None, force: bool = False):
        if updated_config:
            config = json.dumps(updated_config, indent=4, sort_keys=True)
            hash_value = hashlib.md5(config.encode()).hexdigest()

            if hash_value != self.config_hash or force:
                try:
                    self.__set_keyring_value(self.secret_name, config)
                except Exception as e:
                    self.logger.error(
                        f"Failed to save config JSON to keyring: {str(e)}"
                    )

                self.config_hash = hash_value
                self.config = dict(updated_config)
            else:
                self.logger.warning("Skipped config JSON save. No changes detected.")
                return


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
            self.logger.debug(f"Removed key {kv}")
        else:
            self.logger.debug(f"No key {kv} was found in config")

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

    def is_empty(self):
        config = self.read_storage()
        return not config

