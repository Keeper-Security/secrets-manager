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
import logging
import os
import json

# An Interface for different storage types
import errno
from json import JSONDecodeError
import platform
import subprocess

from keeper_secrets_manager_core import exceptions, utils
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.utils import (
    ENCODING, 
    base64_to_string, 
    json_to_dict, 
    set_config_mode, 
    check_config_mode
)


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

            f = open(self.default_config_file_location, "w+")
            f.write(json.dumps({}))
            f.close()

            # Make sure the new config file has the correct mode.
            set_config_mode(self.default_config_file_location)

    def is_empty(self):
        config = self.read_storage()

        return not config


class InMemoryKeyValueStorage(KeyValueStorage):
    """ In Memory based implementation of the key value storage"""

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


class SecureOSStorage(KeyValueStorage):
    """Secure OS based implementation of the key value storage
    
    Uses either the Windows Credential Manager, Linux Keyring or macOS Keychain to store 
    the config. The config is stored as a base64 encoded string.
    """
    def __init__(self, app_name, exec_path):
        if not app_name:
            logging.getLogger(logger_name).error("An application name is required for SecureOSStorage")
            raise exceptions.KeeperError("An application name is required for SecureOSStorage")

        self.app_name = app_name
        self._machine_os = platform.system()
        
        if not exec_path:
            self._exec_path = self._find_exe_path()
            if not self._exec_path:
                logging.getLogger(logger_name).error("Could not find secure config executable")
                raise exceptions.KeeperError("Could not find secure config executable")
        else:
            self._exec_path = exec_path

        self.config = {}

    def _find_exe_path(self) -> str | None:
        if path := os.getenv("KSM_CONFIG_EXE_PATH"):
            return path
        
        if self._machine_os == "Windows":
            return self._run_command(["powershell", "-command", "(Get-Command wcm).Source"])                
        elif self._machine_os == "Linux":
            return self._run_command(["which", "lku"])
            
    def _run_command(self, args: list[str]) -> str | None:
        """Run a command and return the output of stdout. 
        If stdout is empty and has zero exit code, return None.
        """
        try:
            completed_process = subprocess.run(args, capture_output=True, check=True)
            if completed_process.stdout:
                return completed_process.stdout.decode().strip()
            else:
                logging.getLogger(logger_name).error(f"Command: {args} returned empty stdout")
                return None
        except subprocess.CalledProcessError:
            logging.getLogger(logger_name).error(f"Failed to run command: {args}, which returned {completed_process.stderr}")
            raise exceptions.KeeperError(f"Failed to run command: {args}")

    def read_storage(self) -> dict:
        result = self._run_command([self._exec_path, "get", self.app_name])
        if not result:
            logging.getLogger(logger_name).error("Failed to read config or config does not exist")
            return self.config
        
        config = json_to_dict(base64_to_string(result))
        for key in config:
            self.config[ConfigKeys.get_enum(key)] = config[key]
        
        return self.config

    def save_storage(self, updated_config) -> None:
        # Convert updated config to base64 and save it
        converted_b64 = base64.b64encode(json.dumps(updated_config).encode())

        result = self._run_command([self._exec_path, "set", self.app_name, converted_b64])
        if not result:
            logging.getLogger(logger_name).error("Failed to save config with error")
            raise exceptions.KeeperError("Failed to save config")

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
