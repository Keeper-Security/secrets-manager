#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com

import logging
import os
import json

# An Interface for different storage types
import errno
from json import JSONDecodeError

from keeper_secrets_manager_core import exceptions
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.utils import ENCODING, json_to_dict


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
            with open(self.default_config_file_location, "r", encoding=ENCODING) as config_file:
                try:

                    config = json.load(config_file)
                except JSONDecodeError:
                    logging.warning("Looks like config file is empty.")

                    config = {}
                    self.save_storage(config)

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
            logging.debug("Removed key %s" % kv)
        else:
            logging.warning("No key %s was found in config" % kv)

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
