# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from distutils.util import strtobool
from .profile import Profile
import sys
import logging


class KeeperCli:

    @staticmethod
    def get_client(**kwargs):
        return SecretsManager(**kwargs)

    def __init__(self, ini_file=None, profile_name=None, output=None, use_color=None):

        self.profile = Profile(cli=self, ini_file=ini_file)
        self._client = None

        self._log_level = "INFO"
        self.use_color = use_color

        # If no config file is loaded, then don't init the SDK
        if self.profile.is_loaded is True:

            # If the profile is not set
            if profile_name is None:
                profile_name = self.profile.get_active_profile_name()

                # If we don't have a profile we can't do anything.
                if profile_name is None:
                    raise ValueError("Cannot determine the active profile.")

            # Get the active configuration
            self.config = self.profile.get_profile_config(profile_name)

            config_storage = InMemoryKeyValueStorage()
            config_storage.set(ConfigKeys.KEY_CLIENT_KEY, self.config.get("clientKey"))
            config_storage.set(ConfigKeys.KEY_CLIENT_ID, self.config.get("clientId"))
            config_storage.set(ConfigKeys.KEY_PRIVATE_KEY, self.config.get("privateKey"))
            config_storage.set(ConfigKeys.KEY_APP_KEY, self.config.get("appKey"))
            config_storage.set(ConfigKeys.KEY_HOSTNAME, self.config.get("hostname"))

            common_profile = self.profile.get_profile_config(Profile.config_profile)

            self._client = self.get_client(
                config=config_storage,
                log_level=common_profile.get("log_level", self._log_level)
            )
            if self.use_color is None:
                self.use_color = bool(strtobool(common_profile.get("color", str(True))))
        else:
            # Set the log level. We don't have the client to set the level, so set it here.
            self.log_level = self._log_level
            if use_color is None:
                self.use_color = True

        # Default to stdout if the output is not set.
        if output is None:
            output = "stdout"
        self.output_name = output

    @property
    def client(self):
        if self._client is None:
            raise Exception("The Keeper SDK client has not been loaded. The INI config might not be set.")
        return self._client

    @client.setter
    def client(self, value):
        self._client = value

    @property
    def log_level(self):
        return self._log_level

    @log_level.setter
    def log_level(self, value):
        self.set_log_level(value)
        self._log_level = value

    @staticmethod
    def set_log_level(value):
        logger = logging.getLogger()
        # Set the log level. Look up the int value using the string.
        logger.setLevel(getattr(logging, value))

    def output(self, msg):

        is_file = False
        is_bytes = type(msg) is bytes
        if self.output_name == "stdout":
            output_fh = sys.stdout
        elif self.output_name == "stderr":
            output_fh = sys.stderr
        elif type(self.output_name) is str:
            output_fh = open(self.output_name, "w+")
            is_file = True
        else:
            sys.exit("The output {} is not supported. Cannot display your information.".format(self.output))

        # Write bytes via the buffer since we do not know the encoding. We can't decode() because it might not
        # be utf-8.
        if is_bytes is True:
            output_fh.buffer.write(msg)
        else:
            output_fh.write(msg)

        if is_file is True:
            output_fh.close()
        else:
            # Make sure we push stdout and stderr out.
            output_fh.flush()
