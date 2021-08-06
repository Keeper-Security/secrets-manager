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

import os
import configparser
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.exceptions import KeeperError, KeeperAccessDenied
from keeper_secrets_manager_core.utils import encrypt_aes, decrypt_aes
from .table import Table, ColumnAlign
from colorama import Fore
import sys
import json
import base64
import hashlib
import tempfile


class Profile:

    config_profile = "_config"
    active_profile_key = "active_profile"
    default_profile = os.environ.get("KSM_CLI_PROFILE", "_default")
    default_ini_file = os.environ.get("KSM_INI_FILE", "keeper.ini")
    log_level_key = "log_level"
    color_key = "color"

    def __init__(self, cli, ini_file=None):

        self.cli = cli

        # If the INI file is not set, find it.
        if ini_file is None:
            ini_file = Profile.find_ini_config()

            # If we can't find it, and the KSM_TOKEN env is set, auto create it. We do this because
            # this might be a container startup and there is not INI file, but we have passed in the client key.
            token = os.environ.get("KSM_TOKEN")
            if token is not None:
                Profile.init(
                    token=token,
                    server=os.environ.get("KSM_HOSTNAME", "US")
                )
                # Check again for the INI config file
                ini_file = Profile.find_ini_config()
        self.ini_file = ini_file

        # Lazy load in the config
        self._config = None
        self.is_loaded = False

        if self.ini_file is not None:
            self._load_config()

    def _load_config(self):
        if self._config is None:

            if self.ini_file is None:
                raise FileNotFoundError("Cannot find the Keeper INI file {}".format(Profile.default_ini_file))
            elif os.path.exists(self.ini_file) is False:
                raise FileNotFoundError("Keeper INI files does not exists at {}".format(self.ini_file))

            self._config = configparser.ConfigParser()
            self._config.read(self.ini_file)

            self.is_loaded = True

    def save(self):
        with open(self.ini_file, 'w') as configfile:
            self._config.write(configfile)

    @staticmethod
    def find_ini_config():

        # Directories to scan for the keeper INI file. This both Linux and Windows paths. The os.path.join
        # should create a path that the OS understands. The not_set stuff in case the environmental var is not set.
        # The last entry is the current working directory.
        not_set = "_NOTSET_"
        dir_locations = [
            [os.environ.get("KSM_INI_DIR", not_set)],
            [os.getcwd()],

            # Linux
            [os.environ.get("HOME", not_set)],
            [os.environ.get("HOME", not_set), ".keeper"],
            ["/etc"],
            ["/etc", "keeper"],

            # Windows
            [os.environ.get("USERPROFILE", not_set)],
            [os.environ.get("APPDIR", not_set)],
            [os.environ.get("PROGRAMDATA", not_set), "Keeper"],
            [os.environ.get("PROGRAMFILES", not_set), "Keeper"],
        ]

        for dir_location in dir_locations:
            path = os.path.join(*dir_location, Profile.default_ini_file)
            if os.path.exists(path) and os.path.isfile(path):
                return path

        return None

    def get_config(self):
        self._load_config()
        return self._config

    def get_profile_config(self, profile_name):
        config = self.get_config()
        if profile_name not in config:
            raise ValueError("The profile {} does not exist in the INI config.".format(profile_name))

        return config[profile_name]

    def get_active_profile_name(self):
        common_config = self.get_profile_config(Profile.config_profile)
        return os.environ.get("KSM_CLI_PROFILE", common_config.get(Profile.active_profile_key))

    def _get_common_config(self, error_prefix):
        try:
            return self.get_profile_config(Profile.config_profile)
        except Exception as err:
            sys.exit("{} {}".format(error_prefix, err))

    @staticmethod
    def init(token, ini_file=None, server=None, profile_name=None, log_level="INFO"):

        from . import KeeperCli

        # If the ini is not set, default the file in the current directory.
        if ini_file is None:
            ini_file = os.path.join(
                os.environ.get("KSM_INI_DIR", os.getcwd()),
                Profile.default_ini_file
            )

        if profile_name is None:
            profile_name = os.environ.get("KSM_CLI_PROFILE", Profile.default_profile)

        if profile_name == Profile.config_profile:
            raise ValueError("The profile '{}' is a reserved profile name. Cannot not init profile.".format(
                profile_name))

        config = configparser.ConfigParser()

        # We want to flag if we create a INI file. If there is an error, remove it so it
        # doesn't get picked up if we try again.
        created_ini = False

        # If the ini file doesn't exists, create it with the common profile
        if os.path.exists(ini_file) is False:
            # This section gets applied to all other sections by the config parser. This is left empty.
            config['DEFAULT'] = {}

            # Create our default section name.
            config[Profile.default_profile] = {}

            # Create our config section name.
            config[Profile.config_profile] = {
                "log_level": log_level,
                Profile.active_profile_key: Profile.default_profile
            }
            with open(ini_file, 'w') as configfile:
                config.write(configfile)
            created_ini = True
        else:
            config.read(ini_file)

        config_storage = InMemoryKeyValueStorage()
        config_storage.set(ConfigKeys.KEY_CLIENT_KEY, token)
        if server is not None:
            config_storage.set(ConfigKeys.KEY_HOSTNAME, server)

        client = KeeperCli.get_client(config=config_storage, log_level=log_level)

        # Get the secret records to get the app key. The SDK will add the app key to the config.
        try:
            client.get_secrets()
        except (KeeperError, KeeperAccessDenied) as err:
            # If we just create the INI file and there was an error. Remove it.
            if created_ini is True:
                os.unlink(ini_file)
            sys.exit("Could not init the profile: {}".format(err.message))
        except Exception as err:
            if created_ini is True:
                os.unlink(ini_file)
            sys.exit("Could not init the profile: {}".format(err))

        config[profile_name] = {
            "clientKey": "",
            "clientId": "",
            "privateKey": "",
            "appKey": "",
            "hostname": ""
        }

        for k, v in config_storage.config.items():
            if v is None:
                continue
            config[profile_name][k.value] = v
        with open(ini_file, 'w') as configfile:
            config.write(configfile)

        print("Added profile {} to INI config file located at {}".format(profile_name, ini_file), file=sys.stderr)

    def list_profiles(self, output='text', use_color=True):

        profiles = []

        try:
            active_profile = self.get_active_profile_name()

            for profile in self.get_config():
                if profile == Profile.config_profile:
                    continue
                profiles.append({
                    "active": profile == active_profile,
                    "name": profile
                })

            if output == 'text':
                table = Table(use_color=use_color)
                table.add_column("Active", align=ColumnAlign.CENTER, data_color=Fore.RED)
                table.add_column("Profile", data_color=Fore.YELLOW)

                for profile in profiles:
                    table.add_row(["*" if profile["active"] is True else " ", profile["name"]])

                self.cli.output("\n" + table.get_string() + "\n")
            elif output == 'json':
                self.cli.output(json.dumps(profiles))
            return profiles

        except FileNotFoundError as err:
            sys.exit("Cannot get list of profiles. {}".format(err))

    def set_active(self, profile_name):

        common_config = self._get_common_config("Cannot set active profile.")

        if profile_name not in self.get_config():
            exit("Cannot set profile {} to active. It does not exists.".format(profile_name))

        common_config[Profile.active_profile_key] = profile_name
        self.save()

        print("{} is now the active profile.".format(profile_name), file=sys.stderr)

    def export_config(self, profile_name=None, key=None):

        """Take a profile from an existing config and make it a stand-alone config.

        This is when you want to pull a single profile from a config and use it
        someplace else, like inside of a Docker image.

        The key will encrypt, and base64, the config file. While it's nice
        for security, the real reason was to make a single line string. :)
        """

        # If the profile name is not set, use the active profile.
        if profile_name is None:
            profile_name = self.get_active_profile_name()
        profile_config = self.get_profile_config(profile_name)

        export_config = configparser.ConfigParser()
        export_config[Profile.default_profile] = profile_config
        export_config[Profile.config_profile] = {
            "log_level": "ERROR",
            Profile.active_profile_key: Profile.default_profile
        }

        # Apparently the config parser doesn't like temp files. So create a
        # temp file, then open a file for writing and use that to write
        # the config. Then read the temp file to get our new config.
        with tempfile.NamedTemporaryFile() as tf:

            with open(tf.name, 'w') as configfile:
                export_config.write(configfile)

            tf.seek(0)
            config_str = tf.read()
            tf.close()

        if key is not None:
            real_key = hashlib.sha256(key.encode()).digest()
            ciphertext = encrypt_aes(config_str, real_key)
            config_str = base64.b64encode(ciphertext)

        self.cli.output(config_str)

    @staticmethod
    def import_config(key, enc_config, file=None):

        """Take base64 AES encrypted config file and unencrypted it back to disk.
        """

        if file is None:
            file = Profile.default_ini_file

        real_key = hashlib.sha256(key.encode()).digest()
        cipher = base64.b64decode(enc_config)
        config_str = decrypt_aes(cipher, real_key)

        with open(file, "w") as fh:
            fh.write(config_str.decode())
            fh.close()

        print("Imported config saved to {}".format(file), file=sys.stderr)

    def set_log_level(self, level):
        common_config = self._get_common_config("Cannot set log level.")
        common_config[Profile.log_level_key] = level
        self.cli.log_level = level
        self.save()

    def set_color(self, on_off):
        common_config = self._get_common_config("Cannot set log level.")
        common_config[Profile.color_key] = str(on_off)
        self.cli.use_color = on_off
        self.save()

    def show_config(self):
        common_config = self._get_common_config("Cannot show the config.")
        not_set_text = "-NOT SET-"
        print("Active Profile: {}".format(common_config.get(Profile.active_profile_key, not_set_text)))
        print("Log Level: {}".format(common_config.get(Profile.log_level_key, not_set_text)))
        print("Color Enabled: {}".format(common_config.get(Profile.color_key, not_set_text)))
