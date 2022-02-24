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
from keeper_secrets_manager_cli.exception import KsmCliException
from keeper_secrets_manager_cli.common import find_ksm_path
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.exceptions import KeeperError, KeeperAccessDenied
from .table import Table, ColumnAlign
from .export import Export
from colorama import Fore
import sys
import json
import base64


class Profile:

    config_profile = "_config"
    active_profile_key = "active_profile"
    default_profile = os.environ.get("KSM_CLI_PROFILE", "_default")
    default_ini_file = os.environ.get("KSM_INI_FILE", "keeper.ini")
    color_key = "color"
    cache_key = "cache"
    record_type_dir_key = "record_type_dir"
    editor_key = "editor"
    editor_use_blocking_key = "editor_use_blocking"
    editor_process_name_key = "editor_process_name"

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

            # Auto generate config file from base64 encode env vars.
            # This can import multiple profiles.
            elif os.environ.get("KSM_CONFIG_BASE64_1") is not None:
                self._auto_config_from_env_var()
                ini_file = Profile.find_ini_config()
            # This can only import one. Move the KSM_CONFIG to KSM_CONFIG_BASE64_1
            elif os.environ.get("KSM_CONFIG") is not None:
                os.environ["KSM_CONFIG_BASE64_1"] = os.environ["KSM_CONFIG"]
                self._auto_config_from_env_var()
                ini_file = Profile.find_ini_config()

        self.ini_file = ini_file

        # Lazy load in the config
        self._config = None
        self.is_loaded = False

        if self.ini_file is not None:
            self._load_config()

    @staticmethod
    def _auto_config_from_env_var():

        """Build config from a Base64 config in environmental variables.

        """

        index = 1
        while True:
            config_base64 = os.environ.get("KSM_CONFIG_BASE64_{}".format(index))
            if config_base64 is not None:
                Profile.import_config(
                    config_base64=config_base64,
                    profile_name=os.environ.get("KSM_CONFIG_BASE64_DESC_{}".format(index), "App{}".format(index)))
            else:
                break
            index += 1

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
        file = find_ksm_path(Profile.default_ini_file, is_file=True)
        return file

    def get_config(self):
        self._load_config()
        return self._config

    def get_profile_config(self, profile_name):
        config = self.get_config()
        if profile_name not in config:
            raise KsmCliException("The profile {} does not exist in the INI config.".format(profile_name))

        return config[profile_name]

    def get_active_profile_name(self):
        common_config = self.get_profile_config(Profile.config_profile)
        return os.environ.get("KSM_CLI_PROFILE", common_config.get(Profile.active_profile_key))

    def _get_common_config(self, error_prefix):
        try:
            return self.get_profile_config(Profile.config_profile)
        except Exception as err:
            raise KsmCliException("{} {}".format(error_prefix, err))

    @staticmethod
    def _init_config_file(profile_name=None):

        if profile_name is None:
            profile_name = Profile.default_profile

        config = configparser.ConfigParser()

        # Create our default section name.
        config[profile_name] = {}

        # Create our config section name.
        config[Profile.config_profile] = {
            Profile.active_profile_key: profile_name
        }

        return config

    @staticmethod
    def init(token, ini_file=None, server=None, profile_name=None):

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
            raise KsmCliException("The profile '{}' is a reserved profile name. Cannot not init profile.".format(
                profile_name))

        # We want to flag if we create a INI file. If there is an error, remove it so it
        # doesn't get picked up if we try again.
        created_ini = False

        # If the ini file doesn't exists, create it with the common profile
        if os.path.exists(ini_file) is False:
            config = Profile._init_config_file()
            with open(ini_file, 'w') as configfile:
                config.write(configfile)
            created_ini = True
        else:
            config = configparser.ConfigParser()
            config.read(ini_file)

        # if the token has a ":" in it, the region code/server is concat'd to the token. Split them.
        if ":" in token:
            server, token = token.split(":", 1)

        config_storage = InMemoryKeyValueStorage()
        config_storage.set(ConfigKeys.KEY_CLIENT_KEY, token)
        if server is not None:
            config_storage.set(ConfigKeys.KEY_HOSTNAME, server)

        client = KeeperCli.get_client(config=config_storage)

        # Get the secret records to get the app key. The SDK will add the app key to the config.
        try:
            client.get_secrets()
        except (KeeperError, KeeperAccessDenied) as err:
            # If we just create the INI file and there was an error. Remove it.
            if created_ini is True:
                os.unlink(ini_file)
            raise KsmCliException("Could not init the profile: {}".format(err.message))
        except Exception as err:
            if created_ini is True:
                os.unlink(ini_file)
            raise KsmCliException("Could not init the profile: {}".format(err))

        config[profile_name] = {
            "clientKey": "",
            "clientId": "",
            "privateKey": "",
            "appKey": "",
            "hostname": "",
            "appOwnerPublicKey": ""
        }

        for k, v in config_storage.config.items():
            if v is None:
                continue
            config[profile_name][k.value] = v
        with open(ini_file, 'w') as configfile:
            config.write(configfile)

        print("Added profile {} to INI config file located at {}".format(profile_name, ini_file), file=sys.stderr)

    def list_profiles(self, output='text', use_color=None):

        if use_color is None:
            use_color = self.cli.use_color

        profiles = []

        try:
            active_profile = self.get_active_profile_name()

            for profile in self.get_config():
                if profile == Profile.config_profile:
                    continue
                elif profile == "DEFAULT":
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
            raise KsmCliException("Cannot get list of profiles. {}".format(err))

    def set_active(self, profile_name):

        common_config = self._get_common_config("Cannot set active profile.")

        if profile_name not in self.get_config():
            raise Exception("Cannot set profile {} to active. It does not exists.".format(profile_name))

        common_config[Profile.active_profile_key] = profile_name
        self.save()

        print("{} is now the active profile.".format(profile_name), file=sys.stderr)

    def export_config(self, profile_name=None, file_format='ini', plain=False):

        """Take a profile from an existing config and make it a stand-alone config.

        This is when you want to pull a single profile from a config and use it
        someplace else, like inside of a Docker image.

        """

        # If the profile name is not set, use the active profile.
        if profile_name is None:
            profile_name = self.get_active_profile_name()
        profile_config = self.get_profile_config(profile_name)

        config_str = Export(config=profile_config, file_format=file_format, plain=plain).run()

        self.cli.output(config_str)

    @staticmethod
    def _import_json_config(config_data, file=None, profile_name=None):

        if os.path.exists(file) and os.path.isfile(file):
            config = configparser.ConfigParser()
            config.read(file)
        else:
            config = Profile._init_config_file(profile_name=profile_name)

        if profile_name is None:
            profile_name = Profile.default_profile

        config[profile_name] = {
            "clientKey": "",
            "clientId": "",
            "privateKey": "",
            "appKey": "",
            "hostname": ""
        }

        for k, v in config_data.items():
            if v is None:
                continue
            config[profile_name][k] = v
        with open(file, 'w') as configfile:
            config.write(configfile)

    @staticmethod
    def import_config(config_base64, file=None, profile_name=None):

        """Take base64 config file and write it back to disk.
        """

        if file is None:
            file = Profile.default_ini_file

        config_data = base64.urlsafe_b64decode(config_base64.encode())

        is_json = False
        try:
            config_data = json.loads(config_data)
            is_json = True
        except json.JSONDecodeError as _:
            pass

        # If a JSON file was import, convert the JSON to a INI.
        if is_json is True:
            Profile._import_json_config(config_data, file, profile_name)
        # Else just save the INI
        else:
            with open(file, "w") as fh:
                fh.write(config_data.decode())
                fh.close()

        print("Imported config saved to profile {} at {}.".format(profile_name, file), file=sys.stderr)

    def set_color(self, on_off):
        common_config = self._get_common_config("Cannot set color settings.")
        common_config[Profile.color_key] = str(on_off)
        self.cli.use_color = on_off
        self.save()

    def set_cache(self, on_off):
        common_config = self._get_common_config("Cannot set record cache.")
        common_config[Profile.cache_key] = str(on_off)
        self.cli.use_color = on_off
        self.save()

    def set_record_type_dir(self, directory):
        common_config = self._get_common_config("Cannot set the record type directory.")
        if directory is None:
            del common_config[Profile.record_type_dir_key]
        else:
            if os.path.exists(directory) is False:
                raise FileNotFoundError(f"Cannot find the directory 'directory' for record type schemas.")
            common_config[Profile.record_type_dir_key] = str(directory)
        self.cli.record_type_dir = directory
        self.save()

    def set_editor(self, editor, use_blocking=None, process_name=None):
        common_config = self._get_common_config("Cannot set editor.")
        if editor is None:
            common_config.pop(Profile.editor_key, None)
            common_config.pop(Profile.editor_use_blocking_key, None)
            common_config.pop(Profile.editor_process_name_key, None)
        else:
            common_config[Profile.editor_key] = editor
            if use_blocking is not None:
                common_config[Profile.editor_use_blocking_key] = str(use_blocking)
            if process_name is not None:
                common_config[Profile.editor_process_name_key] = process_name
        self.cli.editor = editor
        self.cli.editor_use_blocking = use_blocking
        self.save()

    def show_config(self):
        common_config = self._get_common_config("Cannot show the config.")

        table = Table(use_color=self.cli.use_color)
        table.add_column("Config Item", data_color=Fore.GREEN)
        table.add_column("Value", data_color=Fore.YELLOW, allow_wrap=True)

        not_set_text = "-NOT SET-"
        table.add_row(["Active Profile", common_config.get(Profile.active_profile_key, not_set_text)])
        table.add_row(["Cache Enabled", common_config.get(Profile.cache_key, not_set_text)])
        table.add_row(["Color Enabled", common_config.get(Profile.color_key, not_set_text)])
        table.add_row(["Record Type Directory", common_config.get(Profile.record_type_dir_key, not_set_text)])
        table.add_row(["Editor", "{} ({})".format(
            common_config.get(Profile.editor_key, not_set_text),
            common_config.get(Profile.editor_process_name_key, "NA")
        )])
        table.add_row(["Editor Blocking", common_config.get(Profile.editor_use_blocking_key, not_set_text)])
        self.cli.output(table.get_string())
