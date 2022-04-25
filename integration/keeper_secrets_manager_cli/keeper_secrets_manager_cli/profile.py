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
from keeper_secrets_manager_cli.exception import KsmCliException
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.exceptions import KeeperError, KeeperAccessDenied
from .table import Table, ColumnAlign
from .export import Export
from .config import Config
from .common import find_ksm_path
from colorama import Fore
import sys
import json
import base64


class Profile:

    default_profile = os.environ.get("KSM_CLI_PROFILE", "_default")

    def __init__(self, cli, ini_file=None, config=None):

        self.cli = cli
        self.ini_file = None
        self.has_profiles = False

        if config is not None:
            self._config = config
        else:
            self._config = Config()

        if ini_file is not None:
            self._config = Config(ini_file=ini_file)
            self._config.load()
            self.ini_file = self._config
        # Else try to find it
        else:
            if os.environ.get("KSM_CONFIG") is not None:
                self._config.set_profile_using_base64(Profile.default_profile, os.environ.get("KSM_CONFIG"))
            elif os.environ.get("KSM_CONFIG_BASE64_1") is not None:
                self._auto_config_from_env_var(self._config)
            elif os.environ.get("KSM_TOKEN") is not None:
                Profile.init(
                    token=os.environ.get("KSM_TOKEN"),
                    server=os.environ.get("KSM_HOSTNAME", "US")
                )
            else:
                ini_file = find_ksm_path(Config.default_ini_file)
                if ini_file is not None:
                    self._config.ini_file = ini_file
                    self._config.has_config_file = True
                    self._config.load()

        self.has_profiles = len(self._config.profile_list()) > 0

    @staticmethod
    def _auto_config_from_env_var(config):

        """Build config from a Base64 config in environmental variables.

        """

        index = 1
        while True:
            config_base64 = os.environ.get("KSM_CONFIG_BASE64_{}".format(index))
            if config_base64 is not None:
                profile_name = os.environ.get("KSM_CONFIG_BASE64_DESC_{}".format(index), "App{}".format(index))
                config.set_profile_using_base64(profile_name, config_base64)
            else:
                break
            index += 1
        config.config.active_profile = os.environ.get("KSM_CONFIG_BASE64_DESC_1", "App1")

    def get_active_profile_name(self):
        return os.environ.get("KSM_CLI_PROFILE", self._config.config.active_profile)

    def get_profile_config(self, profile_name):
        return self._config.get_profile(profile_name)

    def get_common_config(self):
        return self._config.config

    @staticmethod
    def init(token, ini_file=None, server=None, profile_name=None):

        from . import KeeperCli

        # If the ini is not set, default the file in the current directory.
        if ini_file is None:
            ini_file = Config.get_default_ini_file()

        if profile_name is None:
            profile_name = os.environ.get("KSM_CLI_PROFILE", Profile.default_profile)

        if profile_name == Config.CONFIG_KEY:
            raise KsmCliException("The profile '{}' is a reserved profile name. Cannot not init profile.".format(
                profile_name))

        config = Config(ini_file=ini_file)

        if os.path.exists(ini_file) is True:
            config.load()

        # We want to flag if we create a INI file. If there is an error, remove it so it
        # doesn't get picked up if we try again.
        created_ini = False

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

        config_storage = client.config

        config.set_profile(profile_name,
                           client_id=config_storage.get(ConfigKeys.KEY_CLIENT_ID),
                           private_key=config_storage.get(ConfigKeys.KEY_PRIVATE_KEY),
                           app_key=config_storage.get(ConfigKeys.KEY_APP_KEY),
                           hostname=config_storage.get(ConfigKeys.KEY_HOSTNAME),
                           app_owner_public_key=config_storage.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY),
                           server_public_key_id=config_storage.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID))

        if config.config.active_profile is None:
            config.config.active_profile = profile_name

        config.save()

        print("Added profile {} to INI config file located at {}".format(profile_name, ini_file), file=sys.stderr)

    def list_profiles(self, output='text', use_color=None):

        if use_color is None:
            use_color = self.cli.use_color

        profiles = []

        try:
            for profile in self._config.profile_list():
                profiles.append({
                    "active": profile == self._config.config.active_profile,
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

        if self._config.get_profile(profile_name) is None:
            raise KsmCliException("Profile {} does not exists.".format(profile_name))

        self._config.config.active_profile = profile_name
        self._config.save()

        print("{} is now the active profile.".format(profile_name), file=sys.stderr)

    def export_config(self, profile_name=None, file_format='ini', plain=False):

        """Take a profile from an existing config and make it a stand-alone config.

        This is when you want to pull a single profile from a config and use it
        someplace else, like inside of a Docker image.

        """

        # If the profile name is not set, use the active profile.
        if profile_name is None:
            profile_name = self._config.config.active_profile
        profile_config = self._config.get_profile(profile_name)

        config_str = Export(config=profile_config, file_format=file_format, plain=plain).run()

        self.cli.output(config_str)

    @staticmethod
    def import_config(config_base64, file=None, profile_name=None):

        """
        Take base64 config file and write it back to disk.

        This file could be a JSON or a Keeper ini file.

        """

        config_data = base64.urlsafe_b64decode(config_base64.encode())

        # Check if the data is JSON
        is_json = False
        try:
            config_data = json.loads(config_data)
            is_json = True
        except json.JSONDecodeError as _:
            pass

        if file is None:
            file = Config.get_default_ini_file()

        # If a JSON file was import, convert the JSON to a INI.
        if is_json is True:
            config = Config(ini_file=file)
            config.set_profile_using_base64(
                profile_name=Profile.default_profile,
                base64_config=config_base64
            )
            config.save()

        # Else just save the INI. It's in the right format, just save it. No processing needed.
        else:
            with open(file, "w") as fh:
                fh.write(config_data.decode())
                fh.close()

        print("Imported config saved to profile {} at {}.".format(profile_name, file), file=sys.stderr)

    def set_color(self, on_off):
        common_config = self._config.config
        common_config.color = str(on_off)
        self.cli.use_color = on_off
        self._config.save()

    def set_cache(self, on_off):
        common_config = self._config.config
        common_config.cache = str(on_off)
        self.cli.use_cache = on_off
        self._config.save()

    def set_record_type_dir(self, directory):
        common_config = self._config.config
        if directory is None:
            common_config.record_type_dir = None
        else:
            if os.path.exists(directory) is False:
                raise FileNotFoundError(f"Cannot find the directory 'directory' for record type schemas.")
            common_config.record_type_dir = str(directory)
        self.cli.record_type_dir = directory
        self._config.save()

    def set_editor(self, editor, use_blocking=None, process_name=None):
        common_config = self._config.config
        if editor is None:
            common_config.editor = None
            common_config.editor_use_blocking = False
            common_config.editor_process_name = None
        else:
            common_config.editor = editor
            if use_blocking is not None:
                common_config.editor_use_blocking = str(use_blocking)
            if process_name is not None:
                common_config.editor_process_name = process_name
        self.cli.editor = editor
        self.cli.editor_use_blocking = use_blocking
        self._config.save()

    def show_config(self):

        def _check_set(value):
            if value is None:
                return "-NOT SET-"
            return value

        common_config = self._config.config

        table = Table(use_color=self.cli.use_color)
        table.add_column("Config Item", data_color=Fore.GREEN)
        table.add_column("Value", data_color=Fore.YELLOW, allow_wrap=True)

        table.add_row(["Active Profile", _check_set(common_config.active_profile)])
        table.add_row(["Cache Enabled", _check_set(common_config.cache)])
        table.add_row(["Color Enabled", _check_set(common_config.color)])
        table.add_row(["Record Type Directory", _check_set(common_config.record_type_dir)])
        table.add_row(["Editor", "{} ({})".format(_check_set(common_config.editor),
                                                  _check_set(common_config.editor_process_name))])
        table.add_row(["Editor Blocking", _check_set(common_config.editor_use_blocking)])
        self.cli.output(table.get_string())
