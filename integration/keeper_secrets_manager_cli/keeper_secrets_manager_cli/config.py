# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: sm@keepersecurity.com
#

import base64
import colorama
import configparser
import json
import logging
import platform
import os

from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.utils import set_config_mode, check_config_mode
from keeper_secrets_manager_cli.common import find_ksm_path
from keeper_secrets_manager_cli.exception import KsmCliException


class Config:

    """
    Provide a structure representation of the keeper.ini.

    Instead of using a bunch of dictionaries, use objects.
    Then use the attributes to hold data.
    """

    default_ini_file = os.environ.get("KSM_INI_FILE", "keeper.ini")
    default_profile = os.environ.get("KSM_CLI_PROFILE", "_default")
    CONFIG_KEY = "_config"

    def __init__(self, ini_file=None, base64_config=None):
        self.ini_file = ini_file
        self.base64_config = base64_config
        self.config = ConfigCommon()
        self.has_config_file = True

        # Was KSM launched from an application (like Windows or MacOS)
        self.launched_from_app = False

        if ini_file is None:
            self.has_config_file = False

        self._profiles = {}

        self.logger = logging.getLogger(logger_name)

    @staticmethod
    def is_windows():
        return True if platform.system() == "Windows" else False

    def clear(self):
        self._profiles = {}
        self.config = ConfigCommon()

    @staticmethod
    def create_from_json(json_config):
        config = Config()
        config.set_profile(Config.default_profile,
                           client_id=json_config.get("clientId"),
                           private_key=json_config.get("privateKey"),
                           app_key=json_config.get("appKey"),
                           hostname=json_config.get("hostname"),
                           app_owner_public_key=json_config.get("appOwnerPublicKey"),
                           server_public_key_id=json_config.get("serverPublicKeyId"))
        config.config.active_profile = Config.default_profile
        return config

    @staticmethod
    def get_default_ini_file(launched_from_app=False):
        working_directory = os.getcwd()

        # If launched from an application, the current working directory
        # might not be writeable. Use the user's "HOME" directory.
        if launched_from_app is True:
            if Config.is_windows() is True:
                working_directory = os.environ["USERPROFILE"]
            else:
                working_directory = os.environ["HOME"]
        default_ini_dir = os.environ.get("KSM_INI_DIR", working_directory)
        return os.path.join(default_ini_dir, Config.default_ini_file)

    @staticmethod
    def find_ini_config():
        file = find_ksm_path(Config.default_ini_file, is_file=True)
        return file

    def remove_file(self):
        if self.ini_file is not None:
            os.unlink(self.ini_file)

    def profile_list(self):
        return list(self._profiles.keys())

    def set_profile(self, name, **kwargs):
        self._profiles[name] = ConfigProfile(**kwargs)

    def get_profile(self, name):
        if name not in self._profiles:
            raise KsmCliException("The profile {} does not exist in the INI config.".format(name))
        return self._profiles[name]

    def set_profile_using_base64(self, profile_name, base64_config):

        # If the base64_config has already been decoded, then no need to
        # base64 decode.
        if base64_config.strip().startswith("{") is True:
            json_config = base64_config
        else:
            json_config = base64.urlsafe_b64decode(base64_config).decode()
        data = json.loads(json_config)
        kwargs = dict(
            client_id=data.get("clientId"),
            private_key=data.get("privateKey"),
            app_key=data.get("appKey"),
            hostname=data.get("hostname"),
            app_owner_public_key=data.get("appOwnerPublicKey"),
            server_public_key_id=data.get("serverPublicKeyId")
        )
        self.set_profile(profile_name, **kwargs)
        if self.config.active_profile is None:
            self.config.active_profile = profile_name

    def load(self):

        if self.ini_file is None:
            raise FileNotFoundError("Cannot find the Keeper INI file {}".format(Config.default_ini_file))
        elif os.path.exists(self.ini_file) is False:
            raise FileNotFoundError("Keeper INI files does not exists at {}".format(self.ini_file))

        # Make sure the user is allowed to access the configuration.
        check_config_mode(self.ini_file, color_mod=colorama, logger=self.logger)

        try:
            config = configparser.ConfigParser(allow_no_value=True)
            with open(self.ini_file, "r") as fh:
                config.read_file(fh)
                self.config = ConfigCommon(**config[Config.CONFIG_KEY])
                self._profiles = {}
                for profile_name in config.sections():
                    if profile_name == Config.CONFIG_KEY:
                        continue

                    self._profiles[profile_name] = self._load_config(config[profile_name])
        except PermissionError:
            raise PermissionError("Access denied to configuration file {}.".format(self.ini_file))
        except FileNotFoundError:
            raise PermissionError("Cannot find configuration file {}.".format(self.ini_file))

    def _load_config(self, section: configparser.SectionProxy):
        from keeper_secrets_manager_storage.storage_aws_secret import AwsConfigProvider

        storage = section.get("storage", "")
        if storage in ("", "internal"):
            return ConfigProfile(
                    client_id=section.get("clientid"),
                    private_key=section.get("privatekey"),
                    app_key=section.get("appkey"),
                    hostname=section.get("hostname"),
                    app_owner_public_key=section.get("appownerpublickey"),
                    server_public_key_id=section.get("serverpublickeyid"))
        elif storage == "aws":
            cfg = ConfigProfile(storage=storage)
            cfg.storage_config = {x: section.get(x) for x in section.keys() if x != "storage"}

            provider = cfg.storage_config.get("provider", "") or "ec2instance"
            secret = cfg.storage_config.get("secret", "") or "ksm-config"
            fallback = cfg.storage_config.get("fallback", True) or True

            awsp = AwsConfigProvider(secret)
            if provider == "ec2instance":
                awsp.from_ec2instance_config(secret, fallback)
            elif provider == "profile":
                profile = cfg.storage_config.get("profile", "") or ""
                if profile:
                    awsp.from_profile_config(secret, profile, fallback)
                else:
                    awsp.from_default_config(secret, fallback)
            elif provider == "keys":
                aws_access_key_id = cfg.storage_config.get("aws_access_key_id", "") or ""
                aws_secret_access_key = cfg.storage_config.get("aws_secret_access_key", "") or ""
                region = cfg.storage_config.get("region", "") or ""
                awsp.from_custom_config(secret, aws_access_key_id, aws_secret_access_key, region, fallback)
            else:
                raise KsmCliException(f"Failed to load profile from AWS secret - unknown provider '{provider}'")

            ksmcfg = awsp.read_config()
            if not ksmcfg:
                raise KsmCliException(f"Failed to load profile from AWS secret '{secret}'")

            config_storage = InMemoryKeyValueStorage(ksmcfg)
            cfg.client_id = config_storage.get(ConfigKeys.KEY_CLIENT_ID)
            cfg.private_key = config_storage.get(ConfigKeys.KEY_PRIVATE_KEY)
            cfg.app_key = config_storage.get(ConfigKeys.KEY_APP_KEY)
            cfg.hostname = config_storage.get(ConfigKeys.KEY_HOSTNAME)
            cfg.app_owner_public_key = config_storage.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY)
            cfg.server_public_key_id = config_storage.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID)

            return cfg
        else:
            raise KsmCliException("Unknown profile storage '{storage}' - please update KSM CLI")

    def save(self):
        if self.has_config_file is True:

            # Check if the file exists
            file_exists = os.path.exists(self.ini_file)

            config = configparser.ConfigParser(allow_no_value=True)
            config[Config.CONFIG_KEY] = self.config.to_dict()
            for profile in self._profiles:
                config[profile] = self._profiles[profile].to_dict()

            with open(self.ini_file, 'w') as fh:
                config.write(fh)
                fh.close()

            # If the file exists, don't change the permissions.
            if file_exists is False:
                set_config_mode(self.ini_file, logger=self.logger)

    def to_dict(self):
        return {
            "config": self.config.to_dict(),
            "profiles": [self._profiles[x].to_dict() for x in self._profiles]
        }


class ConfigCommon:

    def __init__(self, **kwargs):
        self.active_profile = kwargs.get("active_profile")
        self.color = kwargs.get("color", True)
        self.cache = kwargs.get("cache", False)
        self.record_type_dir = kwargs.get("record_type_dir")
        self.editor = kwargs.get("editor")
        self.editor_use_blocking = kwargs.get("editor_use_blocking", False)
        self.editor_process_name = kwargs.get("editor_process_name")

    def to_dict(self):

        return {
            "active_profile": self.active_profile,
            "color": str(self.color),
            "cache": str(self.cache),
            "record_type_dir": self.record_type_dir,
            "editor": self.editor,
            "editor_use_blocking": str(self.editor_use_blocking),
            "editor_process_name": self.editor_process_name
        }


class ConfigProfile:

    def __init__(self, **kwargs):
        # storage: internal|aws|azure|gcp - only internal is exportable
        self.storage = kwargs.get("storage", "internal")
        self.storage_config = kwargs.get("storage_config", {})
        self.client_id = kwargs.get("client_id")
        self.private_key = kwargs.get("private_key")
        self.app_key = kwargs.get("app_key")
        self.hostname = kwargs.get("hostname")
        self.app_owner_public_key = kwargs.get("app_owner_public_key")
        self.server_public_key_id = kwargs.get("server_public_key_id")

    def to_dict(self):
        result = {
            # "storage": self.storage,  # removed for legacy compatibility
            "clientid": self.client_id,
            "privatekey": self.private_key,
            "appkey": self.app_key,
            "hostname": self.hostname,
            "appownerpublickey": self.app_owner_public_key,
            "serverpublickeyid": self.server_public_key_id
        }

        if self.storage and self.storage != "internal":
            result = {"storage": self.storage}
            if self.storage_config:
                result.update(self.storage_config)

        return result
