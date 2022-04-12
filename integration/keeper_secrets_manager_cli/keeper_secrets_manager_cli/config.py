from keeper_secrets_manager_cli.common import find_ksm_path
from keeper_secrets_manager_cli.exception import KsmCliException
import configparser
import os
import base64
import json


class Config:

    """
    Provide a structure representation of the keeper.ini.

    Instead of using a bunch of dictionaries, use objects. Then use the attributes to hold data.
    """

    default_ini_file = os.environ.get("KSM_INI_FILE", "keeper.ini")
    default_profile = os.environ.get("KSM_CLI_PROFILE", "_default")
    CONFIG_KEY = "_config"

    def __init__(self, ini_file=None, base64_config=None):
        self.ini_file = ini_file
        self.base64_config = base64_config
        self.config = ConfigCommon()
        self.has_config_file = True
        if ini_file is None:
            self.has_config_file = False

        self._profiles = {}

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
    def get_default_ini_file():
        default_ini_dir = os.environ.get("KSM_INI_DIR", os.getcwd())
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

        config = configparser.ConfigParser(allow_no_value=True)
        config.read(self.ini_file)
        self.config = ConfigCommon(**config[Config.CONFIG_KEY])
        self._profiles = {}
        for profile_name in config.sections():
            if profile_name == Config.CONFIG_KEY:
                continue

            self._profiles[profile_name] = ConfigProfile(
                client_id=config[profile_name].get("clientid"),
                private_key=config[profile_name].get("privatekey"),
                app_key=config[profile_name].get("appkey"),
                hostname=config[profile_name].get("hostname"),
                app_owner_public_key=config[profile_name].get("appownerpublickey"),
                server_public_key_id=config[profile_name].get("serverpublickeyid"))

    def save(self):
        if self.has_config_file is True:
            config = configparser.ConfigParser(allow_no_value=True)
            config[Config.CONFIG_KEY] = self.config.to_dict()
            for profile in self._profiles:
                config[profile] = self._profiles[profile].to_dict()

            with open(self.ini_file, 'w') as fh:
                config.write(fh)
                fh.close()

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
        self.client_id = kwargs.get("client_id")
        self.private_key = kwargs.get("private_key")
        self.app_key = kwargs.get("app_key")
        self.hostname = kwargs.get("hostname")
        self.app_owner_public_key = kwargs.get("app_owner_public_key")
        self.server_public_key_id = kwargs.get("server_public_key_id")

    def to_dict(self):
        return {
            "clientid": self.client_id,
            "privatekey": self.private_key,
            "appkey": self.app_key,
            "hostname": self.hostname,
            "appownerpublickey": self.app_owner_public_key,
            "serverpublickeyid": self.server_public_key_id
        }
