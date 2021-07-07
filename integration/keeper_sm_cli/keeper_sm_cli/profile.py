import os
import configparser
from keepercommandersm.storage import InMemoryKeyValueStorage
from keepercommandersm.configkeys import ConfigKeys
from keepercommandersm.exceptions import KeeperError, KeeperAccessDenied
import prettytable
import sys
import json


class Profile:

    common_profile = "common"
    active_profile_key = "active_profile"
    default_profile = os.environ.get("KEEPER_CLI_PROFILE", "DEFAULT")
    default_ini_file = os.environ.get("KEEPER_INI_FILE", "keeper.ini")
    log_level_key = "log_level"

    def __init__(self, cli, ini_file=None):

        self.cli = cli

        # If the INI file is not set, find it.
        if ini_file is None:
            ini_file = Profile.find_ini_config()

            # If we can't find it, and the KEEPER_SECRET_KEY env is set, auto create it. We do this because
            # this might be a container startup and there is not INI file, but we have passed in the client key.
            client_key = os.environ.get("KEEPER_SECRET_KEY")
            if client_key is not None:
                Profile.init(
                    client_key=client_key,
                    server=os.environ.get("KEEPER_SERVER", "US")
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
            [os.environ.get("KEEPER_INI_DIR", not_set)],
            [os.getcwd()],

            # Linux
            [os.environ.get("HOME", not_set)],
            ["", "etc"],
            ["", "etc", "keeper"],

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

    def get_default_profile_name(self):
        profile_config = self.get_profile_config(Profile.common_profile)
        return os.environ.get("KEEPER_CLI_PROFILE", profile_config.get(Profile.active_profile_key))

    @staticmethod
    def _table_setup(table):
        table.align = 'l'
        table.horizontal_char = "="
        table.vertical_char = " "
        table.junction_char = " "
        table.hrules = prettytable.HEADER

    @staticmethod
    def init(client_key, ini_file=None, server=None, profile_name=None, log_level="INFO"):

        from . import KeeperCli

        # If the ini is not set, default the file in the current directory.
        if ini_file is None:
            ini_file = os.path.join(
                os.environ.get("KEEPER_INI_DIR", os.getcwd()),
                Profile.default_ini_file
            )

        if profile_name is None:
            profile_name = os.environ.get("KEEPER_CLI_PROFILE", Profile.default_profile)

        if profile_name == Profile.common_profile:
            raise ValueError("The profile '{}' is a reserved profile name. Cannot not init profile.".format(
                profile_name))

        config = configparser.ConfigParser()

        # We want to flag if we create a INI file. If there is an error, remove it so it
        # doesn't get picked up if we try again.
        created_ini = False

        # If the ini file doesn't exists, create it with the common profile
        if os.path.exists(ini_file) is False:
            config[Profile.default_profile] = {}
            config[Profile.common_profile] = {
                "log_level": log_level,
                Profile.active_profile_key: Profile.default_profile
            }
            with open(ini_file, 'w') as configfile:
                config.write(configfile)
            created_ini = True
        else:
            config.read(ini_file)

        config_storage = InMemoryKeyValueStorage()
        config_storage.set(ConfigKeys.KEY_CLIENT_KEY, client_key)
        if server is not None:
            config_storage.set(ConfigKeys.KEY_SERVER, server)

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
            "server": ""
        }

        for k, v in config_storage.config.items():
            if v is None:
                continue
            config[profile_name][k.value] = v
        with open(ini_file, 'w') as configfile:
            config.write(configfile)

        print("Added profile {} to INI config file located at {}".format(profile_name, ini_file), file=sys.stderr)

    def list_profiles(self, output='text'):

        profiles = []
        active_profile = self.get_default_profile_name()
        for profile in self.get_config():
            if profile == Profile.common_profile:
                continue
            profiles.append({
                "active": profile == active_profile,
                "name": profile
            })

        if output == 'text':
            table = prettytable.PrettyTable()
            table.field_names = ["Active", "Profile"]
            Profile._table_setup(table)

            for profile in profiles:
                table.add_row(["*" if profile["active"] is True else " ", profile["name"]])

            # TODO: Why won't this work with self.cli.output
            self.cli.output(table.get_string() + "\n")
        elif output == 'json':
            self.cli.output(json.dumps(profiles))
        return profiles

    def set_active(self, profile_name):
        common_config = self.get_profile_config(Profile.common_profile)

        if profile_name not in self.get_config():
            exit("Cannot set profile {} to active. It does not exists.".format(profile_name))

        common_config[Profile.active_profile_key] = profile_name
        self.save()

        print("{} is now the active profile.".format(profile_name), file=sys.stderr)

    def set_log_level(self, level):
        common_config = self.get_profile_config(Profile.common_profile)
        common_config[Profile.log_level_key] = level
        self.cli.log_level = level
        self.save()

    def show_config(self):
        common_config = self.get_profile_config(Profile.common_profile)
        not_set_text = "-NOT SET-"
        print("Active Profile: {}".format(common_config.get(Profile.active_profile_key, not_set_text)))
        print("Log Level: {}".format(common_config.get(Profile.log_level_key, not_set_text)))
