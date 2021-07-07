from keepercommandersm import Commander
from keepercommandersm.storage import InMemoryKeyValueStorage
from keepercommandersm.configkeys import ConfigKeys
from .profile import Profile
import sys
import logging


class KeeperCli:

    @staticmethod
    def get_client(**kwargs):
        return Commander(**kwargs)

    def __init__(self, ini_file=None, profile_name=None, output=None):

        self.profile = Profile(cli=self, ini_file=ini_file)
        self._client = None

        self._log_level = "INFO"

        # If no config file is loaded, then don't init the SDK
        if self.profile.is_loaded is True:

            # If the profile is not set
            if profile_name is None:
                profile_name = self.profile.get_default_profile_name()

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
            config_storage.set(ConfigKeys.KEY_SERVER, self.config.get("server"))

            common_profile = self.profile.get_profile_config(Profile.common_profile)

            self._client = self.get_client(
                config=config_storage,
                log_level=common_profile.get("log_level", self._log_level)
            )
        else:
            # Set the log level. We don't have the client to set the level, so set it here.
            self.log_level = self._log_level

        # Default to stdout if the output is not set.
        if output is None:
            output = "stdout"

        if output == "stdout":
            self.output_fh = sys.stdout
        elif output == "stderr":
            self.output_fh = sys.stderr
        elif type(output) is str:
            self.output_fh = open(output, "w+")
        else:
            sys.exit("The output {} is not supported. Cannot display your information.".format(output))

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
        self.output_fh.write(msg)
        self.output_fh.flush()
