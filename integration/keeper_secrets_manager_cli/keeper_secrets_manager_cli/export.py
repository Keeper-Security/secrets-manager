# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from .config import Config
import tempfile
import base64
import json
import os

from keeper_secrets_manager_core.utils import base64_to_bytes
from keeper_secrets_manager_core.keeper_globals import keeper_servers
from .exception import KsmCliException


class Export:

    """
    Export a specific profile config
    """

    def __init__(self, config, file_format=None, plain=False):
        # To prevent exposing cloud based secrets
        # only configurations stored internally can be exported
        if config.storage not in (None, "", "internal"):
            raise KsmCliException(
                "Only configurations stored internally can be exported. "
                f" Current profile has storage={config.storage}")

        # If the JSON dictionary is passed in convert it to a Config
        if isinstance(config, dict) is True:
            config = Config.create_from_json(config).get_profile(Config.default_profile)

        self.config = config
        self.file_format = file_format
        self.plain = plain

    def run(self):

        config_str = None
        if self.file_format == "ini":
            config_str = self._format_ini()
        elif self.file_format == "json":
            config_str = self._format_json()

        if self.plain is False:
            if type(config_str) is str:
                config_str = config_str.encode()

            config_str = base64.urlsafe_b64encode(config_str)

        return config_str

    def _format_ini(self):

        from .profile import Profile

        # Apparently the config parser doesn't like temp files. So create a
        # temp file, then open a file for writing and use that to write
        # the config. Then read the temp file to get our new config.

        temp_file_name = None
        try:
            # Create temp file and close it. We want a filename. Prevent the temp file from being deleted
            # when we close it. Remove it with a "finally".
            tf = tempfile.NamedTemporaryFile(delete=False)
            temp_file_name = tf.name
            tf.close()

            # Make a configuration with one profile and the save it to the temp file.
            config = Config(ini_file=temp_file_name)
            config.set_profile(Profile.default_profile,
                               client_id=self.config.client_id,
                               private_key=self.config.private_key,
                               app_key=self.config.app_key,
                               hostname=self.config.hostname,
                               app_owner_public_key=self.config.app_owner_public_key,
                               server_public_key_id=self.config.server_public_key_id)
            config.config.active_profile = Profile.default_profile
            config.save()

            # Open the temp file and read the configuration that was created above.
            with open(temp_file_name, "r") as config_fh:
                config_str = config_fh.read()
                config_fh.close()
        except Exception as err:
            raise KsmCliException("Could not export profile: {}".format(err))
        finally:
            # Make sure we delete the temp file.
            if temp_file_name is not None and os.path.exists(temp_file_name) is True:
                os.unlink(temp_file_name)

        return config_str

    def _format_json(self):

        def _base64(value):
            if value is not None:
                value_bytes = base64_to_bytes(value)
                value = base64.b64encode(value_bytes).decode()
            return value

        config_dict = {
            "clientId": _base64(self.config.client_id),
            "privateKey": _base64(self.config.private_key),
            "appKey": _base64(self.config.app_key),
            "hostname": keeper_servers.get(self.config.hostname, self.config.hostname),
            "serverPublicKeyId": self.config.server_public_key_id,
            "appOwnerPublicKey": self.config.app_owner_public_key
        }

        return json.dumps(config_dict, indent=4)
