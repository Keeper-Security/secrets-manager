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

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.core import KSMCache
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_cli.common import find_ksm_path
from keeper_secrets_manager_cli.exception import KsmCliException
from keeper_secrets_manager_helper.record_type import RecordType
from keeper_secrets_manager_core.utils import strtobool
from .exception import KsmCliException
from .profile import Profile
from .config import Config
import sys
import os


class KeeperCli:

    @staticmethod
    def get_client(**kwargs):
        return SecretsManager(**kwargs)

    def __init__(self, ini_file=None, profile_name=None, output=None, use_color=None, use_cache=None,
                 record_type_dir=None, editor=None, editor_use_blocking=False, editor_process_name=None,
                 global_config=None, log_level=None):

        self.log_level = os.environ.get("KSM_DEBUG", log_level)
        # If set via the command line, make sure the environmental variable gets set.
        if self.log_level is not None:
            os.environ["KSM_DEBUG"] = self.log_level

        self.profile = Profile(cli=self, ini_file=ini_file, config=global_config)
        self._client = None

        self.use_color = use_color
        self.record_type_dir = record_type_dir

        # The editor to launch ... however this might be a bat or cmd file, not the real application
        self.editor = editor
        # Some applications don't block. To enabling blocking the CLI, set this to True
        self.editor_use_blocking = editor_use_blocking
        # Blocking might be waiting until a process in the task list goes away. This is that process.
        self.editor_process_name = editor_process_name

        self.use_cache = use_cache

        # If we have profiles
        if self.profile.has_profiles is True:

            # If the profile is not set
            if profile_name is None:
                profile_name = self.profile.get_active_profile_name()

                # If we don't have a profile we can't do anything.
                if profile_name is None:
                    raise ValueError("Cannot determine the active profile.")

            self.config = self.profile.get_profile_config(profile_name)

            config_storage = InMemoryKeyValueStorage()
            config_storage.set(ConfigKeys.KEY_CLIENT_ID, self.config.client_id)
            config_storage.set(ConfigKeys.KEY_PRIVATE_KEY, self.config.private_key)
            config_storage.set(ConfigKeys.KEY_APP_KEY, self.config.app_key)
            config_storage.set(ConfigKeys.KEY_HOSTNAME, self.config.hostname)
            config_storage.set(ConfigKeys.KEY_OWNER_PUBLIC_KEY, self.config.app_owner_public_key)

            common_config = self.profile.get_common_config()

            # Get the active configuration

            # By default, don't use the cache.
            if self.use_cache is None:
                self.use_cache = bool(strtobool(str(common_config.cache)))

            try:
                self._client = self.get_client(
                    config=config_storage,
                    log_level=self.log_level,
                    custom_post_function=KSMCache.caching_post_function if self.use_cache is True else None
                )
            except Exception as err:
                raise KsmCliException(str(err))

            # By default, use colors.
            if self.use_color is None:
                self.use_color = bool(strtobool(str(common_config.color)))

            if self.record_type_dir is None:
                self.record_type_dir = common_config.record_type_dir
                if self.record_type_dir is None:
                    self.record_type_dir = find_ksm_path("record_type", is_file=False)

            # If they have a directory where record type schema files may exist, attempt to load
            # them.
            if self.record_type_dir is not None and os.path.exists(self.record_type_dir) is True:
                RecordType.find_and_load_record_type_schema_files(self.record_type_dir)

            # Get the editor to use for visual editing a record
            if self.editor is None:
                self.editor = common_config.editor
            self.editor_use_blocking = bool(strtobool(str(common_config.editor_use_blocking)))
            self.editor_process_name = common_config.editor_process_name
        else:
            # Set the log level. We don't have the client to set the level, so set it here.
            if use_color is None:
                self.use_color = True

        # Default to stdout if the output is not set.
        if output is None:
            output = "stdout"
        self.output_name = output

    @property
    def client(self):
        if self._client is None:
            raise KsmCliException("The Keeper SDK client has not been loaded. The INI config might not be set.")
        return self._client

    @client.setter
    def client(self, value):
        self._client = value

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
