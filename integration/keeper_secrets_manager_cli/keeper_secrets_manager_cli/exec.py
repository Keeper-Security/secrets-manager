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
import sys
import subprocess
from keeper_secrets_manager_cli.exception import KsmCliException
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.keeper_globals import logger_name
import re
import json
import logging


class Exec:

    def __init__(self, cli):
        self.cli = cli
        self.logger = logging.getLogger(logger_name)

        # Since the cli is short lived, this won't stick around long.
        self.local_cache = {}

    def _get_secret(self, notation):

        # If not in the cache, go get the secret and then store it in the cache.
        if notation not in self.local_cache:
            value = self.cli.client.get_notation(notation)
            if type(value) is dict or type(value) is list:
                value = json.dumps(value)
            self.local_cache[notation] = str(value)

        return self.local_cache[notation]

    def env_replace(self):

        for env_key, env_value in list(os.environ.items()):
            if env_value.startswith(SecretsManager.notation_prefix) is True:
                try:
                    os.environ["_" + env_key] = "_" + env_value
                    os.environ[env_key] = self._get_secret(env_value)
                except ValueError as err:
                    # TODO: Change the SDK to throw a different exception when might not be notation.
                    # If the notation isn't actually notation, skip it, don't raise an exception
                    if str(err).startswith("Keeper url missing"):
                        self.logger.info("Possible notation for env key {} was not used.".format(env_key))
                    else:
                        raise KsmCliException(str(err))

    def inline_replace(self, cmd=None):

        if cmd is None:
            cmd = []

        new_cmd = []
        for item in cmd:
            # Due to custom fields, that allow spaces in the label, we have not idea
            # where the notation ends.
            try:
                results = re.search(r'{}://.*?$'.format(SecretsManager.notation_prefix), item)
                if results is not None:
                    env_value = results.group()
                    item = item.replace(env_value, self._get_secret(env_value))
                new_cmd.append(item)
            except ValueError as err:
                # If the notation isn't actually notation, skip it, don't raise an exception
                if str(err).startswith("Keeper url missing"):
                    self.logger.info("Possible notation for inline param {} was not used.".format(item))
                else:
                    raise KsmCliException(str(err))
        cmd = new_cmd

        return cmd

    def execute(self, cmd, capture_output=False, inline=False):

        # Make a version of the command before replacing secrets. We don't want to expose them if
        # there is error.
        full_cmd = " ".join(cmd)

        if len(cmd) == 0:
            raise Exception("Cannot execute command, it's missing.")
        else:
            self.env_replace()

            if inline is True:
                cmd = self.inline_replace(cmd)

            # Python 3.6's subprocess.run does not have a capture flag. Instead it used the PIPE with
            # the stderr parameter.
            kwargs = {}
            if capture_output is True:
                if sys.version_info[0] == 3 and sys.version_info[1] < 7:
                    kwargs["stdout"] = subprocess.PIPE
                else:
                    kwargs["capture_output"] = capture_output

            try:
                completed = subprocess.run(cmd, **kwargs)
            except OSError as err:
                message = str(err)
                if (re.search(r'WinError 193', message) is not None and
                        re.search(r'\.ps1', full_cmd, re.IGNORECASE) is not None):
                    raise KsmCliException("Cannot execute command. If this was a powershell script, please use"
                                          " the command 'powershell {}'".format(full_cmd))
                else:
                    raise KsmCliException("Cannot execute command: {}".format(message))
            except Exception as err:
                raise KsmCliException("Cannot execute command: {}".format(err))

            if completed.returncode != 0:
                raise KsmCliException("Return code was: " + str(completed.returncode))
            if capture_output is True:
                print(completed.stdout)
