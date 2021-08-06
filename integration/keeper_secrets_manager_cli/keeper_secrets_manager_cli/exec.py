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
from keeper_secrets_manager_core.core import SecretsManager
import re
import json


class Exec:

    def __init__(self, cli):
        self.cli = cli

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
                os.environ["_" + env_key] = "_" + env_value
                os.environ[env_key] = self._get_secret(env_value)

    def inline_replace(self, cmd=None):

        if cmd is None:
            cmd = []

        new_cmd = []
        for item in cmd:
            # Due to custom fields, that allow spaces in the label, we have not idea
            # where the notation ends.
            results = re.search(r'{}://.*?$'.format(SecretsManager.notation_prefix), item)
            if results is not None:
                env_value = results.group()
                item = item.replace(env_value, self._get_secret(env_value))
            new_cmd.append(item)
        cmd = new_cmd

        return cmd

    def execute(self, cmd, capture_output=False, inline=False):

        # Make a version of the command before replacing secrets. We don't want to expose them if
        # there is error.
        full_cmd = " ".join(cmd)

        if len(cmd) == 0:
            sys.stderr.write("Cannot execute command, it's missing.\n")
            sys.exit(1)
        else:
            self.env_replace()

            if inline is True:
                cmd = self.inline_replace(cmd)

            # Python 3.6's subprocess.run does not have a capture flag. Instead it used the PIPE with
            # the stderr parameter.
            kwargs = {}
            if (sys.version_info[0] == 3 and sys.version_info[1] < 7) and capture_output is True:
                kwargs["stdout"] = subprocess.PIPE
            else:
                kwargs["capture_output"] = capture_output

            try:
                completed = subprocess.run(cmd, **kwargs)
            except OSError as err:
                message = str(err)
                if (re.search(r'WinError 193', message) is not None and
                        re.search(r'\.ps1', full_cmd, re.IGNORECASE) is not None):
                    sys.exit("Cannot execute command. If this was a powershell script, please use the command"
                             " 'powershell {}'".format(full_cmd))
                else:
                    sys.exit("Cannot execute command: {}".format(message))
            except Exception as err:
                sys.exit("Cannot execute command: {}".format(err))

            if completed.returncode != 0:
                exit(completed.returncode)
            if capture_output is True:
                print(completed.stdout)
