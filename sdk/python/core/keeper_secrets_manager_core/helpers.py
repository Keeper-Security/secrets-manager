# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2023 Keeper Security Inc.
# Contact: sm@keepersecurity.com
import json
import logging
import os
from urllib.parse import urlparse

from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import keeper_servers, logger_name
from keeper_secrets_manager_core.storage import KeyValueStorage


def get_server(code_server, config_store: KeyValueStorage):

    env_server = os.getenv('KSM_HOSTNAME')

    if env_server:
        server_to_use = env_server
    elif config_store.get(ConfigKeys.KEY_HOSTNAME):
        server_to_use = config_store.get(ConfigKeys.KEY_HOSTNAME)
    elif code_server:
        server_to_use = code_server
    else:
        server_to_use = keeper_servers.get('US')

    if server_to_use in keeper_servers:
        # Server key was supplied
        server_to_return = keeper_servers.get(server_to_use)
    else:
        # Looks like an URL
        # Un-parsing URL to get only domain:
        if 'http' not in server_to_use:
            server_to_use = 'https://%s' % server_to_use

        server_to_return = urlparse(server_to_use).netloc

    logging.getLogger(logger_name).debug("Keeper hostname %s" % server_to_return)

    return server_to_return


def is_json(json_str):
    try:
        json.loads(json_str)
    except ValueError as e:
        return False

    return True


def obj_to_dict(obj):
    return json.loads(
        json.dumps(obj, default=lambda o: getattr(o, '__dict__', str(o)))
    )


def get_folder_key(folder_uid, secrets_and_folders):

    folders = secrets_and_folders.folders

    for f in folders:
        if f.uid == folder_uid:
            return f

    return None
