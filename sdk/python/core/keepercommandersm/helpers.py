#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import logging
import os
from urllib.parse import urlparse

from keeper_globals import keeper_servers
from keepercommandersm.configkeys import ConfigKeys
from keepercommandersm.storage import KeyValueStorage


def get_server(code_server, config_store: KeyValueStorage):

    env_server = os.getenv('KEEPER_SERVER')

    if env_server:
        server_to_use = env_server
    elif config_store.get(ConfigKeys.KEY_SERVER):
        server_to_use = config_store.get(ConfigKeys.KEY_SERVER)
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

    logging.debug("Keeper server %s" % server_to_return)

    return server_to_return
