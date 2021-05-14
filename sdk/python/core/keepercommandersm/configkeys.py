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
from enum import Enum


class ConfigKeys(Enum):
    KEY_URL = 'url'
    KEY_CLIENT_ID = 'clientId'
    KEY_SECRET_KEY = 'secretKey'
    KEY_MASTER_KEY = 'masterKey'
    KEY_PRIVATE_KEY = 'privateKey'

    KEY_BINDING_TOKEN = 'bat'
    KEY_BINDING_KEY = 'bindingKey'
    KEY_SERVER = 'server'
