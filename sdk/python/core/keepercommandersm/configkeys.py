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
    KEY_URL = 'url'                 # base url for the Secrets Manager service
    KEY_CLIENT_ID = 'clientId'
    KEY_CLIENT_KEY = 'clientKey'    # The key that is used to identify the client before public key
    KEY_APP_KEY = 'appKey'          # The application key with which all secrets are encrypted
    KEY_PRIVATE_KEY = 'privateKey'  # The client's private key

    KEY_BINDING_TOKEN = 'bat'
    KEY_BINDING_KEY = 'bindingKey'
    KEY_SERVER = 'server'
