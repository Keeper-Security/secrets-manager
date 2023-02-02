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
#

from enum import Enum


class ConfigKeys(Enum):
    KEY_URL = 'url'                 # base url for the Secrets Manager service
    KEY_CLIENT_ID = 'clientId'
    KEY_CLIENT_KEY = 'clientKey'    # The key that is used to identify the client before public key. This is token.
    KEY_APP_KEY = 'appKey'          # The application key with which all secrets are encrypted
    KEY_OWNER_PUBLIC_KEY = 'appOwnerPublicKey'  # The application owner public key, to create records
    KEY_PRIVATE_KEY = 'privateKey'  # The client's private key
    KEY_SERVER_PUBLIC_KEY_ID = 'serverPublicKeyId'  # Which public key should be using?

    KEY_BINDING_TOKEN = 'bat'
    KEY_BINDING_KEY = 'bindingKey'
    KEY_HOSTNAME = 'hostname'

    @classmethod
    def get_enum(cls, value):
        for e in cls:
            # Check if the value passed is the value of the enum key, or the enum key itself.
            if e.value == value or e == value:
                return e
        return None
