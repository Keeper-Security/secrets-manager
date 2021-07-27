#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com

import importlib_metadata

# Get the version of the keeper secrets manager core
version = "16.0.0"
try:
    version = importlib_metadata.version("keeper-secrets-manager-core")
except importlib_metadata.PackageNotFoundError:
    # In a unit test or development run, not an installed version
    pass
except Exception as err:
    raise Exception(err)
keeper_secrets_manager_sdk_client_id = "mp{}".format(version)

keeper_server_public_key_raw_string = \
    'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'

keeper_servers = {
    'US': 'keepersecurity.com',
    'EU': 'keepersecurity.eu',
    'AU': 'keepersecurity.com.au',
    'US_GOV': 'govcloud.keepersecurity.us'
}
