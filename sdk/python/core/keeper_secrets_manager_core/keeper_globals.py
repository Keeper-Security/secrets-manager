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
import re


def get_client_version():
    """Get the version of the client

    The version # comes from metadata. In a unit test, there is metadata, so the version will
    be the defined major and 0.0 (ie 16.0.0.).

    If installed, the method can get the real version number. For the client version number
    we use the defined major and minor and revision numbers of the module version.

    For example, module version of 0.1.23 would create a client version would be 16.1.23.

    We also need to remove any alpha characters from the revision since Python allows that.

    """
    # Get the version of the keeper secrets manager core
    version_major = "16"
    version = "{}.0.0".format(version_major)
    try:
        ksm_version = importlib_metadata.version("keeper-secrets-manager-core")
        version_parts = ksm_version.split(".")
        version_minor = version_parts[1]
        version_revision = re.search(r'^\d+', version_parts[2]).group()
        version = "{}.{}.{}".format(version_major, version_minor, version_revision)
    except importlib_metadata.PackageNotFoundError:
        # In a unit test or development run, not an installed version. Just use the default.
        pass
    except Exception as err:
        raise Exception(err)
    return version


keeper_secrets_manager_sdk_client_id = "mp{}".format(get_client_version())

keeper_public_keys = {
    '1': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
    '2': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
    '3': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
    '4': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
    '5': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
    '6': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
}

keeper_servers = {
    'US': 'keepersecurity.com',
    'EU': 'keepersecurity.eu',
    'AU': 'keepersecurity.com.au',
    'US_GOV': 'govcloud.keepersecurity.us'
}
