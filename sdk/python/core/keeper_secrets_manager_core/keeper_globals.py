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

from importlib.metadata import version as _get_pkg_version, PackageNotFoundError
import re

logger_name = 'ksm'


def get_client_version(hardcode=False):
    """Get the version of the client

    Primary source: Package __version__ attribute from _version.py (single source of truth)
    Fallback: importlib.metadata (for edge cases with broken installs)
    Default: Hardcoded version for unit tests or when both fail

    The client version uses the major.minor.revision format (e.g., 17.1.0).
    We remove any alpha characters from the revision since Python allows that (e.g., 17.1.0a0 -> 17.1.0).

    This fixes KSM-749: Previous implementation relied solely on importlib_metadata which could
    pick up stale .dist-info directories from previous installations, causing "invalid client
    version id" errors from the backend.
    """
    # Default version for hardcode mode or when all detection methods fail
    version_major = "17"
    version_minor_default = "2"
    version_revision_default = "0"
    version = "{}.{}.{}".format(version_major, version_minor_default, version_revision_default)

    # Allow the default version to be hard coded
    if hardcode is False:
        # Primary: Try to get version from package __version__ attribute (single source of truth)
        try:
            from keeper_secrets_manager_core._version import __version__
            version_parts = __version__.split(".")
            if len(version_parts) >= 3:
                version_minor = version_parts[1]
                version_revision = re.search(r'^\d+', version_parts[2]).group()
                version = "{}.{}.{}".format(version_major, version_minor, version_revision)
                return version
        except (ImportError, AttributeError, IndexError, ValueError):
            # If __version__ isn't available, fall back to importlib_metadata
            pass

        # Fallback: Try importlib.metadata (for edge cases with broken installs)
        try:
            ksm_version = _get_pkg_version("keeper-secrets-manager-core")
            version_parts = ksm_version.split(".")
            version_minor = version_parts[1]
            version_revision = re.search(r'^\d+', version_parts[2]).group()
            version = "{}.{}.{}".format(version_major, version_minor, version_revision)
        except PackageNotFoundError:
            # In a unit test or development run, not an installed version. Just use the default.
            pass
        except Exception as err:
            raise Exception(err)
    return version


# Right now the client version is being hardcoded.
keeper_secrets_manager_sdk_client_id = "mp{}".format(get_client_version(hardcode=False))


keeper_public_keys = {
    '1': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
    '2': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
    '3': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
    '4': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
    '5': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
    '6': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',

    '7': 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
    '8': 'BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ',
    '9': 'BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g',
    '10': 'BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg',
    '11': 'BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk',
    '12': 'BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY',
    '13': 'BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI',
    '14': 'BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE',
    '15': 'BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8',
    '16': 'BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c',
    '17': 'BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU',
    '18': 'BNhngQqTT1bPKxGuB6FhbPTAeNVFl8PKGGSGo5W06xWIReutm6ix6JPivqnbvkydY-1uDQTr-5e6t70G01Bb5JA'
}

keeper_servers = {
    'US': 'keepersecurity.com',
    'EU': 'keepersecurity.eu',
    'AU': 'keepersecurity.com.au',
    'GOV': 'govcloud.keepersecurity.us',
    'JP': 'keepersecurity.jp',
    'CA': 'keepersecurity.ca'
}
