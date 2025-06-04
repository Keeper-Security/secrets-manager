#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com

import logging
import os
import traceback
from typing import Optional

try:
    from oci.config import from_file
except ImportError:
    logging.getLogger().error("Missing OCI import dependencies."
                 " To install missing packages run: \r\n"
                 "pip install --upgrade \"oci\"\r\n"
                 "pip install --upgrade \"pycryptodome\"\r\n")
    logging.getLogger().debug(f"Missing import dependencies: oci. Additional data related to error is as follows: {traceback.format_exc()}")

class OCISessionConfig:
    def __init__(self, oci_config_file_location: str, profile: Optional[str] = None, kms_crypto_endpoint: str = "",kms_management_endpoint: str = ""):
        self.oci_config_file_location = os.path.abspath(oci_config_file_location)
        self.profile = profile if profile else "DEFAULT"
        self.kms_crypto_endpoint = kms_crypto_endpoint
        self.kms_management_endpoint = kms_management_endpoint

    def get_provider(self):
        return from_file(self.oci_config_file_location, self.profile)

    def get_kms_crypto_endpoint(self) -> str:
        return self.kms_crypto_endpoint
    
    def get_kms_management_endpoint(self) -> str:
        return self.kms_management_endpoint
