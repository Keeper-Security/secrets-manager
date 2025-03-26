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
import traceback
from .oci_session_config import OCISessionConfig

try:
    from oci.key_management import KmsCryptoClient,KmsManagementClient
except ImportError:
    logging.getLogger().error("Missing OCI import dependencies."
                 " To install missing packages run: \r\n"
                 "pip install --upgrade \"oci\"\r\n")
    raise Exception(f"Missing import dependencies: oci. Additional data related to error is as follows: {traceback.format_exc()}")

class OciKmsClient:
    def __init__(self, session_config: OCISessionConfig):
        self.oci_kms_crypto_client = KmsCryptoClient(session_config.get_provider(), session_config.get_kms_crypto_endpoint())
        self.oci_kms_management_client = KmsManagementClient(session_config.get_provider(), session_config.get_kms_management_endpoint())

    def get_crypto_client(self) -> KmsCryptoClient:
        return self.oci_kms_crypto_client
    
    def get_management_client(self) -> KmsManagementClient:
        return self.oci_kms_management_client