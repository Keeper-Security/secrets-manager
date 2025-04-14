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
import os

from .constants import SCOPES

try:
    from google.cloud import kms
    from google.oauth2 import service_account
    from google.auth.exceptions import RefreshError
    from google.auth.transport.requests import Request
except ImportError:
    logging.getLogger().error("Missing GCP import dependencies."
                 " To install missing packages run: \r\n"
                 "pip install --upgrade \"google-cloud-kms\"\r\n"
                 "pip install --upgrade \"google-crc32c\"\r\n"
                 "pip install --upgrade \"pycryptodome\"\r\n"
                 "pip install --upgrade \"google-auth\"\r\n")
    raise Exception(f"Missing import dependencies: google cloud kms and google oauth2. Additional details: {traceback.format_exc()}")

class GCPKMSClientConfig:
    """
    A client for interacting with Google Cloud KMS.
    """
    def __init__(self):
        """
        Initializes a GCP KMS client using the default configuration.
        
        By default, the GCP KMS client will use the Application Default Credentials (ADC)
        to authenticate.
        """
        self.kms_client = None
        self.credentials=None

    def create_client_from_credentials_file(self, credentials_key_file_path: str):
        """
        Creates a new GCP KMS client using the specified credentials file.

        :param credentials_key_file_path: Path to the JSON key file containing
                                          the service account credentials.
        :return: The GCPKMSClient instance with the new client.
        """
        self.credentials = service_account.Credentials.from_service_account_file(os.path.abspath(credentials_key_file_path),scopes =SCOPES)
        self.kms_client = kms.KeyManagementServiceClient(credentials=self.credentials)
        return self

    def create_client_using_credentials(self, client_email: str, private_key: str):
        """
        Creates a new GCP KMS client using the specified client email and private key.

        :param client_email: The email address associated with the service account.
        :param private_key: The private key corresponding to the service account.
        :return: The GCPKMSClient instance with the new client.
        """
        self.credentials = service_account.Credentials.from_service_account_info({
            "type": "service_account",
            "client_email": client_email,
            "private_key": private_key,
        })
        self.kms_client = kms.KeyManagementServiceClient(credentials=self.credentials,scopes=SCOPES)
        return self

    def get_default_crypto_client(self):
        """
        Returns the KMS client instance.
        """
        self.kms_client =  kms.KeyManagementServiceClient()
        return self
    
    def get_crypto_client(self):
        """
        Returns the KMS client instance.
        """
        return self.kms_client

    def getToken(self):
        if self.credentials is None:
            raise Exception("KMS client not initialized. Please call create_client_from_credentials_file or create_client_using_credentials first.")
        try:
            # If the token is expired or absent, refresh it
            if not self.credentials.valid:
                auth_request = Request()
                self.credentials.refresh(auth_request)
            return self.credentials.token
        except RefreshError as e:
            raise RuntimeError(f"Failed to retrieve access token: {e}")