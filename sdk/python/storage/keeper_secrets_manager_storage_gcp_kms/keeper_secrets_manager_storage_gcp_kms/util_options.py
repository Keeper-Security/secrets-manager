#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com

from google.cloud import kms
from typing import Type

KMSClient = Type[kms.KeyManagementServiceClient]

class Options:
    def __init__(self, is_asymmetric: bool, crypto_client: kms.KeyManagementServiceClient, key_properties: KMSClient):
        self.is_asymmetric = is_asymmetric
        self.crypto_client = crypto_client
        self.key_properties = key_properties

class BufferOptions(Options):
    def __init__(self, is_asymmetric: bool, crypto_client: kms.KeyManagementServiceClient, key_properties: KMSClient, key_type: str):
        super().__init__(is_asymmetric, crypto_client, key_properties)
        self.key_type = key_type

class EncryptBufferOptions(BufferOptions):
    def __init__(self, is_asymmetric: bool, crypto_client: kms.KeyManagementServiceClient, key_properties: KMSClient, key_type: str, message: str):
        super().__init__(is_asymmetric, crypto_client, key_properties, key_type)
        self.message = message

class DecryptBufferOptions(BufferOptions):
    def __init__(self, is_asymmetric: bool, crypto_client: kms.KeyManagementServiceClient, key_properties: KMSClient, key_type: str, ciphertext: bytes):
        super().__init__(is_asymmetric, crypto_client, key_properties, key_type)
        self.ciphertext = ciphertext

class EncryptOptions(Options):
    def __init__(self, is_asymmetric: bool, crypto_client: kms.KeyManagementServiceClient, key_properties: KMSClient, message: bytes):
        super().__init__(is_asymmetric, crypto_client, key_properties)
        self.message = message

class DecryptOptions(Options):
    def __init__(self, is_asymmetric: bool, crypto_client: kms.KeyManagementServiceClient, key_properties: KMSClient, cipher_text: bytes):
        super().__init__(is_asymmetric, crypto_client, key_properties)
        self.cipher_text = cipher_text
