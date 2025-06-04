#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from google.cloud.kms_v1 import CryptoKey,CryptoKeyVersion

class KeyPurpose:
    RAW_ENCRYPT_DECRYPT = CryptoKey.CryptoKeyPurpose.RAW_ENCRYPT_DECRYPT
    ENCRYPT_DECRYPT = CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    ASYMMETRIC_DECRYPT = CryptoKey.CryptoKeyPurpose.ASYMMETRIC_DECRYPT

class KeyAlgorithm:
    RSA_DECRYPT_OAEP_2048_SHA256 = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_DECRYPT_OAEP_2048_SHA256
    RSA_DECRYPT_OAEP_3072_SHA256 = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_DECRYPT_OAEP_3072_SHA256
    RSA_DECRYPT_OAEP_4096_SHA256 = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_DECRYPT_OAEP_4096_SHA256
    RSA_DECRYPT_OAEP_4096_SHA512 = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_DECRYPT_OAEP_4096_SHA512
    RSA_DECRYPT_OAEP_2048_SHA1 = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_DECRYPT_OAEP_2048_SHA1
    RSA_DECRYPT_OAEP_3072_SHA1 = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_DECRYPT_OAEP_3072_SHA1
    RSA_DECRYPT_OAEP_4096_SHA1 = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_DECRYPT_OAEP_4096_SHA1

# Supported key purposes
SUPPORTED_KEY_PURPOSE = [
    CryptoKey.CryptoKeyPurpose.RAW_ENCRYPT_DECRYPT,
    CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
    CryptoKey.CryptoKeyPurpose.ASYMMETRIC_DECRYPT,
]

# Constants
BLOB_HEADER = b"\xff\xff"  # Encrypted BLOB Header: U+FFFF is a non-character
LATIN1_ENCODING = "latin1"
UTF_8_ENCODING = "utf-8"
AES_256_GCM = "aes-256-gcm"
MD5_HASH = "md5"
HEX_DIGEST = "hex"
DEFAULT_JSON_INDENT = 4
OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)

ADDITIONAL_AUTHENTICATION_DATA = "keeper_auth"
TOKEN_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
RAW_ENCRYPT_GCP_API_URL = "https://cloudkms.googleapis.com/v1/{0}:rawEncrypt"
RAW_DECRYPT_GCP_API_URL = "https://cloudkms.googleapis.com/v1/{0}:rawDecrypt"
SCOPES = [TOKEN_SCOPE]