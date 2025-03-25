#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com

from enum import Enum

class KeyPurpose(Enum): 
  ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT",
  ASYMMETRIC_DECRYPT = "ASYMMETRIC_DECRYPT",
  CRYPTO_KEY_PURPOSE_UNSPECIFIED = "CRYPTO_KEY_PURPOSE_UNSPECIFIED",
  ASSYMMETRIC_SIGN = "ASYMMETRIC_SIGN",
  RAW_ENCRYPT_DECRYPT = "RAW_ENCRYPT_DECRYPT",
  MAC = "MAC"


class EncryptionAlgorithmSpec(Enum):
  SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT",
  RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256"
