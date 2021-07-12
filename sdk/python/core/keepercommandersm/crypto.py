#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com

import base64
import os

from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class CryptoUtils:

    @staticmethod
    def bytes_to_int(b):
        return int.from_bytes(b, byteorder='big')

    @staticmethod
    def url_safe_str_to_bytes(s):
        b = base64.urlsafe_b64decode(s + '==')
        return b

    @staticmethod
    def generate_random_bytes(length):
        return os.urandom(length)

    @staticmethod
    def generate_encryption_key_bytes():
        """Generates 32 bit transmission key"""
        return CryptoUtils.generate_random_bytes(32)

    @staticmethod
    def bytes_to_url_safe_str(b):
        return base64.urlsafe_b64encode(b).decode().rstrip('=')

    @staticmethod
    def url_safe_str_to_int(s):
        b = CryptoUtils.url_safe_str_to_bytes(s)
        return CryptoUtils.bytes_to_int(b)

    @staticmethod
    def generate_ecc_keys():

        encryption_key_bytes = CryptoUtils.generate_encryption_key_bytes()
        private_key_str = CryptoUtils.bytes_to_url_safe_str(encryption_key_bytes)
        encryption_key_int = CryptoUtils.url_safe_str_to_int(private_key_str)
        private_key = ec.derive_private_key(encryption_key_int, ec.SECP256R1(), default_backend())

        return private_key

    @staticmethod
    def public_key_ecc(private_key):
        pub_key = private_key.public_key()
        pub_key_bytes = pub_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return pub_key_bytes

    @staticmethod
    def encrypt_aes(data, key):
        # type: (bytes, bytes) -> bytes
        iv = os.urandom(12)
        cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
        enc_data, tag = cipher.encrypt_and_digest(data)
        return iv + enc_data + tag

    @staticmethod
    def encrypt_rsa(data, rsa_key):
        # type: (bytes, RSA.RsaKey) -> bytes
        cipher = PKCS1_v1_5.new(rsa_key)
        return cipher.encrypt(data)


# if __name__ == '__main__':
#
    # pk = CryptoUtils.generate_encryption_key_bytes()
    # print(pk)
