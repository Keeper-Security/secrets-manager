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

import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_der_private_key

from . import utils

_CRYPTO_BACKEND = default_backend()


def pad_data(data):    # type: (bytes) -> bytes
    padder = PKCS7(16*8).padder()
    return padder.update(data) + padder.finalize()


def unpad_data(data):     # type: (bytes) -> bytes
    unpadder = PKCS7(16*8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


class CryptoUtils:

    BS = 16

    @staticmethod
    def pad_binary(data: bytes, block_size: int = BS) -> bytes:
        """ Apply standard pkcs7 padding """
        pad_len = block_size - len(data) % block_size
        padding = chr(pad_len).encode()*pad_len
        return data + padding

    @staticmethod
    def unpad_binary(data: bytes, block_size: int = BS):
        """ Remove standard pkcs7 padding """
        data_len = len(data)
        if data_len % block_size == 0:
            pad_len = data[-1]
            if pad_len > 0 and pad_len <= min(block_size, data_len):
                # if data[-pad_len:] == chr(pad_len).encode()*pad_len:
                return data[:-pad_len]
        return data

    @staticmethod
    def unpad_char(data):
        return data[0:-ord(data[-1])]

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
    def generate_private_key_ecc():
        encryption_key_bytes = utils.generate_random_bytes(32)
        private_key_str = utils.bytes_to_base64(encryption_key_bytes)

        encryption_key_int = utils.url_safe_str_to_int(private_key_str)

        private_key = ec.derive_private_key(encryption_key_int, ec.SECP256R1(), default_backend())

        return private_key

    @staticmethod
    def generate_private_key_der():

        private_key = CryptoUtils.generate_private_key_ecc()

        # export to DER

        private_key_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return private_key_der

    @staticmethod
    def generate_new_ecc_key():
        curve = ec.SECP256R1()
        ephemeral_key = ec.generate_private_key(curve, default_backend())
        return ephemeral_key

    @staticmethod
    def encrypt_aes(data, key, iv=None):
        aesgcm = AESGCM(key)
        iv = iv or os.urandom(12)
        enc = aesgcm.encrypt(iv, data, None)
        return iv + enc

    @staticmethod
    def decrypt_aes(data, key):
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(data[:12], data[12:], None)

    @staticmethod
    def encrypt_aes_cbc(data, key, iv=None):
        iv = iv or os.urandom(16)
        cipher = Cipher(AES(key), CBC(iv), backend=_CRYPTO_BACKEND)
        encryptor = cipher.encryptor()
        enc = encryptor.update(pad_data(data)) + encryptor.finalize()
        return iv + enc

    @staticmethod
    def decrypt_aes_cbc(data, key):
        iv = data[:16]
        cipher = Cipher(AES(key), CBC(iv), backend=_CRYPTO_BACKEND)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data[16:]) + decryptor.finalize()
        return unpad_data(decrypted_data)

    @staticmethod
    def public_encrypt(data: bytes, server_public_raw_key_bytes: bytes, idz: bytes = None):

        curve = ec.SECP256R1()

        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, server_public_raw_key_bytes)

        # server_public_key = load_pem_public_key(server_public_key_bytes)
        ephemeral_key2 = CryptoUtils.generate_new_ecc_key()
        shared_key = ephemeral_key2.exchange(ec.ECDH(), ephemeral_public_key)

        if idz:
            shared_key = shared_key + idz

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_key)
        enc_key = digest.finalize()
        encrypted_data = CryptoUtils.encrypt_aes(data, enc_key)
        eph_public_key = ephemeral_key2.public_key().public_bytes(serialization.Encoding.X962,
                                                                  serialization.PublicFormat.UncompressedPoint)

        return eph_public_key + encrypted_data

    @staticmethod
    def hash_of_string(value):
        value_bytes = utils.base64_to_bytes(value)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(value_bytes)
        return digest.finalize()

    @staticmethod
    def ecies_decrypt(server_public_key, ciphertext, priv_key_data, id=b''):

        try:
            # server_public_key = ciphertext[:65]
            encrypted_data = ciphertext
            curve = ec.SECP256R1()
            private_value = int.from_bytes(priv_key_data, byteorder='big', signed=False)
            ecc_private_key = ec.derive_private_key(private_value, curve, default_backend())

            # ecc_private_key = CommonHelperMethods.get_private_key_ecc(params)
            ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, server_public_key)
            shared_key = ecc_private_key.exchange(ec.ECDH(), ephemeral_public_key)
            shared_key = shared_key + id if id else shared_key
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(shared_key)
            enc_key = digest.finalize()
            result = CryptoUtils.decrypt_aes(encrypted_data, enc_key)

        except Exception as e:
            raise e

        return result

    @staticmethod
    def decrypt_record(data, secret_key):
        if isinstance(data, str):
            data = utils.base64_to_bytes(data)

        record = CryptoUtils.decrypt_aes(data, secret_key)
        record_json = utils.bytes_to_string(record)
        return record_json

    @staticmethod
    def decrypt_ec(ecc_private_key, encrypted_data_bag: bytes):
        curve = ec.SECP256R1()

        server_public_key = encrypted_data_bag[:65]
        encrypted_data = encrypted_data_bag[65:]

        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, server_public_key)
        shared_key = ecc_private_key.exchange(ec.ECDH(), ephemeral_public_key)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_key)
        enc_key = digest.finalize()
        decrypted_data = CryptoUtils.decrypt_aes(encrypted_data, enc_key)
        return decrypted_data

    @staticmethod
    def der_base64_private_key_to_private_key(private_key_der_base64):

        if isinstance(private_key_der_base64, str):
            private_key_der_base64 = utils.base64_to_bytes(private_key_der_base64)

        return load_der_private_key(private_key_der_base64, password=None)

    @staticmethod
    def extract_public_key_bytes(private_key_der_base64):

        if isinstance(private_key_der_base64, str):
            private_key_der_base64 = utils.base64_to_bytes(private_key_der_base64)

        ec_private_key = CryptoUtils.der_base64_private_key_to_private_key(private_key_der_base64)
        pub_key = ec_private_key.public_key()
        pub_key_bytes = pub_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return pub_key_bytes

    @staticmethod
    def sign(data, private_key):
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
