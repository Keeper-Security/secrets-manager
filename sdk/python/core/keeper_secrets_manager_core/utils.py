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
import json
import logging
import os
from json import JSONDecodeError
from sys import platform as _platform

from Cryptodome.Cipher import AES, PKCS1_v1_5
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_private_key

ENCODING = 'UTF-8'


def get_os():
    if _platform.lower().startswith("linux"):
        return "linux"
    elif _platform.lower().startswith("darwin"):
        return "macOS"
    # elif _platform.lower().startswith("win32"):
    #     return "win32"
    # elif _platform.lower().startswith("win64"):
    #     return "win64"
    else:
        return _platform


def bytes_to_string(b):
    return b.decode(ENCODING)


def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')


def bytes_to_url_safe_str(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def base64_to_bytes(s):
    bbytes = base64.urlsafe_b64decode(s + '==')

    return bbytes


def string_to_bytes(s):
    return s.encode(ENCODING)


def url_safe_str_to_bytes(s):
    b = base64.urlsafe_b64decode(s + '==')
    return b


def url_safe_str_to_int(s):
    b = url_safe_str_to_bytes(s)
    return bytes_to_int(b)


def generate_random_bytes(length):
    return os.urandom(length)


def dict_to_json(dictionary):
    return json.dumps(dictionary, indent=4)


def json_to_dict(json_str):

    try:
        resp = json.loads(json_str)
    except JSONDecodeError as jsonDecErr:
        logging.warning(jsonDecErr)
        resp = None

    return resp


BS = 16

pad_binary = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()

unpad_binary = lambda s: s[0:-s[-1]]

unpad_char = lambda s: s[0:-ord(s[-1])]


########################################################################################################################
#                                                  Encryption methods                                                  #
########################################################################################################################


def generate_private_key_ecc():
    encryption_key_bytes = generate_random_bytes(32)
    private_key_str = bytes_to_url_safe_str(encryption_key_bytes)

    encryption_key_int = url_safe_str_to_int(private_key_str)

    private_key = ec.derive_private_key(encryption_key_int, ec.SECP256R1(), default_backend())

    return private_key


def generate_private_key_der():

    private_key = generate_private_key_ecc()

    # export to DER

    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return private_key_der


def generate_new_ecc_key():
    curve = ec.SECP256R1()
    ephemeral_key = ec.generate_private_key(curve, default_backend())
    return ephemeral_key


def encrypt_rsa(data, rsa_key):
    # type: (bytes, RSA.RsaKey) -> bytes
    cipher = PKCS1_v1_5.new(rsa_key)
    return cipher.encrypt(data)


def encrypt_aes(data, key):
    # type: (bytes, bytes) -> bytes
    iv = os.urandom(12)
    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    enc_data, tag = cipher.encrypt_and_digest(data)
    return iv + enc_data + tag


def public_encrypt(data: bytes, server_public_raw_key_bytes: bytes, idz: bytes = None):
    try:
        curve = ec.SECP256R1()

        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, server_public_raw_key_bytes)

        # server_public_key = load_pem_public_key(server_public_key_bytes)
        ephemeral_key2 = generate_new_ecc_key()
        shared_key = ephemeral_key2.exchange(ec.ECDH(), ephemeral_public_key)

        if idz:
            shared_key = shared_key + idz

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_key)
        enc_key = digest.finalize()
        encrypted_data = encrypt_aes(data, enc_key)
        eph_public_key = ephemeral_key2.public_key().public_bytes(serialization.Encoding.X962,
                                                                  serialization.PublicFormat.UncompressedPoint)

        return eph_public_key + encrypted_data

    except Exception as e:
        logging.warning(e)
        return


def hash_of_string(value):
    value_bytes = base64_to_bytes(value)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(value_bytes)
    return digest.finalize()


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
        result = decrypt_aes(encrypted_data, enc_key)

    except Exception as e:
        raise e

    return result


def decrypt_data_aes(data, key):
    # type: (str, bytes) -> bytes
    decoded_data = base64.urlsafe_b64decode(data + '==')
    iv = decoded_data[:16]
    ciphertext = decoded_data[16:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    return cipher.decrypt(ciphertext)


def decrypt_aes(encrypted_data, key):
    # type: (bytes, bytes) -> bytes

    if isinstance(key, str):
        key = base64_to_bytes(key)

    nonce = encrypted_data[:12]
    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(encrypted_data[12:-16], encrypted_data[-16:])


def decrypt_record(data, secret_key):
    if isinstance(data, str):
        data = base64_to_bytes(data)

    record = decrypt_aes(data, secret_key)
    record_json = bytes_to_string(record)
    return record_json


def decrypt_data(data, key):
    # type: (str, bytes) -> bytes

    data_padded = decrypt_data_aes(data, key)
    un_padded = unpad_binary(data_padded)
    return un_padded


def decrypt_ec(ecc_private_key, encrypted_data_bag: bytes):
    curve = ec.SECP256R1()

    server_public_key = encrypted_data_bag[:65]
    encrypted_data = encrypted_data_bag[65:]

    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, server_public_key)
    shared_key = ecc_private_key.exchange(ec.ECDH(), ephemeral_public_key)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_key)
    enc_key = digest.finalize()
    decrypted_data = decrypt_aes(encrypted_data, enc_key)
    return decrypted_data


def der_base64_private_key_to_private_key(private_key_der_base64):

    if isinstance(private_key_der_base64, str):
        private_key_der_base64 = base64_to_bytes(private_key_der_base64)

    return load_der_private_key(private_key_der_base64, password=None)


def extract_public_key_bytes(private_key_der_base64):

    if isinstance(private_key_der_base64, str):
        private_key_der_base64 = base64_to_bytes(private_key_der_base64)

    ec_private_key = der_base64_private_key_to_private_key(private_key_der_base64)
    pub_key = ec_private_key.public_key()
    pub_key_bytes = pub_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return pub_key_bytes


def sign(data, private_key):
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature
