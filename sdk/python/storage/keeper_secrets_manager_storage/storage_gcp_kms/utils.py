#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com
import base64
import json
import traceback
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256, SHA1, SHA512
from cryptography.hazmat.primitives import hashes
import requests
from .constants import ADDITIONAL_AUTHENTICATION_DATA, BLOB_HEADER, RAW_DECRYPT_GCP_API_URL, RAW_ENCRYPT_GCP_API_URL, KeyAlgorithm, KeyPurpose


try:
    from google.cloud.kms_v1 import CryptoKey, EncryptRequest, AsymmetricDecryptRequest, DecryptRequest
    import google_crc32c
except ImportError:
    logging.getLogger().error("Missing GCP checksum import dependencies."
                              " To install missing packages run: \r\n"
                              "pip install google-crc32c\r\n")
    raise Exception(f"Missing import dependencies: google-crc32c. Additional details: {traceback.format_exc()}")


def encrypt_buffer(is_asymmetric, message, crypto_client, key_properties,encryption_algorithm,logger,token=None):
    try:
        # Generate a random 32-byte key
        key = get_random_bytes(32)

        # Create AES-GCM cipher instance
        cipher = AES.new(key, AES.MODE_GCM)

        # Encrypt the message
        ciphertext, tag = cipher.encrypt_and_digest(
            message.encode())

        encrypt_options = {
            'message': key,
            'crypto_client': crypto_client,
            'key_properties': key_properties,
            'is_asymmetric': is_asymmetric,
            'encryption_algorithm': encryption_algorithm,
            'token' :token
        }

        if is_asymmetric:
            encrypted_key = encrypt_data_and_validate_crc_asymmetric(
                encrypt_options)
        else:
            if token:
                encrypted_key = encrypt_data_symmetric_raw(encrypt_options,logger)
            else:
                encrypted_key = encrypt_data_and_validate_crc(encrypt_options)

        parts = [encrypted_key, cipher.nonce, tag, ciphertext]

        buffers = bytearray()
        buffers.extend(BLOB_HEADER)
        for part in parts:
            length_buffer = len(part).to_bytes(2, byteorder='big')
            buffers.extend(length_buffer)
            buffers.extend(part)

        return buffers
    except Exception as err:
        logger.warning(f"KCP KMS Storage failed to encrypt: {err}")
        return b''  # Return empty buffer in case of an error


def encrypt_data_and_validate_crc_asymmetric(options):

    key_name = options['key_properties'].to_resource_name()
    encoded_data = options['message']

    # Get public key from Cloud KMS
    client = options['crypto_client']
    public_key = client.get_public_key(request={"name": key_name})

    if public_key.name != key_name:
        raise ValueError('GetPublicKey: request corrupted in-transit')

    crc32c = google_crc32c.value(public_key.pem.encode())
    if public_key.pem_crc32c != crc32c:
        raise ValueError('GetPublicKey: response corrupted in-transit')

    rsa_key = RSA.import_key(public_key.pem.encode())
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo= get_hash_algorithm(options.get('encryption_algorithm')))
    ciphertext = cipher.encrypt(encoded_data)

    return ciphertext


def encrypt_data_and_validate_crc(options):
    key_name = options['key_properties'].to_resource_name()
    encoded_data = options['message']

    encoded_data_crc = google_crc32c.value(encoded_data)

    client = options['crypto_client']
    input = EncryptRequest(name=key_name, plaintext=encoded_data,
                           plaintext_crc32c=encoded_data_crc)

    encrypt_response = client.encrypt(request=input)
    ciphertext = encrypt_response.ciphertext
    cipher_text_crc = google_crc32c.value(ciphertext)

    if not encrypt_response.verified_plaintext_crc32c:
        raise ValueError("Encrypt: request corrupted in-transit")
    if cipher_text_crc != encrypt_response.ciphertext_crc32c:
        raise ValueError("Encrypt: response corrupted in-transit")

    return ciphertext

def encrypt_data_symmetric_raw(options, logger: logging.Logger) -> bytes:
    logger.debug("Trying to extract resource name")
    key_name = options.get("key_properties").to_resource_name()

    logger.debug("Trying to encrypt data with given resource name %s", key_name)
    additional_data = ADDITIONAL_AUTHENTICATION_DATA.encode('utf-8')
    encoded_message = options.get("message")

    payload = {
        "plaintext": base64.b64encode(encoded_message).decode('utf-8'),
        "additionalAuthenticatedData": base64.b64encode(additional_data).decode('utf-8')
    }

    token = options.get("token")
    api_url = RAW_ENCRYPT_GCP_API_URL.format(key_name)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.post(api_url, headers=headers, data=json.dumps(payload))
    response_body = response.text

    if not response.ok:
        logger.error("rawEncrypt API call failed with status: %s, response: %s", response.status_code, response_body)
        raise Exception(f"rawEncrypt API call failed with status: {response.status_code}, response: {response_body}")

    logger.debug("rawEncrypt API call completed successfully")

    result = response.json()

    if "ciphertext" not in result or "initializationVector" not in result:
        logger.error("Failed to parse response from rawEncrypt API call")
        raise Exception("Failed to parse response from rawEncrypt API call")

    ciphertext = base64.b64decode(result["ciphertext"])
    initialization_vector = base64.b64decode(result["initializationVector"])
    encrypted_data = initialization_vector + ciphertext

    # Create 2-byte length prefix (big endian)
    length = len(encrypted_data)
    length_prefix = length.to_bytes(2, byteorder='big')

    logger.debug("Raw encryption completed, concatenating data with length prefix")
    final_payload = length_prefix + encrypted_data

    return final_payload

def decrypt_buffer(is_asymmetric, ciphertext, crypto_client, key_properties,logger: logging.Logger,token=None):
    try:
        # Validate BLOB_HEADER
        header = ciphertext[:2]
        if header != BLOB_HEADER:
            raise ValueError("Decryption failed: Invalid header")

        pos = 2
        parts = []

        # Parse the ciphertext into its components
        encrypted_key, nonce, tag, encrypted_text = (b'', b'', b'', b'')
        for x in range(1, 5):
            buf = ciphertext[pos:pos + 2]  # chunks are size prefixed
            pos += len(buf)
            if len(buf) == 2:
                buflen = int.from_bytes(buf, byteorder='big')
                buf = ciphertext[pos:pos + buflen]
                pos += len(buf)
                if len(buf) == buflen:
                    parts.append(buf)
                else:
                    logging.error("Decryption buffer contains incomplete data.")

        encrypted_key, nonce, tag, encrypted_text = parts

        decrypt_options = {
            'ciphertext': encrypted_key,
            'crypto_client': crypto_client,
            'key_properties': key_properties,
            'is_asymmetric': is_asymmetric,
            'token': token,
            'logger': logger
        }

        key = decrypt_data_and_validate_crc(decrypt_options)

        # Decrypt the message using AES-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(encrypted_text, tag)

        # Convert decrypted data to a UTF-8 string
        return decrypted.decode()
    except Exception as err:
        logger.warning(f"Google KMS KeyVault Storage failed to decrypt: {err}")
        return ""  # Return empty string in case of an error


def decrypt_data_and_validate_crc(options):
    cipher_data = options['ciphertext']
    cipher_data_crc = google_crc32c.value(options['ciphertext'])
    client = options['crypto_client']

    if options['is_asymmetric']:
        key_name_for_asymmetric_decrypt = options['key_properties'].to_resource_name(
        )
        request = AsymmetricDecryptRequest(
            name=key_name_for_asymmetric_decrypt,
            ciphertext=cipher_data,
            ciphertext_crc32c=cipher_data_crc
        )
        decrypt_response = client.asymmetric_decrypt(request=request)
    else:
        if options.get("token"):
            plaintext = decrypt_data_symmetric_raw(options, options['logger'])
            return plaintext
            
        key_name = options['key_properties'].to_key_name()
        input = DecryptRequest(name=key_name, ciphertext=cipher_data,
                               ciphertext_crc32c=cipher_data_crc)
        decrypt_response = client.decrypt(request=input)

    plaintext = decrypt_response.plaintext
    plaintext_crc = google_crc32c.value(plaintext)

    if plaintext_crc != decrypt_response.plaintext_crc32c:
        raise ValueError("Decrypt: response corrupted in-transit")

    return plaintext

def decrypt_data_symmetric_raw(options, logger: logging.Logger) -> bytes:
    
    logger.debug("Trying to extract resource name")
    key_name = options["key_properties"].to_resource_name()

    logger.debug(f"Trying to decrypt data with given resource name {key_name}")
    additional_data = ADDITIONAL_AUTHENTICATION_DATA.encode("utf-8")

    encrypted_data = options["ciphertext"]
    if len(encrypted_data) < 14:
        logger.error("Invalid ciphertext structure: size buffer length mismatch.")
        raise ValueError("Invalid ciphertext structure: size buffer length mismatch.")

    _length = (encrypted_data[0] << 8) | encrypted_data[1]
    initialization_vector = encrypted_data[2:14]
    ciphertext = encrypted_data[14:]

    payload = {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "additionalAuthenticatedData": base64.b64encode(additional_data).decode("utf-8"),
        "initializationVector": base64.b64encode(initialization_vector).decode("utf-8")
    }

    token = options["token"]
    api_url = RAW_DECRYPT_GCP_API_URL.format(key_name)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.post(api_url, data=json.dumps(payload), headers=headers)
    response_body = response.text

    if not response.ok:
        logger.error(f"rawDecrypt API call failed with status: {response.status_code}, response: {response_body}")
        raise Exception(f"rawDecrypt API call failed with status: {response.status_code}, response: {response_body}")

    logger.debug("rawDecrypt API call completed successfully")

    result = json.loads(response_body)
    if result is None or "plaintext" not in result:
        logger.error("Failed to parse response from rawDecrypt API call")
        raise Exception("Failed to parse response from rawDecrypt API call")

    logger.debug("Raw decryption completed")
    return base64.b64decode(result["plaintext"])

def get_key_type(key_purpose: CryptoKey.CryptoKeyPurpose):
    if key_purpose == KeyPurpose.RAW_ENCRYPT_DECRYPT:
        return "RAW_ENCRYPT_DECRYPT"
    elif key_purpose == KeyPurpose.ENCRYPT_DECRYPT:
        return "ENCRYPT_DECRYPT"
    elif key_purpose == KeyPurpose.ASYMMETRIC_DECRYPT:
        return "ASYMMETRIC_DECRYPT"

def get_hash_algorithm(encryption_algorithm: KeyAlgorithm) -> hashes.HashAlgorithm:
    """Converts a KeyAlgorithm to a HashAlgorithm."""

    hash_algorithms = {
        KeyAlgorithm.RSA_DECRYPT_OAEP_2048_SHA256: SHA256,
        KeyAlgorithm.RSA_DECRYPT_OAEP_3072_SHA256: SHA256,
        KeyAlgorithm.RSA_DECRYPT_OAEP_4096_SHA256: SHA256,
        KeyAlgorithm.RSA_DECRYPT_OAEP_4096_SHA512: SHA512,
        KeyAlgorithm.RSA_DECRYPT_OAEP_2048_SHA1: SHA1,
        KeyAlgorithm.RSA_DECRYPT_OAEP_3072_SHA1: SHA1,
        KeyAlgorithm.RSA_DECRYPT_OAEP_4096_SHA1: SHA1,
    }

    try:
        return hash_algorithms[encryption_algorithm]
    except KeyError:
        raise TypeError(
            "Unsupported encryption algorithm is used for provided key"
        ) from None
