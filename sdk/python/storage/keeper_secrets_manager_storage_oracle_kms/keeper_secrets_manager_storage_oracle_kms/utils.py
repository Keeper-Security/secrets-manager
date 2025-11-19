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
import logging
import traceback
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from .constants import BLOB_HEADER, UTF_8_ENCODING


try:
    from oci.key_management import KmsCryptoClient
    from oci.key_management.models import DecryptDataDetails,EncryptDataDetails
except ImportError:
    logging.getLogger().error("Missing oracle dependencies, import dependencies."
                              " To install missing packages run: \r\n"
                              "pip install oci\r\n")
    raise Exception(f"Missing import dependencies: oci. Additional data related to error is as follows: {traceback.format_exc()}")


def encrypt_buffer(key_id, message, crypto_client, key_version_id=None, is_asymmetric=False,logger=None):
    try:
        logger.debug("Encrypting data using encrypt_buffer")
        key = get_random_bytes(32)

        cipher = AES.new(key, AES.MODE_GCM)

        ciphertext, tag = cipher.encrypt_and_digest(
            message.encode())
        logger.debug("symmetric encryption using generated AES key is successful")
    
        logger.debug("generating encrypt data details payload")
        encrypt_data_details= EncryptDataDetails(
                key_id= key_id,
                plaintext= base64.b64encode(key).decode(UTF_8_ENCODING),
            )
        if key_version_id:
            logger.debug("key version id is set")
            encrypt_data_details.key_version_id = key_version_id

        if is_asymmetric:
            logger.debug("asymmetric encryption is being used")
            encrypt_data_details.encryption_algorithm = EncryptDataDetails.ENCRYPTION_ALGORITHM_RSA_OAEP_SHA_256

        encrypt_response = crypto_client.encrypt(encrypt_data_details)
        encrypted_key = base64.b64decode(encrypt_response.data.ciphertext)
        logger.debug("symmetric encryption using generated AES key is successful")
        
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

def decrypt_buffer(key_id : str, ciphertext : str,  crypto_client: KmsCryptoClient, key_version_id: str, is_asymmetric=False,logger=None):
    try:
        logger.debug("Decrypting data using decrypt_buffer,Validating blob header.")
        # Validate BLOB_HEADER
        header = ciphertext[:2]
        if header != BLOB_HEADER:
            raise ValueError("Decryption failed: Invalid header")

        pos = 2
        parts = []

        # Parse the ciphertext into its components
        encrypted_key, nonce, tag, encrypted_text = (b'', b'', b'', b'')
        for _ in range(1, 5):
            buf = ciphertext[pos:pos + 2]  # chunks are size prefixed
            pos += len(buf)
            if len(buf) == 2:
                buflen = int.from_bytes(buf, byteorder='big')
                buf = ciphertext[pos:pos + buflen]
                pos += len(buf)
                if len(buf) == buflen:
                    parts.append(buf)
                else:
                    logger.error("Decryption buffer contains incomplete data.")
                    raise ValueError("Decryption buffer contains incomplete data.")

        encrypted_key, nonce, tag, encrypted_text = parts
        logger.debug(" extracted encrypted key from encrypted buffer data")

        decrpt_data  = DecryptDataDetails(key_id= key_id, ciphertext= base64.b64encode(encrypted_key).decode())
        
        if key_version_id:
            logger.debug("key version id is set for decryption")
            decrpt_data.key_version_id = key_version_id
        
        if is_asymmetric:
            logger.debug("asymmetric decryption is being used for decryption")
            decrpt_data.encryption_algorithm = DecryptDataDetails.ENCRYPTION_ALGORITHM_RSA_OAEP_SHA_256
        
        encrypt_response = crypto_client.decrypt(decrypt_data_details=decrpt_data)
        key = base64.b64decode(encrypt_response.data.plaintext)
        logger.info("decryption successful, key is to be extracted")
        
        # Decrypt the message using AES-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(encrypted_text, tag)

        # Convert decrypted data to a UTF-8 string
        return decrypted.decode()
    except Exception as err:
        logger.warning(f"Oracle KMS KeyVault Storage failed to decrypt: {err}")
        return ""  # Return empty string in case of an error
