import {
    DecryptBufferOptions,
    decryptOptions,
    EncryptBufferOptions,
    encryptOptions,
} from "./interface";

import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { calculate } from "fast-crc32c";
import {
    AES_256_GCM,
    BLOB_HEADER,
    LATIN1_ENCODING,
    SHA_256,
    SHA_1,
    UTF_8_ENCODING,
    SHA_512,
    ADDITIONAL_AUTHENTICATION_DATA,
    RAW_ENCRYPT_GCP_API_URL,
    RAW_DECRYPT_GCP_API_URL,
} from "./constants";
import { publicEncrypt } from "crypto";
import { RSA_PKCS1_OAEP_PADDING } from "constants";
import { GCPKeyValueStorageError } from "./error";
import pino from "pino";
import axios from "axios";


export async function encryptBuffer(
    options: EncryptBufferOptions, logger: pino.Logger
): Promise<Buffer> {
    try {
        logger.debug("started encryption of data provided");
        // Generate a random 32-byte key
        const key = randomBytes(32);

        // Create AES-GCM cipher instance
        const nonce = randomBytes(16); // AES-GCM requires a 16-byte nonce
        const cipher = createCipheriv(AES_256_GCM, key, nonce);

        // Encrypt the message
        const ciphertext = Buffer.concat([
            cipher.update(options.message),
            cipher.final(),
        ]);
        const tag = cipher.getAuthTag();

        const encryptOptions = {
            message: key,
            cryptoClient: options.cryptoClient,
            keyProperties: options.keyProperties,
            isAsymmetric: options.isAsymmetric,
            encryptionAlgorithm: options.encryptionAlgorithm,
            token: options.token
        };

        const CiphertextBlob: Buffer = options.isAsymmetric ? await encryptDataAndValidateCRCAsymmetric(encryptOptions, logger) : (options.token ? await encryptDataSymmetricRaw(encryptOptions, logger) : await encryptDataAndValidateCRC(encryptOptions, logger));

        const parts = [CiphertextBlob, nonce, tag, ciphertext];

        const buffers: Buffer[] = [];
        buffers[0] = Buffer.from(BLOB_HEADER, LATIN1_ENCODING);
        for (const part of parts) {
            const lengthBuffer = Buffer.alloc(2);
            lengthBuffer.writeUInt16BE(part.length, 0);
            buffers.push(lengthBuffer, part);
        }
        logger.debug("Encryption successful");
        return Buffer.concat(buffers);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        logger.warn("KCP KMS Storage failed to encrypt:", err.message);
        return Buffer.alloc(0); // Return empty buffer in case of an error
    }
}

async function encryptDataAndValidateCRCAsymmetric(
    options: encryptOptions, logger: pino.Logger
): Promise<Buffer<ArrayBufferLike>> {
    logger.debug("started encryption of data provided based on asymmetric key provided");
    const keyName = options.keyProperties.toResourceName();
    const encodedData = options.message;

    logger.debug("retrieving public key of given key from Cloud KMS");
    // Get public key from Cloud KMS
    const [publicKey] = await options.cryptoClient.getPublicKey({
        name: keyName,
    });

    if (publicKey.name !== keyName) {
        logger.error("public key not found in Cloud KMS");
        throw new Error('GetPublicKey: request corrupted in-transit');
    }

    if (!publicKey.pem) {
        logger.error("public key not found in Cloud KMS for given private key");
        throw new Error('Public key PEM is missing or invalid');
    }

    if (publicKey.pemCrc32c && publicKey.pemCrc32c.value !== undefined) {
        if (calculate(publicKey.pem) !== Number(publicKey.pemCrc32c.value)) {
            throw new Error('GetPublicKey: response corrupted in-transit');
        }
    } else {
        logger.error("Public key CRC32c is missing or invalid");
        throw new Error('Public key CRC32c is missing or invalid');
    }

    const ciphertextBuffer = publicEncrypt(
        {
            key: publicKey.pem,
            oaepHash: getHashingAlgorithm(options.encryptionAlgorithm, logger),
            padding: RSA_PKCS1_OAEP_PADDING,
        },
        encodedData
    );
    logger.debug("Encryption using asymmetric key provided successful.");
    return ciphertextBuffer;
}

export async function encryptDataSymmetricRaw(
    options: encryptOptions,
    logger: pino.Logger
): Promise<Buffer> {
    logger.debug('Trying to extract resource name');
    const keyName = options.keyProperties.toResourceName();

    logger.debug('Trying to encrypt data with given resource name %s', keyName);

    const additionalData = Buffer.from(ADDITIONAL_AUTHENTICATION_DATA, 'utf-8');
    const encodedMessage = options.message;

    const payload = {
        plaintext: encodedMessage.toString('base64'),
        additionalAuthenticatedData: additionalData.toString('base64')
    };

    const apiUrl = RAW_ENCRYPT_GCP_API_URL.replace('{}', keyName);

    try {
        const response = await axios.post(apiUrl, payload, {
            headers: {
                Authorization: `Bearer ${options.token}`,
                'Content-Type': 'application/json'
            }
        });

        logger.debug('rawEncrypt API call completed successfully');

        const result = response.data;

        if (!result.ciphertext || !result.initializationVector) {
            logger.error('Failed to parse response from rawEncrypt API call');
            throw new Error('Failed to parse response from rawEncrypt API call');
        }

        const ciphertext = Buffer.from(result.ciphertext, 'base64');
        const initializationVector = Buffer.from(result.initializationVector, 'base64');

        const encryptedData = Buffer.concat([initializationVector, ciphertext]);

        // 2-byte big endian length prefix
        const lengthPrefix = Buffer.alloc(2);
        lengthPrefix.writeUInt16BE(encryptedData.length, 0);

        logger.debug('Raw encryption completed, concatenating data with length prefix');
        return Buffer.concat([lengthPrefix, encryptedData]);

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (error: any) {
        logger.error(
            'rawEncrypt API call failed with status: %s, response: %s',
            error.response?.status,
            error.response?.data
        );
        throw new Error(
            `rawEncrypt API call failed with status: ${error.response?.status}, response: ${JSON.stringify(error.response?.data)}`
        );
    }
}

async function encryptDataAndValidateCRC(
    options: encryptOptions, logger: pino.Logger
): Promise<Buffer<ArrayBufferLike>> {
    logger.debug("started encryption of data provided based on symmetric key provided");
    const keyName = options.keyProperties.toResourceName();
    const encodedData = options.message;
    const encodedDataCrc = calculate(encodedData);

    const KMSClient = options.cryptoClient;
    const input = {
        name: keyName,
        plaintext: encodedData,
        plaintextCrc32c: {
            value: encodedDataCrc,
        },
    };

    const [encryptResponse] = await KMSClient.encrypt(input);
    const ciphertext = encryptResponse.ciphertext;
    if (ciphertext === null || ciphertext === undefined) {
        logger.error("Ciphertext is null or undefined");
        throw new Error("Ciphertext is null or undefined");
    }
    const cipherTextCrc = calculate(
        typeof ciphertext === "string" ? Buffer.from(ciphertext, LATIN1_ENCODING) : Buffer.from(ciphertext)
    );
    if (!encryptResponse.verifiedPlaintextCrc32c) {
        throw new Error("Encrypt: request corrupted in-transit");
    }
    if (cipherTextCrc !== Number(encryptResponse.ciphertextCrc32c?.value)) {
        throw new Error("Encrypt: response corrupted in-transit");
    }
    logger.debug("Encryption using symmetric key provided successful, encoding is pending");
    return typeof ciphertext === "string" ? Buffer.from(ciphertext.toString(), LATIN1_ENCODING) : Buffer.from(ciphertext);
}

export async function decryptBuffer(
    options: DecryptBufferOptions, logger: pino.Logger
): Promise<string> {
    try {
        logger.debug("started decryption of data provided");
        // Validate BLOB_HEADER
        const header = Buffer.from(options.ciphertext.subarray(0, 2));
        if (!header.equals(Buffer.from(BLOB_HEADER, LATIN1_ENCODING))) {
            throw new Error("Decryption failed : Invalid header"); // Invalid header
        }

        let pos = 2;
        const parts: Buffer[] = [];

        // Parse the ciphertext into its components
        for (let i = 1; i <= 4; i++) {
            const sizeBuffer = options.ciphertext.subarray(pos, pos + 2); // Read the size (2 bytes)
            if (sizeBuffer.length !== 2) {
                throw new Error("Invalid ciphertext structure: size buffer length mismatch.");
            }
            pos += 2;

            const partLength = sizeBuffer.readUInt16BE(0); // Parse length as big-endian
            const part = options.ciphertext.subarray(pos, pos + partLength);
            if (part.length !== partLength) {
                throw new Error("Invalid ciphertext structure: part length mismatch.");
            }
            pos += partLength;

            parts.push(part);
        }

        if (parts.length !== 4) {
            throw new Error("Invalid ciphertext structure: incorrect number of parts.");
        }
        const [encryptedKey, nonce, tag, encryptedText] = parts;
        const decryptedData = await decryptDataAndValidateCRC({
            cipherText: encryptedKey,
            cryptoClient: options.cryptoClient,
            keyProperties: options.keyProperties,
            isAsymmetric: options.isAsymmetric,
            encryptionAlgorithm: options.encryptionAlgorithm,
            token: options.token
        }, logger);

        const key = decryptedData;
        // Decrypt the message using AES-GCM
        const decipher = createDecipheriv(AES_256_GCM, key, nonce);
        decipher.setAuthTag(tag);

        const decrypted = Buffer.concat([
            decipher.update(encryptedText),
            decipher.final(),
        ]);
        logger.debug("Google KMS KeyVault Storage decrypted data");
        // Convert decrypted data to a UTF-8 string
        return decrypted.toString(UTF_8_ENCODING);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        logger.warn("Google KMS KeyVault Storage failed to decrypt:", err.message);
        return ""; // Return empty string in case of an error
    }
}

export async function decryptDataSymmetricRaw(
    options: decryptOptions,
    logger: pino.Logger
): Promise<Buffer> {
    logger.debug('Trying to extract resource name');
    const keyName = options.keyProperties.toResourceName();

    logger.debug(`Trying to decrypt data with given resource name ${keyName}`);
    const additionalData = Buffer.from(ADDITIONAL_AUTHENTICATION_DATA, 'utf-8');

    const encryptedData = options.cipherText;

    if (encryptedData.length < 14) {
        logger.error('Invalid ciphertext structure: size buffer length mismatch.');
        throw new Error('Invalid ciphertext structure: size buffer length mismatch.');
    }

    const initializationVector = encryptedData.subarray(2, 14);
    const ciphertext = encryptedData.subarray(14);

    const payload = {
        ciphertext: ciphertext.toString('base64'),
        additionalAuthenticatedData: additionalData.toString('base64'),
        initializationVector: initializationVector.toString('base64')
    };

    const apiUrl = RAW_DECRYPT_GCP_API_URL.replace('{}', keyName);

    try {
        const response = await axios.post(apiUrl, payload, {
            headers: {
                Authorization: `Bearer ${options.token}`,
                'Content-Type': 'application/json'
            }
        });

        logger.debug('rawDecrypt API call completed successfully');

        const result = response.data;

        if (!result.plaintext) {
            logger.error('Failed to parse response from rawDecrypt API call');
            throw new Error('Failed to parse response from rawDecrypt API call');
        }

        logger.debug('Raw decryption completed');
        return Buffer.from(result.plaintext, 'base64');

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (error: any) {
        logger.error(
            'rawDecrypt API call failed with status: %s, response: %s',
            error.response?.status,
            error.response?.data
        );
        throw new Error(
            `rawDecrypt API call failed with status: ${error.response?.status}, response: ${JSON.stringify(error.response?.data)}`
        );
    }
}

async function decryptDataAndValidateCRC(
    options: decryptOptions, logger: pino.Logger
): Promise<Buffer<ArrayBufferLike>> {
    const keyName = options.keyProperties.toKeyName();
    const cipherData = options.cipherText;
    const cipherDataCRC = calculate(cipherData);

    const KMSClient = options.cryptoClient;
    const input = {
        name: keyName,
        ciphertext: cipherData,
        ciphertextCrc32c: {
            value: cipherDataCRC,
        },
    };
    let decryptResponseData;
    if (options.isAsymmetric) {
        logger.debug(`Decrypting using asymmetric key ${keyName}`);
        const keyNameForAsymmetricDecrypt = options.keyProperties.toResourceName();
        input.name = keyNameForAsymmetricDecrypt;
        const [decryptResponse] = await KMSClient.asymmetricDecrypt(input);
        decryptResponseData = decryptResponse;
    } else {
        if (options.token) {
            const plaintext = await decryptDataSymmetricRaw(options, logger);
            return plaintext;
        }
        logger.debug(`decrypting using symmetric key ${keyName}`);
        const [decryptResponse] = await KMSClient.decrypt(input);
        decryptResponseData = decryptResponse;
    }

    if (
        calculate(decryptResponseData.plaintext) !==
        Number(decryptResponseData.plaintextCrc32c.value)
    ) {
        logger.error("Decrypt: response corrupted in-transit");
        throw new Error("Decrypt: response corrupted in-transit");
    }
    const plaintext = decryptResponseData.plaintext;

    return typeof plaintext === "string" ? Buffer.from(plaintext.toString(), LATIN1_ENCODING) : Buffer.from(plaintext);
}

function getHashingAlgorithm(encryptionAlgorithm, logger: pino.Logger): string {

    const supportedEncryptionAlgorithms = {
        "RSA_DECRYPT_OAEP_2048_SHA256": SHA_256,
        "RSA_DECRYPT_OAEP_3072_SHA256": SHA_256,
        "RSA_DECRYPT_OAEP_4096_SHA256": SHA_256,
        "RSA_DECRYPT_OAEP_4096_SHA512": SHA_512,
        "RSA_DECRYPT_OAEP_2048_SHA1": SHA_1,
        "RSA_DECRYPT_OAEP_3072_SHA1": SHA_1,
        "RSA_DECRYPT_OAEP_4096_SHA1": SHA_1,
    };

    const suggestedHash = supportedEncryptionAlgorithms[encryptionAlgorithm];
    if (!suggestedHash) {
        logger.error(`Unsupported encryption algorithm: ${encryptionAlgorithm} is used for provided key, Supported encryption algorithms are ${Object.keys(supportedEncryptionAlgorithms)}`);
        throw new GCPKeyValueStorageError("Unsupported encryption algorithm is used for provided key");
    }
    return suggestedHash;
}