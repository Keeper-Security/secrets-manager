import { DecryptBufferOptions, EncryptBufferOptions } from "./interface";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { DecryptRequest, EncryptRequest } from "oci-keymanagement/lib/request";
import {
  AES_256_GCM,
  BASE_64,
  BLOB_HEADER,
  LATIN1_ENCODING,
  UTF_8_ENCODING,
} from "./constants";
import { DecryptResponse, EncryptResponse } from "oci-keymanagement/lib/response";
import { calculate } from "fast-crc32c";
import { EncryptDataDetails } from "oci-keymanagement/lib/model";
import { Logger } from "pino";

export async function encryptBuffer(
  options: EncryptBufferOptions, logger: Logger
): Promise<Buffer> {
  try {
    logger.debug("started encryption buffer");
    // Generate a random 32-byte key
    const key = randomBytes(32);

    // Create AES-GCM cipher instance
    const nonce = randomBytes(16); // AES-GCM requires a 16-byte nonce
    const cipher = createCipheriv(AES_256_GCM, key, nonce);

    // Encrypt the message
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(options.message, UTF_8_ENCODING)),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    logger.debug("creating encryption request payload");
    const encryptRequest: EncryptRequest = {
      encryptDataDetails: {
        keyId: options.keyId,
        plaintext: key.toString(BASE_64),
      },
    };

    if (options.keyVersionId) {
      logger.debug(`adding key version Id ${options.keyVersionId} to payload`);
      encryptRequest.encryptDataDetails.keyVersionId = options.keyVersionId;
    }

    if (options.isAsymmetric) {
      logger.debug(`adding encryption value as ${EncryptDataDetails.EncryptionAlgorithm.RsaOaepSha256} to payload`);
      encryptRequest.encryptDataDetails.encryptionAlgorithm = EncryptDataDetails.EncryptionAlgorithm.RsaOaepSha256;
    }

    const response: EncryptResponse = await options.cryptoClient.encrypt(encryptRequest);
    logger.debug("encryption successful from Oracle side");

    const CiphertextBlob = Buffer.from(Buffer.from(response.encryptedData.ciphertext, BASE_64).toString(LATIN1_ENCODING), LATIN1_ENCODING); // making a latin1 buffer from byte64 buffer

    // Build the blob
    const parts = [CiphertextBlob, nonce, tag, ciphertext];

    const buffers: Buffer[] = [];
    buffers[0] = Buffer.from(BLOB_HEADER, LATIN1_ENCODING);
    for (const part of parts) {
      const lengthBuffer = Buffer.alloc(2);
      lengthBuffer.writeUInt16BE(part.length, 0);
      buffers.push(lengthBuffer, part);
    }
    const blob = Buffer.concat(buffers);

    logger.debug("Completed encryption of data provided");
    return blob;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err: any) {
    console.error("OCI KMS Storage failed to encrypt:", err.message);
    return Buffer.alloc(0); // Return empty buffer in case of an error
  }
}

export async function decryptBuffer(
  options: DecryptBufferOptions, logger: Logger
): Promise<string> {
  try {
    logger.debug("Started decryption");
    // Validate BLOB_HEADER
    const header = Buffer.from(options.ciphertext.subarray(0, 2));
    if (!header.equals(Buffer.from(BLOB_HEADER, LATIN1_ENCODING))) {
      logger.debug("Header validation failed for encrypted data, maybe data has been altered?");
      throw new Error("Invalid ciphertext structure: missing header.");
    }

    let pos = 2;
    const parts: Buffer[] = [];

    // Parse the ciphertext into its components
    for (let i = 0; i < 4; i++) {
      const sizeBuffer = options.ciphertext.subarray(pos, pos + 2); // Read the size (2 bytes)
      if (sizeBuffer.length !== 2) {
        logger.debug("cipher text structure is not matching, maybe the data is corrupt?");
        throw new Error("Invalid ciphertext structure: size buffer length mismatch.");
      }
      pos += 2;

      const partLength = sizeBuffer.readUInt16BE(0); // Parse length as big-endian
      const part = options.ciphertext.subarray(pos, pos + partLength);
      if (part.length !== partLength) {
        logger.debug("Cipher text structure altered. data corruption occurred.");
        throw new Error("Invalid ciphertext structure: part length mismatch.");
      }
      pos += partLength;

      parts.push(part);
    }

    if (parts.length !== 4) {
      logger.debug("Cipher text structure altered. data corruption occurred.");
      throw new Error("Invalid ciphertext structure: incorrect number of parts.");
    }

    const [encryptedKey, nonce, tag, encryptedText] = parts;

    const decryptOptions: DecryptRequest = {
      decryptDataDetails: {
        keyId: options.keyId,
        ciphertext: Buffer.from(encryptedKey).toString(BASE_64),
      }
    };
    if (options.keyVersionId) {
      logger.debug(`adding key version Id ${options.keyVersionId} to decryption payload`);
      decryptOptions.decryptDataDetails.keyVersionId = options.keyVersionId;
    }

    if (options.isAsymmetric) {
      logger.debug(`adding encryption value as ${EncryptDataDetails.EncryptionAlgorithm.RsaOaepSha256} to decryption payload`);
      decryptOptions.decryptDataDetails.encryptionAlgorithm = EncryptDataDetails.EncryptionAlgorithm.RsaOaepSha256;
    };

    const response: DecryptResponse = await options.cryptoClient.decrypt(
      decryptOptions
    );

    const decryptedKey = response.decryptedData.plaintext;

    const verificationStatus = await verifyDecryption(decryptedKey, response.decryptedData.plaintextChecksum);
    if (verificationStatus) {
      logger.debug("checksum validation failed while transporting data to oracle");
      throw new Error("Invalid ciphertext structure: checksum mismatch.");
    }

    const key = Buffer.from(decryptedKey, BASE_64);
    // Decrypt the message using AES-GCM
    const decipher = createDecipheriv(AES_256_GCM, key, nonce);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(encryptedText),
      decipher.final(),
    ]);

    logger.debug("decryption of data successful");
    // Convert decrypted data to a UTF-8 string
    return decrypted.toString(UTF_8_ENCODING);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err: any) {
    console.error("oracle KMS Storage failed to decrypt:", err.message);
    return ""; // Return empty string in case of an error
  }
}


async function verifyDecryption(decryptedData, ociChecksum) {
  const decryptedDataBuffer = Buffer.from(decryptedData, BASE_64);
  const checksum = calculate(decryptedDataBuffer);
  return checksum === ociChecksum;
}
