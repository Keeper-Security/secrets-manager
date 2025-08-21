import {
  EncryptResponse,
  EncryptCommand,
  DecryptCommand,
  EncryptCommandInput,
  DecryptCommandOutput,
  EncryptionAlgorithmSpec,
} from "@aws-sdk/client-kms";
import { DecryptBufferOptions, EncryptBufferOptions } from "./interface";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import {
  AES_256_GCM,
  BLOB_HEADER,
  LATIN1_ENCODING,
  UTF_8_ENCODING,
} from "./constants";
import { KeySpecEnum } from "./enum";
import pino from "pino";

export async function encryptBuffer(
  options: EncryptBufferOptions, logger: pino.Logger
): Promise<Buffer> {
  try {
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

    const encryptCommandOptions: EncryptCommandInput = {
      KeyId: options.keyId,
      Plaintext: key,
      EncryptionAlgorithm: options.encryptionAlgorithm,
    };

    if (options.keyType === KeySpecEnum.SYMMETRIC_DEFAULT) {
      delete encryptCommandOptions.EncryptionAlgorithm;
    }

    const encryptCommandPayload = new EncryptCommand(encryptCommandOptions);
    const response : EncryptResponse = await options.cryptoClient.send(
      encryptCommandPayload
    );
    const CiphertextBlob = response.CiphertextBlob ? Buffer.from(response.CiphertextBlob) : Buffer.alloc(0);
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

    return blob;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err: any) {
    logger.error("AWS KMS Storage failed to encrypt:", err.message);
    return Buffer.alloc(0); // Return empty buffer in case of an error
  }
}

export async function decryptBuffer(
  options: DecryptBufferOptions, logger: pino.Logger
): Promise<string> {
  try {
    // Validate BLOB_HEADER
    const header = Buffer.from(options.ciphertext.subarray(0, 2));
    if (!header.equals(Buffer.from(BLOB_HEADER, LATIN1_ENCODING))) {
      throw new Error("Invalid ciphertext structure: missing header.");
    }

    let pos = 2;
    const parts: Buffer[] = [];

    // Parse the ciphertext into its components
    for (let i = 0; i < 4; i++) {
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

    const decryptCommandOptions = {
      EncryptionAlgorithm: options.encryptionAlgorithm,
      KeyId: options.keyId,
      CiphertextBlob: encryptedKey,
    };

    if (options.keyType === KeySpecEnum.SYMMETRIC_DEFAULT) {
      decryptCommandOptions.EncryptionAlgorithm = EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT;
    }

    const decryptCommandPayload: DecryptCommand = new DecryptCommand(
      decryptCommandOptions
    );
    const response: DecryptCommandOutput = await options.cryptoClient.send(
      decryptCommandPayload
    );
    const key = response.Plaintext;
    if (!key) {
      logger.debug("Failed to retrieve plaintext key from decrypt command response as it was either empty or undefined.");
      throw new Error("Failed to retrieve plaintext key from decrypt command response.");
    }
    // Decrypt the message using AES-GCM
    const decipher = createDecipheriv(AES_256_GCM, key, nonce);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(encryptedText),
      decipher.final(),
    ]);

    // Convert decrypted data to a UTF-8 string
    return decrypted.toString(UTF_8_ENCODING);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err: any) {
    logger.error("AWS KMS Storage failed to decrypt:", err.message);
    return ""; // Return empty string in case of an error
  }
}