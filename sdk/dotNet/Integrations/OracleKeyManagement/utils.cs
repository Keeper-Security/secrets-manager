#nullable enable

using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Text;
using System.IO;
using System.Linq;
using Oci.KeymanagementService.Models;
using Microsoft.IdentityModel.Tokens;

public class IntegrationUtils
{
    private const int AesKeySize = IntegrationConstants.AES_KEY_SIZE; // 256-bit key
    private const int NonceSize = IntegrationConstants.NONCE_SIZE;  // AES-GCM nonce size

    public static async Task<byte[]> EncryptBufferAsync(EncryptOptions options, ILogger logger)
    {
        try
        {
            logger.LogInformation("Encrypting data");
            // Step 1: Generate a random 32-byte AES key
            byte[] key = GenerateRandomBytes(AesKeySize);

            // Step 2: Generate a 16-byte nonce
            byte[] nonce = GenerateRandomBytes(NonceSize);

            // Step 3: Encrypt the message using AES-GCM
            byte[] ciphertext, tag;
            using (AesGcm aes = new AesGcm(key, IntegrationConstants.AES_GCM_TAG_BYTE_SIZE))
            {
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(options.Message);
                ciphertext = new byte[plaintextBytes.Length];
                tag = new byte[AesGcm.TagByteSizes.MaxSize];

                aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
            }
            logger.LogDebug("AES encryption completed");
            EncryptDataDetails encryptDataDetails = new EncryptDataDetails
            {
                KeyId = options.KeyId,
                Plaintext = Convert.ToBase64String(key)
            };

            if (!options.keyVersionId.IsNullOrEmpty())
            {
                logger.LogDebug("Using key version id: {KeyVersionId}", options.keyVersionId);
                encryptDataDetails.KeyVersionId = options.keyVersionId;
            }

            if (options.IsAsymmetric)
            {
                logger.LogDebug("Using asymmetric encryption");
                encryptDataDetails.EncryptionAlgorithm = EncryptDataDetails.EncryptionAlgorithmEnum.RsaOaepSha256;
            }

            Oci.KeymanagementService.Requests.EncryptRequest encryptRequest = new Oci.KeymanagementService.Requests.EncryptRequest
            {
                EncryptDataDetails = encryptDataDetails
            };

            logger.LogDebug("Sending encrypt request");
            Oci.KeymanagementService.Responses.EncryptResponse encryptResponse = await options.CryptoClient.Encrypt(encryptRequest);
            logger.LogDebug("Received encrypt response");

            var EncryptedKeyString = encryptResponse.EncryptedData.Ciphertext;
            byte[] EncryptedKey = Convert.FromBase64String(EncryptedKeyString);

            // Step 5: Build the encrypted blob
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(ms))
                {
                    writer.Write(IntegrationConstants.BLOB_HEADER);
                    WriteLengthPrefixed(writer, EncryptedKey);
                    WriteLengthPrefixed(writer, nonce);
                    WriteLengthPrefixed(writer, tag);
                    WriteLengthPrefixed(writer, ciphertext);
                }
                logger.LogDebug("Completed writing to memory stream");
                return ms.ToArray();
            }
        }
        catch (Exception ex)
        {
            logger.LogCritical($"Oracle KMS Storage failed to encrypt: {ex.Message}");
            return Array.Empty<byte>(); // Return empty array in case of an error
        }
    }

    public static async Task<string> DecryptBufferAsync(DecryptOptions options, ILogger logger)
    {
        try
        {
            logger.LogInformation("Decrypting data");
            // Step 1: Validate BLOB_HEADER
            byte[] header = new byte[IntegrationConstants.HEADER_SIZE];
            Array.Copy(options.CipherText, header, IntegrationConstants.HEADER_SIZE);
            if (!header.AsEnumerable().SequenceEqual(IntegrationConstants.BLOB_HEADER))
            {
                logger.LogError("Invalid ciphertext structure: invalid header. Maybe the data is corrupted?");
                throw new InvalidOperationException("Invalid ciphertext structure: invalid header.");
            }

            int pos = IntegrationConstants.HEADER_SIZE;
            byte[][] parts = new byte[4][];

            // Step 2: Extract length-prefixed parts
            for (int i = 0; i < 4; i++)
            {
                if (pos + IntegrationConstants.LENGTH_PREFIX_SIZE > options.CipherText.Length)
                {
                    logger.LogError("Invalid ciphertext structure: size buffer length mismatch.");
                    throw new InvalidOperationException("Invalid ciphertext structure: size buffer length mismatch.");
                }

                ushort partLength = BitConverter.ToUInt16(options.CipherText, pos);
                pos += IntegrationConstants.LENGTH_PREFIX_SIZE;

                if (pos + partLength > options.CipherText.Length)
                {
                    logger.LogError("Invalid ciphertext structure: part length mismatch.");
                    throw new InvalidOperationException("Invalid ciphertext structure: part length mismatch.");
                }

                parts[i] = options.CipherText[pos..(pos + partLength)];
                pos += partLength;
            }

            if (parts.Length != 4)
            {
                logger.LogError("Invalid ciphertext structure: incorrect number of parts.");
                throw new InvalidOperationException("Invalid ciphertext structure: incorrect number of parts.");
            }

            byte[] encryptedKey = parts[0];
            byte[] nonce = parts[1];
            byte[] tag = parts[2];
            byte[] encryptedText = parts[3];

            DecryptDataDetails decryptDataDetails = new DecryptDataDetails
            {
                Ciphertext = Convert.ToBase64String(encryptedKey),
                KeyId = options.KeyId
            };

            if (!options.keyVersionId.IsNullOrEmpty())
            {
                logger.LogInformation("Using key version id: {KeyVersionId}", options.keyVersionId);
                decryptDataDetails.KeyVersionId = options.keyVersionId;
            }

            if (options.IsAsymmetric)
            {
                logger.LogInformation("Using asymmetric encryption for decrypt operation");
                decryptDataDetails.EncryptionAlgorithm = DecryptDataDetails.EncryptionAlgorithmEnum.RsaOaepSha256;
            }

            Oci.KeymanagementService.Requests.DecryptRequest decryptRequest = new Oci.KeymanagementService.Requests.DecryptRequest
            {
                DecryptDataDetails = decryptDataDetails
            };

            logger.LogDebug("Decrypting key using Oci KeyManagement Key");
            // Step 3: Decrypt AES key using Oci KeyManagement Key
            Oci.KeymanagementService.Responses.DecryptResponse decryptResponse = await options.CryptoClient.Decrypt(decryptRequest);
            logger.LogDebug("Decrypted key using Oci KeyManagement Key");

            var DecryptedKeyString = decryptResponse.DecryptedData.Plaintext;
            byte[] decryptedKey = Convert.FromBase64String(DecryptedKeyString);

            // Step 4: Decrypt the message using AES-GCM
            try
            {
                logger.LogDebug("Decrypting data using AES-GCM");
                using AesGcm aesGcm = new AesGcm(decryptedKey, IntegrationConstants.AES_GCM_TAG_BYTE_SIZE);
                byte[] decryptedData = new byte[encryptedText.Length];

                aesGcm.Decrypt(nonce, encryptedText, tag, decryptedData);
                logger.LogDebug("Decrypted data using AES-GCM");
                // Step 5: Convert decrypted data to a UTF-8 string
                return Encoding.UTF8.GetString(decryptedData);
            }
            catch (Exception ex)
            {
                logger.LogError($"Decryption failed: {ex.Message}");
                return string.Empty;
            }
        }
        catch (Exception ex)
        {
            logger.LogError($"Oracle Key Management Storage failed to decrypt: {ex.Message}");
            return string.Empty;
        }
    }

    private static byte[] GenerateRandomBytes(int size)
    {
        byte[] bytes = new byte[size];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    private static void WriteLengthPrefixed(BinaryWriter writer, byte[] data)
    {
        writer.Write((ushort)data.Length);
        writer.Write(data);
    }
}

