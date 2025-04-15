using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Microsoft.Extensions.Logging;


public class IntegrationUtils
{
    private const int AesKeySize = IntegrationConstants.AES_KEY_SIZE; // 256-bit key
    private const int NonceSize = IntegrationConstants.NONCE_SIZE;  // AES-GCM nonce size

    public static async Task<byte[]> EncryptBufferAsync(AmazonKeyManagementServiceClient AWSKvStorageCryptoClient, EncryptBufferOptions options, ILogger logger)
    {
        try
        {
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


            EncryptRequest encryptRequest;
            if (options.KeyType == KeySpecEnum.SYMMETRIC_DEFAULT)
            {
                encryptRequest = new EncryptRequest
                {
                    KeyId = options.KeyId,
                    Plaintext = new MemoryStream(key),

                };
            }
            else
            {
                encryptRequest = new EncryptRequest
                {
                    KeyId = options.KeyId,
                    Plaintext = new MemoryStream(key),
                    EncryptionAlgorithm = EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256
                };
            }

            var response = await AWSKvStorageCryptoClient.EncryptAsync(encryptRequest);

            var EncryptedKey = response.CiphertextBlob.ToArray();


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
                return ms.ToArray();
            }
        }
        catch (Exception ex)
        {
            logger.LogCritical($"AWS KMS Storage failed to encrypt: {ex.Message}");
            return Array.Empty<byte>(); // Return empty array in case of an error
        }
    }

    public static async Task<string> DecryptBufferAsync(AmazonKeyManagementServiceClient AWSKeyManagementCryptoClient, DecryptBufferOptions options, ILogger logger)
    {
        try
        {
            // Step 1: Validate BLOB_HEADER
            byte[] header = new byte[IntegrationConstants.HEADER_SIZE];
            Array.Copy(options.Ciphertext, header, IntegrationConstants.HEADER_SIZE);
            if (!header.AsEnumerable().SequenceEqual(IntegrationConstants.BLOB_HEADER))
            {
                throw new InvalidOperationException("Invalid ciphertext structure: invalid header.");
            }

            int pos = IntegrationConstants.HEADER_SIZE;
            byte[][] parts = new byte[4][];

            // Step 2: Extract length-prefixed parts
            for (int i = 0; i < 4; i++)
            {
                if (pos + IntegrationConstants.LENGTH_PREFIX_SIZE > options.Ciphertext.Length)
                    throw new InvalidOperationException("Invalid ciphertext structure: size buffer length mismatch.");

                ushort partLength = BitConverter.ToUInt16(options.Ciphertext, pos);
                pos += IntegrationConstants.LENGTH_PREFIX_SIZE;

                if (pos + partLength > options.Ciphertext.Length)
                    throw new InvalidOperationException("Invalid ciphertext structure: part length mismatch.");

                parts[i] = options.Ciphertext[pos..(pos + partLength)];
                pos += partLength;
            }

            if (parts.Length != 4)
                throw new InvalidOperationException("Invalid ciphertext structure: incorrect number of parts.");

            byte[] encryptedKey = parts[0];
            byte[] nonce = parts[1];
            byte[] tag = parts[2];
            byte[] encryptedText = parts[3];


            // Step 3: Unwrap AES key using AWS KMS
            DecryptRequest decryptRequest;
            if (options.KeyType == KeySpecEnum.SYMMETRIC_DEFAULT)
            {
                decryptRequest = new DecryptRequest
                {
                    KeyId = options.KeyId,
                    CiphertextBlob = new MemoryStream(encryptedKey),

                };
            }
            else
            {
                decryptRequest = new DecryptRequest
                {
                    KeyId = options.KeyId,
                    CiphertextBlob = new MemoryStream(encryptedKey),
                    EncryptionAlgorithm = EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256
                };
            }

            var response = await AWSKeyManagementCryptoClient.DecryptAsync(decryptRequest);

            var decryptedKey = response.Plaintext.ToArray();

            // Step 4: Decrypt the message using AES-GCM
            try
            {
                using AesGcm aesGcm = new AesGcm(decryptedKey, IntegrationConstants.AES_GCM_TAG_BYTE_SIZE);
                byte[] decryptedData = new byte[encryptedText.Length];

                aesGcm.Decrypt(nonce, encryptedText, tag, decryptedData);

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
            logger.LogError($"AWS KMS Storage failed to decrypt: {ex.Message}");
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

