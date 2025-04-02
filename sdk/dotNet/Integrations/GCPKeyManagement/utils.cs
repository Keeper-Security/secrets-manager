#nullable enable

using Google.Cloud.Kms.V1;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Google.Protobuf;
using Microsoft.Extensions.Logging;
using System.Text;
using System.IO;
using System.Linq;

public class IntegrationUtils
{
    private const int AesKeySize = IntegrationConstants.AES_KEY_SIZE; // 256-bit key
    private const int NonceSize = IntegrationConstants.NONCE_SIZE;  // AES-GCM nonce size

    public static async Task<byte[]> EncryptBufferAsync(EncryptBufferOptions options, ILogger logger)
    {
        logger.LogInformation("Encrypting buffer...");
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
            logger.LogDebug("Encryption with AES key completed");
            var encryptOptions = new EncryptOptions
            {
                KeyProperties = options.KeyProperties,
                Message = key,
                CryptoClient = options.CryptoClient,
                IsAsymmetric = options.IsAsymmetric,
                EncryptionAlgorithm = options.EncryptionAlgorithm,
            };

            var EncryptedKey = options.IsAsymmetric ? await EncryptDataAsymmetric(encryptOptions,logger) : await EncryptDataSymmetric(encryptOptions,logger);
            logger.LogDebug("Encryption with KMS key completed");
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
                logger.LogDebug("Encryption completed and encoding and creating file content completed");
                return ms.ToArray();
            }
        }
        catch (Exception ex)
        {
            logger.LogCritical($"GCP KMS Storage failed to encrypt: {ex.Message}");
            return Array.Empty<byte>(); // Return empty array in case of an error
        }
    }

    public static async Task<string> DecryptBufferAsync(DecryptBufferOptions options, ILogger logger)
    {
        try
        {
            logger.LogInformation("Decrypting buffer...");
            // Step 1: Validate BLOB_HEADER
            byte[] header = new byte[IntegrationConstants.HEADER_SIZE];
            Array.Copy(options.Ciphertext, header, IntegrationConstants.HEADER_SIZE);
            if (!header.AsEnumerable().SequenceEqual(IntegrationConstants.BLOB_HEADER))
            {
                logger.LogError("Invalid ciphertext structure: invalid header. maybe the data is corrupted.");
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
            logger.LogDebug("Splitting the decryption data content into parts is completed. Success is still pending");
            if (parts.Length != 4){
                logger.LogError("Invalid ciphertext structure: incorrect number of parts. maybe the data is corrupted.");
                throw new InvalidOperationException("Invalid ciphertext structure: incorrect number of parts.");
            }

            byte[] encryptedKey = parts[0];
            byte[] nonce = parts[1];
            byte[] tag = parts[2];
            byte[] encryptedText = parts[3];


            // Step 3: Unwrap AES key using GCPKeyManagement Key
            var decryptData = new DecryptOptions
            {
                KeyProperties = options.KeyProperties,
                CipherText = encryptedKey,
                CryptoClient = options.CryptoClient,
                IsAsymmetric = options.IsAsymmetric,
                EncryptionAlgorithm = options.EncryptionAlgorithm,
            };

            var decryptedKey = await DecryptData(decryptData,logger);
            logger.LogDebug("Decryption with KMS key completed");
            // Step 4: Decrypt the message using AES-GCM
            try
            {
                using AesGcm aesGcm = new AesGcm(decryptedKey, IntegrationConstants.AES_GCM_TAG_BYTE_SIZE);
                byte[] decryptedData = new byte[encryptedText.Length];

                aesGcm.Decrypt(nonce, encryptedText, tag, decryptedData);
                logger.LogDebug("Decryption with AES key completed");
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
            logger.LogError($"GCP Key Management Storage failed to decrypt: {ex.Message}");
            return string.Empty;
        }
    }


    public static async Task<byte[]> EncryptDataAsymmetric(EncryptOptions options,ILogger logger)
    {   
        logger.LogDebug("trying to Extract resource name");
        string keyName = options.KeyProperties.ToResourceName();
        
        // Get the public key from Cloud KMS
        PublicKey publicKey = await options.CryptoClient.GetPublicKeyAsync(new GetPublicKeyRequest { Name = keyName });
        logger.LogDebug("Trying to extract public key from given resource name");

        if (publicKey.Name != keyName)
        {
            logger.LogError("GetPublicKey: request corrupted in-transit/ wrong key retrieved. expected {expectedKeyName} but got {receivedKeyName}", keyName, publicKey.Name);
            throw new Exception("GetPublicKey: request corrupted in-transit");
        }

        string[] blocks = publicKey.Pem.Split("-", StringSplitOptions.RemoveEmptyEntries);
        byte[] pem = Convert.FromBase64String(blocks[1]);
        logger.LogDebug("Extracted public key from given resource name, converted from pem to bytes. RSA encryption pending.");

        // Encrypt using RSA and OAEP padding
        using RSA rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(pem, out _);

        RSAEncryptionPadding padding = GetPadding(options.EncryptionAlgorithm,logger);
        byte[] ciphertext = rsa.Encrypt(options.Message, padding);
        logger.LogDebug("RSA encryption completed");
        return ciphertext;
    }

    public static async Task<byte[]> EncryptDataSymmetric(EncryptOptions options,ILogger logger)
    {
        logger.LogDebug("trying to Extract resource name");
        string keyName = options.KeyProperties.ToResourceName();
        byte[] encodedData = options.Message;

        var kmsClient = options.CryptoClient;
        var request = new EncryptRequest
        {
            Name = keyName,
            Plaintext = ByteString.CopyFrom(encodedData),
        };
        logger.LogDebug("Trying to encrypt data with given resource name");
        EncryptResponse encryptResponse = await kmsClient.EncryptAsync(request);
        byte[] ciphertext = encryptResponse.Ciphertext.ToByteArray();
        logger.LogDebug("Encryption with KMS key completed");
        return ciphertext;
    }

    public static async Task<byte[]> DecryptData(
        DecryptOptions options,ILogger logger)
    {

        if (options.IsAsymmetric)
        {
            logger.LogDebug("Received asymmetric decryption request");
            var request = new AsymmetricDecryptRequest
            {
                Name = options.KeyProperties.ToResourceName(),
                Ciphertext = ByteString.CopyFrom(options.CipherText),
            };
            logger.LogDebug("Trying to decrypt data with given resource name {resourceName}", request.Name);
            var response = await options.CryptoClient.AsymmetricDecryptAsync(request);
            logger.LogDebug("Decryption with KMS key completed");
            return response.Plaintext.ToByteArray();
        }
        else
        {
            logger.LogDebug("Received symmetric decryption request");
            var request = new DecryptRequest
            {
                Name = options.KeyProperties.ToKeyName(),
                Ciphertext = ByteString.CopyFrom(options.CipherText),
            };
            logger.LogDebug("Trying to decrypt data with given resource name {resourceName}", request.Name);
            var response = await options.CryptoClient.DecryptAsync(request);
            logger.LogDebug("Decryption with KMS key completed");
            return response.Plaintext.ToByteArray();
        }
    }


    private static RSAEncryptionPadding GetPadding(string encryptionAlgorithm,ILogger logger)
    {
        if (SupportedEncryptionAlgorithms.TryGetValue(encryptionAlgorithm, out RSAEncryptionPadding? hashAlgorithm))
        {
            return hashAlgorithm;
        }
        logger.LogError("Unsupported encryption algorithm is used for the provided key: {}", encryptionAlgorithm);
        throw new Exception("Unsupported encryption algorithm is used for the provided key");
        
    }

    private static readonly System.Collections.Generic.Dictionary<string, RSAEncryptionPadding> SupportedEncryptionAlgorithms = new()
    {
        { "RsaDecryptOaep2048Sha256", RSAEncryptionPadding.OaepSHA256 },
        { "RsaDecryptOaep3072Sha256", RSAEncryptionPadding.OaepSHA256},
        { "RsaDecryptOaep4096Sha256", RSAEncryptionPadding.OaepSHA256},
        { "RsaDecryptOaep4096Sha512", RSAEncryptionPadding.OaepSHA512 },
        { "RsaDecryptOaep2048Sha1", RSAEncryptionPadding.OaepSHA1 },
        { "RsaDecryptOaep3072Sha1", RSAEncryptionPadding.OaepSHA1 },
        { "RsaDecryptOaep4096Sha1", RSAEncryptionPadding.OaepSHA1 }
    };


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

