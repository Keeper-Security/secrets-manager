using Amazon.KeyManagementService;

public static class IntegrationConstants
{
    // Supported Key Specs
    public static readonly string[] SupportedKeySpecs = 
    {
        KeySpecEnum.RSA_2048,
        KeySpecEnum.RSA_4096,
        KeySpecEnum.RSA_3072,
        KeySpecEnum.SYMMETRIC_DEFAULT
    };

    public static readonly byte[] BLOB_HEADER = { 0xFF, 0xFF }; // Encrypted BLOB Header: U+FFFF is a non-character

    public const int HEADER_SIZE = 2;

    public const int AES_KEY_SIZE = 32;
    public const int NONCE_SIZE = 12;
    public const int AES_GCM_TAG_BYTE_SIZE = 16;

    public const int LENGTH_PREFIX_SIZE = 2;
}

public static class KeySpecEnum
{
    public const string RSA_2048 = "RSA_2048";
    public const string RSA_4096 = "RSA_4096";
    public const string RSA_3072 = "RSA_3072";
    public const string SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT";
}

public class BufferOptions
{
    public string KeyId { get; set; }
    public string EncryptionAlgorithm { get; set; } // Assuming string, or use an Enum
    public AmazonKeyManagementServiceClient CryptoClient { get; set; }
    public string KeyType { get; set; }
}

public class EncryptBufferOptions : BufferOptions
{
    public string Message { get; set; }
}

public class DecryptBufferOptions : BufferOptions
{
    public byte[] Ciphertext { get; set; }
}
