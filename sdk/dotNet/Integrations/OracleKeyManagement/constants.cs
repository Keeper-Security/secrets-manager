using Oci.KeymanagementService;
using System;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;

public static class IntegrationConstants
{
    // Supported Key Specs
    public static readonly byte[] BLOB_HEADER = { 0xFF, 0xFF }; // Encrypted BLOB Header: U+FFFF is a non-utf-8-character

    public const int HEADER_SIZE = 2;

    public const int AES_KEY_SIZE = 32;
    public const int NONCE_SIZE = 12;
    public const int AES_GCM_TAG_BYTE_SIZE = 16;

    public const int LENGTH_PREFIX_SIZE = 2;
}

public class Options
{
    public bool IsAsymmetric { get; set; }
    public KmsCryptoClient CryptoClient { get; set; }
    public string KeyId {get; set; }
    public string keyVersionId { get; set; }
}

public class BufferOptions : Options
{
    public string KeyPurpose { get; set; }
}

public class EncryptOptions : Options
{
    public string Message { get; set; }
}

public class DecryptOptions : Options
{
    public byte[] CipherText { get; set; }
}
