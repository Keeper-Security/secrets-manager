using Google.Cloud.Kms.V1;
using System;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;

public static class IntegrationConstants
{
    // Supported Key Specs
    public static readonly string[] SupportedKeySpecs = 
    {
        KeyPurposeHelper.GetEnumMemberValue(KeyPurpose.RAW_ENCRYPT_DECRYPT),
        KeyPurposeHelper.GetEnumMemberValue(KeyPurpose.ASYMMETRIC_DECRYPT)
    };

    public static readonly byte[] BLOB_HEADER = { 0xFF, 0xFF }; // Encrypted BLOB Header: U+FFFF is a non-utf-8-character

    public const int HEADER_SIZE = 2;

    public const int AES_KEY_SIZE = 32;
    public const int NONCE_SIZE = 12;
    public const int AES_GCM_TAG_BYTE_SIZE = 16;

    public const int LENGTH_PREFIX_SIZE = 2;
    public static readonly string[] SupportedKeyPurpose =
    {
        KeyPurpose.RAW_ENCRYPT_DECRYPT.ToString(),
        KeyPurpose.ENCRYPT_DECRYPT.ToString(),
        KeyPurpose.ASYMMETRIC_DECRYPT.ToString()
    };
}

public enum KeyPurpose
{
    [EnumMember(Value = "EncryptDecrypt")]
    ENCRYPT_DECRYPT,

    [EnumMember(Value = "AsymmetricDecrypt")]
    ASYMMETRIC_DECRYPT,

    [EnumMember(Value = "Unspecified")]
    CRYPTO_KEY_PURPOSE_UNSPECIFIED,

    [EnumMember(Value = "AsymmetricSign")]
    ASYMMETRIC_SIGN,

    [EnumMember(Value = "RawEncryptDecrypt")]
    RAW_ENCRYPT_DECRYPT,

    [EnumMember(Value = "Mac")]
    MAC
}

public class Options
{
    public bool IsAsymmetric { get; set; }
    public KeyManagementServiceClient CryptoClient { get; set; }
    public GCPKeyConfig KeyProperties { get; set; }
    public string EncryptionAlgorithm { get; set; }
}

public class BufferOptions : Options
{
    public string KeyPurpose { get; set; }
}

public class EncryptBufferOptions : BufferOptions
{
    public string Message { get; set; }
}

public class DecryptBufferOptions : BufferOptions
{
    public byte[] Ciphertext { get; set; }
}

public class EncryptOptions : Options
{
    public byte[] Message { get; set; }
}

public class DecryptOptions : Options
{
    public byte[] CipherText { get; set; }
}

public static class KeyPurposeHelper
{
    public static string GetEnumMemberValue(Enum enumValue)
    {
        var type = enumValue.GetType();
        var member = type.GetMember(enumValue.ToString()).FirstOrDefault();
        var attribute = member?.GetCustomAttribute<EnumMemberAttribute>();
        return attribute?.Value ?? enumValue.ToString();
    }
}