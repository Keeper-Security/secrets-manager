public static class IntegrationConstants
{
    public static readonly byte[] BLOB_HEADER = { 0xFF, 0xFF }; // Encrypted BLOB Header: U+FFFF is a non-character
    internal static readonly int LENGTH_PREFIX_SIZE = 2;
    public const string LATIN1_ENCODING = "ISO-8859-1"; // Latin-1 encoding equivalent
    public const string UTF_8_ENCODING = "utf-8";
    public const string AES_256_GCM = "AES-GCM";
    public const string RSA_OAEP = "RSA-OAEP";
    public const string DEFAULT_AZURE_CREDENTIAL_ENVIRONMENTAL_VARIABLE = "KSM_AZ_KEY_ID";
    public const string MD5_HASH = "MD5";
    public const string HEX_DIGEST = "hex";
    public const int DEFAULT_JSON_INDENT = 4;
    public const int HEADER_SIZE = 2;
    public const int AES_KEY_SIZE = 32;
    public const int NONCE_SIZE = 12;
    public const int AES_GCM_TAG_BYTE_SIZE = 16;
    public const int RSA_OAEP_KEY_SIZE = 2048;
}
