using System;
using System.Buffers.Text;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace SecretsManager
{
    public static class CryptoUtils
    {
        static readonly RNGCryptoServiceProvider RngCsp = new RNGCryptoServiceProvider();

        public static byte[] GetRandomBytes(int length)
        {
            var bytes = new byte[length];
            RngCsp.GetBytes(bytes);
            return bytes;
        }


        public static byte[] WebSafe64ToBytes(string data)
        {
            if (data == null) return null;
            var base64 = data
                .Replace("-", "+")
                .Replace("_", "/")
                .Replace("=", "")
                .Replace("\r", "")
                .Replace("\n", "");
            base64 = base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
            return Convert.FromBase64String(base64);
        }

        public static byte[] PublicEncrypt(byte[] transmissionKey, byte[] keeperPublicKey)
        {
            return transmissionKey;
        }
    }

    public class TransmissionKey
    {
        public TransmissionKey(int keyNumber, byte[] transmissionKey)
        {
        }
    }

    public interface KeyValueStorage
    {
        string GetString(string key);
    }

    public static class SecretsManagerClient
    {
        static readonly string KEY_URL = "url"; // base url for the Secrets Manager service
        static readonly string KEY_CLIENT_ID = "clientId";
        static readonly string KEY_CLIENT_KEY = "clientKey"; // The key that is used to identify the client before public key
        static readonly string KEY_APP_KEY = "appKey"; // The application key with which all secrets are encrypted
        static readonly string KEY_PRIVATE_KEY = "privateKey"; // The client's private key
        static readonly string KEY_PUBLIC_KEY = "publicKey"; // The client's public key
        static readonly string CLIENT_ID_HASH_TAG = "KEEPER_SECRETS_MANAGER_CLIENT_ID"; // Tag for hashing the client key to client id

        public static string GetSecrets()
        {
            return "Secrets";
        }

        public static async Task<string> FetchAndDecryptSecrets(KeyValueStorage storage, string[] recordsFilter = null)
        {
            var transmissionKey = GenerateTransmissionKey(1);
            var encryptedPayload = PrepareGetPayload(storage, transmissionKey, recordsFilter);
            var httpResponse = await PostQuery(storage, "get_secret", transmissionKey, encryptedPayload);
            return httpResponse;
        }

        static byte[] PrepareGetPayload(KeyValueStorage storage, TransmissionKey transmissionKey, string[] recordsFilter)
        {
            var clientId = storage.GetString(KEY_CLIENT_ID);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }
            return new byte[] { 1 };
        }

        static readonly byte[][] KeeperPublicKeys =
        {
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
        };

        static TransmissionKey GenerateTransmissionKey(int keyNumber)
        {
            var transmissionKey = CryptoUtils.GetRandomBytes(32);
            var encryptedKey = CryptoUtils.PublicEncrypt(transmissionKey, KeeperPublicKeys[keyNumber - 1]);
            return new TransmissionKey(keyNumber, transmissionKey);
        }

        public static async Task<string> PostQuery(KeyValueStorage keyValueStorage, string getSecret, TransmissionKey transmissionKey, byte[] payload)
        {
            var client = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(10)
            };

            var bodyBytes = new ByteArrayContent(payload);
            // bodyBytes.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var response = await client.PostAsync("https://dev.keepersecurity.com/api/rest/sm/v1/get_secret", bodyBytes);
            Console.WriteLine(response);
            return "ok";
        }
    }
}