using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;

namespace SecretsManager
{
    public class TransmissionKey
    {
        public int PublicKeyId { get; }
        public byte[] Key { get; }
        public byte[] EncryptedKey { get; }

        public TransmissionKey(int publicKeyId, byte[] key, byte[] encryptedKey)
        {
            PublicKeyId = publicKeyId;
            Key = key;
            EncryptedKey = encryptedKey;
        }
    }

    public interface IKeyValueStorage
    {
        string GetString(string key);
    }

    public static class SecretsManagerClient
    {
        static readonly string KEY_URL = "url"; // base url for the Secrets Manager service
        static readonly string KEY_CLIENT_ID = "clientId";

        static readonly string
            KEY_CLIENT_KEY = "clientKey"; // The key that is used to identify the client before public key

        static readonly string KEY_APP_KEY = "appKey"; // The application key with which all secrets are encrypted
        static readonly string KEY_PRIVATE_KEY = "privateKey"; // The client's private key
        static readonly string KEY_PUBLIC_KEY = "publicKey"; // The client's public key

        static readonly string
            CLIENT_ID_HASH_TAG = "KEEPER_SECRETS_MANAGER_CLIENT_ID"; // Tag for hashing the client key to client id

        public static string GetSecrets()
        {
            return "Secrets";
        }

        public static async Task<string> FetchAndDecryptSecrets(IKeyValueStorage storage, string[] recordsFilter = null)
        {
            var transmissionKey = GenerateTransmissionKey(1);
            var encryptedPayload = PrepareGetPayload(storage, transmissionKey, recordsFilter);
            var httpResponse = await PostQuery(storage, "get_secret", transmissionKey, encryptedPayload);
            return httpResponse;
        }

        static byte[] PrepareGetPayload(IKeyValueStorage storage, TransmissionKey transmissionKey,
            string[] recordsFilter)
        {
            var clientId = storage.GetString(KEY_CLIENT_ID);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            return new byte[] {1};
        }

        private static readonly byte[][] KeeperPublicKeys =
        {
            CryptoUtils.WebSafe64ToBytes(
                "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes(
                "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes(
                "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes(
                "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes(
                "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes(
                "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
        };

        static TransmissionKey GenerateTransmissionKey(int keyNumber)
        {
            var transmissionKey = CryptoUtils.GetRandomBytes(32);
            var encryptedKey = CryptoUtils.PublicEncrypt(transmissionKey, KeeperPublicKeys[keyNumber - 1]);
            return new TransmissionKey(keyNumber, transmissionKey, encryptedKey);
        }

        public static async Task<string> PostQuery(IKeyValueStorage keyValueStorage, string getSecret,
            TransmissionKey transmissionKey, byte[] payload)
        {
            // WebRequest.Create();

            var request =
                (HttpWebRequest) WebRequest.Create("https://dev.keepersecurity.com/api/rest/sm/v1/get_secret");

            // request.UserAgent = "KeeperSDK.Net/" + ClientVersion;
            request.ContentType = "application/octet-stream";
            request.Headers["PublicKeyId"] = transmissionKey.PublicKeyId.ToString();
            request.Method = "POST";

            HttpWebResponse response;
            try
            {
                using (var requestStream = request.GetRequestStream())
                {
                    await requestStream.WriteAsync(payload, 0, payload.Length);
                }

                response = (HttpWebResponse) request.GetResponse();
                Console.WriteLine(response);
            }
            catch (WebException e)
            {
                response = (HttpWebResponse) e.Response;
                var errorMsg = await new StreamReader(
                        response.GetResponseStream() ?? throw new InvalidOperationException("Response was expected but not received"))
                    .ReadToEndAsync();
                Console.WriteLine(errorMsg);
                if (response == null) throw;
            }

            // var client = new HttpClient
            // {
            //     Timeout = TimeSpan.FromSeconds(10)
            // };
            //
            // var bodyBytes = new ByteArrayContent(payload);
            // // bodyBytes.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            //
            // var response = await client.PostAsync("https://dev.keepersecurity.com/api/rest/sm/v1/get_secret", bodyBytes);
            // var responseContent = await response.Content.ReadAsStringAsync();
            // Console.WriteLine(responseContent);
            return "ok";
        }
    }
}