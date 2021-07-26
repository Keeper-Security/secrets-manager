using System;
using System.IO;
using System.Linq;
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

    public class GetPayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string publicKey { get; }
        public string[] requestedRecords { get; }

        public GetPayload(string clientVersion, string clientId, string publicKey, string[] requestedRecords)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.publicKey = publicKey;
            this.requestedRecords = requestedRecords;
        }
    }

    public interface IKeyValueStorage
    {
        string GetString(string key);
        byte[] GetBytes(string key);
        void SaveString(string key, string value);
        void SaveBytes(string key, byte[] value);
    }

    public static class SecretsManagerClient
    {
        static readonly string KEY_HOSTNAME = "hostname"; // base url for the Secrets Manager service
        static readonly string KEY_SERVER_PUBIC_KEY_ID = "serverPublicKeyId";
        static readonly string KEY_CLIENT_ID = "clientId";
        static readonly string KEY_CLIENT_KEY = "clientKey"; // The key that is used to identify the client before public key
        static readonly string KEY_APP_KEY = "appKey"; // The application key with which all secrets are encrypted
        static readonly string KEY_PRIVATE_KEY = "privateKey"; // The client's private key
        static readonly string KEY_PUBLIC_KEY = "publicKey"; // The client's public key
        static readonly string CLIENT_ID_HASH_TAG = "KEEPER_SECRETS_MANAGER_CLIENT_ID"; // Tag for hashing the client key to client id

        public static void InitializeStorage(IKeyValueStorage storage, string clientKey, string hostName)
        {
            var existingClientId = storage.GetString(KEY_CLIENT_ID);
            if (existingClientId != null && clientKey == null)
            {
                return;
            }

            if (clientKey == null)
            {
                throw new Exception("Storage is not initialized");
            }

            var clientKeyBytes = CryptoUtils.WebSafe64ToBytes(clientKey);
            var clientKeyHash = CryptoUtils.Hash(clientKeyBytes, CLIENT_ID_HASH_TAG);
            var clientId = CryptoUtils.BytesToBase64(clientKeyHash);
            if (existingClientId != null && existingClientId == clientId)
            {
                return; // the storage is already initialized
            }

            if (existingClientId != null)
            {
                throw new Exception($"The storage is already initialized with a different client Id ({existingClientId})");
            }

            storage.SaveString(KEY_HOSTNAME, hostName);
            storage.SaveString(KEY_CLIENT_ID, clientId);
            storage.SaveBytes(KEY_CLIENT_KEY, clientKeyBytes);
            var keyPair = CryptoUtils.GenerateKeyPair();
            storage.SaveBytes(KEY_PUBLIC_KEY, keyPair.Item1);
            storage.SaveBytes(KEY_PRIVATE_KEY, keyPair.Item2);
        }

        public static string GetSecrets()
        {
            return "Secrets";
        }

        public static async Task<string> FetchAndDecryptSecrets(IKeyValueStorage storage, string[] recordsFilter = null)
        {
            var payload = PrepareGetPayload(storage, recordsFilter);
            var httpResponse = await PostQuery(storage, "get_secret", payload);
            return httpResponse;
        }

        static GetPayload PrepareGetPayload(IKeyValueStorage storage, string[] recordsFilter)
        {
            var clientId = storage.GetString(KEY_CLIENT_ID);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            string publicKey = null;
            var appKey = storage.GetString(KEY_APP_KEY);
            if (appKey == null)
            {
                var publicKeyBytes = storage.GetBytes(KEY_PUBLIC_KEY);
                if (publicKeyBytes == null)
                {
                    throw new Exception("Public key is missing from the storage");
                }

                publicKey = CryptoUtils.BytesToBase64(publicKeyBytes);
            }

            return new GetPayload("mn16.0.0", clientId, publicKey, recordsFilter);
        }

        private static readonly byte[][] KeeperPublicKeys =
        {
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
        };

        static TransmissionKey GenerateTransmissionKey(IKeyValueStorage storage)
        {
            var transmissionKey = CryptoUtils.GetRandomBytes(32);
            var keyNumberString = storage.GetString(KEY_SERVER_PUBIC_KEY_ID);
            var keyNumber = keyNumberString == null ? 1 : int.Parse(keyNumberString);
            var encryptedKey = CryptoUtils.PublicEncrypt(transmissionKey, KeeperPublicKeys[keyNumber - 1]);
            return new TransmissionKey(keyNumber, transmissionKey, encryptedKey);
        }

        private static Tuple<byte[], byte[]> encryptAndSignPayload<T>(IKeyValueStorage storage, TransmissionKey transmissionKey, T payload)
        {
            var payloadBytes = JsonUtils.SerializeJson(payload);
            var encryptedPayload = CryptoUtils.Encrypt(payloadBytes, transmissionKey.Key);
            var privateKey = storage.GetBytes(KEY_PRIVATE_KEY);
            if (privateKey == null)
            {
                throw new Exception("Private key is missing from the storage");
            }

            var signatureBase = transmissionKey.EncryptedKey.Concat(encryptedPayload).ToArray();
            var signature = CryptoUtils.Sign(signatureBase, privateKey);
            return new Tuple<byte[], byte[]>(encryptedPayload, signature);
        }

        public static async Task<string> PostQuery<T>(IKeyValueStorage storage, string path, T payload)
        {
            var hostName = "dev.keepersecurity.com";
            var url = $"https://{hostName}/api/rest/sm/v1/get_secret/{path}";
            // WebRequest.Create();
            var request = (HttpWebRequest) WebRequest.Create(url);
            while (true)
            {
                var transmissionKey = GenerateTransmissionKey(storage);
                var encryptedPayload = encryptAndSignPayload(storage, transmissionKey, payload);
                // request.UserAgent = "KeeperSDK.Net/" + ClientVersion;
                request.ContentType = "application/octet-stream";
                request.Headers["PublicKeyId"] = transmissionKey.PublicKeyId.ToString();
                request.Headers["TransmissionKey"] = CryptoUtils.BytesToBase64(transmissionKey.EncryptedKey);
                request.Headers["Authorization"] = $"Signature {CryptoUtils.BytesToBase64(encryptedPayload.Item2)}";
                request.Method = "POST";

                HttpWebResponse response;
                try
                {
                    using (var requestStream = request.GetRequestStream())
                    {
                        await requestStream.WriteAsync(encryptedPayload.Item1, 0, encryptedPayload.Item1.Length);
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
}