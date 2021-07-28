using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Threading.Tasks;

namespace SecretsManager
{
    public interface IKeyValueStorage
    {
        string GetString(string key);
        byte[] GetBytes(string key);
        void SaveString(string key, string value);
        void SaveBytes(string key, byte[] value);
        void Delete(string key);
    }

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

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [DataContract]
    public class GetPayload
    {
        [DataMember] public string clientVersion { get; set; }
        [DataMember] public string clientId { get; set; }
        [DataMember] public string publicKey { get; set; }
        [DataMember] public string[] requestedRecords { get; set; }

        public GetPayload(string clientVersion, string clientId, string publicKey, string[] requestedRecords)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.publicKey = publicKey;
            this.requestedRecords = requestedRecords;
        }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [DataContract]
    public class SecretsManagerResponse
    {
        [DataMember] public string encryptedAppKey { get; set; }
        [DataMember] public SecretsManagerResponseFolder[] folders { get; set; }
        [DataMember] public SecretsManagerResponseRecord[] records { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [DataContract]
    public class SecretsManagerResponseFolder
    {
        [DataMember] public string folderUid { get; set; }
        [DataMember] public string folderKey { get; set; }
        [DataMember] public SecretsManagerResponseRecord[] records { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [DataContract]
    public class SecretsManagerResponseRecord
    {
        [DataMember] public string recordUid { get; set; }
        [DataMember] public string recordKey { get; set; }
        [DataMember] public string data { get; set; }
        [DataMember] public string isEditable { get; set; }
        [DataMember] public SecretsManagerResponseFile[] files { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [DataContract]
    public class SecretsManagerResponseFile
    {
        [DataMember] public string fileUid { get; set; }
        [DataMember] public string fileKey { get; set; }
        [DataMember] public string data { get; set; }
        [DataMember] public string url { get; set; }
        [DataMember] public string thumbnailUrl { get; set; }
    }

    public class KeeperSecrets
    {
        public KeeperRecord[] Records { get; set; }

        public KeeperSecrets(KeeperRecord[] records)
        {
            Records = records;
        }
    }

    public class KeeperRecord
    {
        public KeeperRecord(byte[] recordKey, string recordUid, string folderUid, KeeperRecordData data, KeeperFile[] files)
        {
            RecordKey = recordKey;
            RecordUid = recordUid;
            FolderUid = FolderUid;
            Data = data;
            Files = files;
        }

        public byte[] RecordKey { get; set; }
        public string RecordUid { get; set; }
        public string FolderUid { get; set; }
        public KeeperRecordData Data { get; set; }
        public KeeperFile[] Files { get; set; }
    }

    public class KeeperFile
    {
        public KeeperFile(byte[] fileKey, string fileUid, KeeperFileData data, string url, string thumbnailUrl)
        {
            FileKey = fileKey;
            FileUid = fileUid;
            Data = data;
            Url = url;
            ThumbnailUrl = thumbnailUrl;
        }

        public byte[] FileKey { get; set; }
        public string FileUid { get; set; }
        public KeeperFileData Data { get; set; }
        public string Url { get; set; }
        public string ThumbnailUrl { get; set; }
    }

    public static class SecretsManagerClient
    {
        static readonly string KEY_HOSTNAME = "hostname"; // base url for the Secrets Manager service
        static readonly string KEY_SERVER_PUBIC_KEY_ID = "serverPublicKeyId";
        static readonly string KEY_CLIENT_ID = "clientId";

        static readonly string
            KEY_CLIENT_KEY = "clientKey"; // The key that is used to identify the client before public key

        static readonly string KEY_APP_KEY = "appKey"; // The application key with which all secrets are encrypted
        static readonly string KEY_PRIVATE_KEY = "privateKey"; // The client's private key
        static readonly string KEY_PUBLIC_KEY = "publicKey"; // The client's public key

        static readonly string
            CLIENT_ID_HASH_TAG = "KEEPER_SECRETS_MANAGER_CLIENT_ID"; // Tag for hashing the client key to client id

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
                throw new Exception(
                    $"The storage is already initialized with a different client Id ({existingClientId})");
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

        public static async Task<Tuple<KeeperSecrets, bool>> FetchAndDecryptSecrets(IKeyValueStorage storage,
            string[] recordsFilter = null)
        {
            var payload = PrepareGetPayload(storage, recordsFilter);
            var responseData = await PostQuery(storage, "get_secret", payload);
            var response = JsonUtils.ParseJson<SecretsManagerResponse>(responseData);
            var justBound = false;
            byte[] appKey;
            if (response.encryptedAppKey != null)
            {
                justBound = true;
                var clientKey = storage.GetBytes(KEY_CLIENT_KEY);
                if (clientKey == null)
                {
                    throw new Exception("Client key is missing from the storage");
                }

                appKey = CryptoUtils.Decrypt(response.encryptedAppKey, clientKey);
                storage.SaveBytes(KEY_APP_KEY, appKey);
                storage.Delete(KEY_CLIENT_KEY);
            }
            else
            {
                appKey = storage.GetBytes(KEY_APP_KEY);
                if (appKey == null)
                {
                    throw new Exception("App key is missing from the storage");
                }
            }

            var records = new List<KeeperRecord>();
            if (response.records != null)
            {
                foreach (var record in response.records)
                {
                    var recordKey = CryptoUtils.Decrypt(record.recordKey, appKey);
                    var decryptedRecord = DecryptRecord(record, recordKey);
                    records.Add(decryptedRecord);
                }
            }

            if (response.folders != null)
            {
                foreach (var folder in response.folders)
                {
                    var folderKey = CryptoUtils.Decrypt(folder.folderKey, appKey);
                    foreach (var record in folder.records)
                    {
                        var recordKey = CryptoUtils.Decrypt(record.recordKey, folderKey);
                        var decryptedRecord = DecryptRecord(record, recordKey, folder.folderUid);
                        records.Add(decryptedRecord);
                    }
                }
            }

            var secrets = new KeeperSecrets(records.ToArray());
            return new Tuple<KeeperSecrets, bool>(secrets, justBound);
        }

        private static KeeperRecord DecryptRecord(SecretsManagerResponseRecord record, byte[] recordKey, string folderUid = null)
        {
            var decryptedRecord = CryptoUtils.Decrypt(record.data, recordKey);
            var files = new List<KeeperFile>();
            if (record.files != null)
            {
                foreach (var file in record.files)
                {
                    var fileKey = CryptoUtils.Decrypt(file.fileKey, recordKey);
                    var decryptedFile = CryptoUtils.Decrypt(file.data, fileKey);
                    files.Add(new KeeperFile(fileKey, file.fileUid, JsonUtils.ParseJson<KeeperFileData>(decryptedFile), file.url, file.thumbnailUrl));
                }
            }

            return new KeeperRecord(recordKey, record.recordUid, folderUid, JsonUtils.ParseJson<KeeperRecordData>(decryptedRecord), files.ToArray());
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

        static TransmissionKey GenerateTransmissionKey(IKeyValueStorage storage)
        {
            var transmissionKey = CryptoUtils.GetRandomBytes(32);
            var keyNumberString = storage.GetString(KEY_SERVER_PUBIC_KEY_ID);
            var keyNumber = keyNumberString == null ? 1 : int.Parse(keyNumberString);
            var encryptedKey = CryptoUtils.PublicEncrypt(transmissionKey, KeeperPublicKeys[keyNumber - 1]);
            return new TransmissionKey(keyNumber, transmissionKey, encryptedKey);
        }

        private static Tuple<byte[], byte[]> EncryptAndSignPayload<T>(IKeyValueStorage storage,
            TransmissionKey transmissionKey, T payload)
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

        public static async Task<byte[]> PostQuery<T>(IKeyValueStorage storage, string path, T payload)
        {
            var hostName = storage.GetString(KEY_HOSTNAME);
            if (hostName == null)
            {
                throw new Exception("hostname is missing from the storage");
            }

            var url = $"https://{hostName}/api/rest/sm/v1/{path}";
            var request = (HttpWebRequest) WebRequest.Create(url);
            request.ServerCertificateValidationCallback += (_, _, _, _) => true;
            while (true)
            {
                var transmissionKey = GenerateTransmissionKey(storage);
                var encryptedPayload = EncryptAndSignPayload(storage, transmissionKey, payload);
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
                }
                catch (WebException e)
                {
                    if (e.Response == null) throw;
                    var errorMsg = await new StreamReader(
                            ((HttpWebResponse) e.Response).GetResponseStream() ??
                            throw new InvalidOperationException("Response was expected but not received"))
                        .ReadToEndAsync();
                    throw new Exception(errorMsg);
                }

                using var responseStream = response.GetResponseStream();
                if (responseStream == null)
                {
                    throw new Exception("server response does not contain data");
                }

                using var ms = new MemoryStream();
                await responseStream.CopyToAsync(ms);
                var bytes = CryptoUtils.Decrypt(ms.ToArray(), transmissionKey.Key);
                return bytes;
            }
        }
    }
}