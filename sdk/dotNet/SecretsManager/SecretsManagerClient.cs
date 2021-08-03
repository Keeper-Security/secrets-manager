using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text.Json;
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
    internal class KeeperError
    {
        public int key_id { get; set; }
        public string error { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    internal class GetPayload
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

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    public class SecretsManagerResponse
    {
        public string encryptedAppKey { get; set; }
        public SecretsManagerResponseFolder[] folders { get; set; }
        public SecretsManagerResponseRecord[] records { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    public class SecretsManagerResponseFolder
    {
        public string folderUid { get; set; }
        public string folderKey { get; set; }
        public SecretsManagerResponseRecord[] records { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    public class SecretsManagerResponseRecord
    {
        public string recordUid { get; set; }
        public string recordKey { get; set; }
        public string data { get; set; }
        public bool isEditable { get; set; }
        public SecretsManagerResponseFile[] files { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    public class SecretsManagerResponseFile
    {
        public string fileUid { get; set; }
        public string fileKey { get; set; }
        public string data { get; set; }
        public string url { get; set; }
        public string thumbnailUrl { get; set; }
    }

    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    public class KeeperSecrets
    {
        public KeeperRecord[] Records { get; }

        public KeeperSecrets(KeeperRecord[] records)
        {
            Records = records;
        }
    }

    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    public class KeeperRecord
    {
        public KeeperRecord(byte[] recordKey, string recordUid, string folderUid, KeeperRecordData data, KeeperFile[] files)
        {
            RecordKey = recordKey;
            RecordUid = recordUid;
            FolderUid = folderUid;
            Data = data;
            Files = files;
        }

        public byte[] RecordKey { get; }
        public string RecordUid { get; }
        public string FolderUid { get; }
        public KeeperRecordData Data { get; }
        public KeeperFile[] Files { get; }

        private static object GetFieldValueByType(string fieldType, IEnumerable<KeeperRecordField> fields)
        {
            return fields.FirstOrDefault(x => x.type == fieldType)?.value[0];
        }

        private static void UpdateFieldValueForType(string fieldType, object value, IEnumerable<KeeperRecordField> fields)
        {
            var field = fields.FirstOrDefault(x => x.type == fieldType);
            if (field == null)
            {
                return;
            }

            field.value[0] = value;
        }

        public object FieldValue(string fieldType)
        {
            return GetFieldValueByType(fieldType, Data.fields);
        }

        public object CustomFieldValue(string fieldType)
        {
            return GetFieldValueByType(fieldType, Data.custom);
        }

        public void UpdateFieldValue(string fieldType, object value)
        {
            UpdateFieldValueForType(fieldType, value, Data.fields);
        }

        public void UpdateCustomFieldValue(string fieldType, object value)
        {
            UpdateFieldValueForType(fieldType, value, Data.custom);
        }
    }

    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
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

        public byte[] FileKey { get; }
        public string FileUid { get; }
        public KeeperFileData Data { get; }
        public string Url { get; set; }
        public string ThumbnailUrl { get; }
    }

    public static class SecretsManagerClient
    {
        private const string KeyHostname = "hostname"; // base url for the Secrets Manager service
        private const string KeyServerPubicKeyId = "serverPublicKeyId";
        private const string KeyClientId = "clientId";
        private const string KeyClientKey = "clientKey"; // The key that is used to identify the client before public key
        private const string KeyAppKey = "appKey"; // The application key with which all secrets are encrypted
        private const string KeyPrivateKey = "privateKey"; // The client's private key
        private const string KeyPublicKey = "publicKey"; // The client's public key
        private const string ClientIdHashTag = "KEEPER_SECRETS_MANAGER_CLIENT_ID"; // Tag for hashing the client key to client id

        public static void InitializeStorage(IKeyValueStorage storage, string clientKey, string hostName)
        {
            var existingClientId = storage.GetString(KeyClientId);
            if (existingClientId != null && clientKey == null)
            {
                return;
            }

            if (clientKey == null)
            {
                throw new Exception("Storage is not initialized");
            }

            var clientKeyBytes = CryptoUtils.WebSafe64ToBytes(clientKey);
            var clientKeyHash = CryptoUtils.Hash(clientKeyBytes, ClientIdHashTag);
            var clientId = CryptoUtils.BytesToBase64(clientKeyHash);
            if (existingClientId != null && existingClientId == clientId)
            {
                return; // the storage is already initialized
            }

            if (existingClientId != null)
            {
                throw new Exception($"The storage is already initialized with a different client Id ({existingClientId})");
            }

            storage.SaveString(KeyHostname, hostName);
            storage.SaveString(KeyClientId, clientId);
            storage.SaveBytes(KeyClientKey, clientKeyBytes);
            var (publicKey, privateKey) = CryptoUtils.GenerateKeyPair();
            storage.SaveBytes(KeyPublicKey, publicKey);
            storage.SaveBytes(KeyPrivateKey, privateKey);
        }

        public static async Task<KeeperSecrets> GetSecrets(IKeyValueStorage storage, string[] recordsFilter = null)
        {
            var (keeperSecrets, justBound) = await FetchAndDecryptSecrets(storage, recordsFilter);
            if (justBound)
            {
                try
                {
                    await FetchAndDecryptSecrets(storage, recordsFilter);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e);
                }
            }

            return keeperSecrets;
        }

        private static async Task<Tuple<KeeperSecrets, bool>> FetchAndDecryptSecrets(IKeyValueStorage storage, string[] recordsFilter)
        {
            var payload = PrepareGetPayload(storage, recordsFilter);
            var responseData = await PostQuery(storage, "get_secret", payload);
            var response = JsonUtils.ParseJson<SecretsManagerResponse>(responseData);
            var justBound = false;
            byte[] appKey;
            if (response.encryptedAppKey != null)
            {
                justBound = true;
                var clientKey = storage.GetBytes(KeyClientKey);
                if (clientKey == null)
                {
                    throw new Exception("Client key is missing from the storage");
                }

                appKey = CryptoUtils.Decrypt(response.encryptedAppKey, clientKey);
                storage.SaveBytes(KeyAppKey, appKey);
                storage.Delete(KeyClientKey);
            }
            else
            {
                appKey = storage.GetBytes(KeyAppKey);
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

        private static GetPayload PrepareGetPayload(IKeyValueStorage storage, string[] recordsFilter)
        {
            var clientId = storage.GetString(KeyClientId);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            string publicKey = null;
            var appKey = storage.GetString(KeyAppKey);
            if (appKey == null)
            {
                var publicKeyBytes = storage.GetBytes(KeyPublicKey);
                if (publicKeyBytes == null)
                {
                    throw new Exception("Public key is missing from the storage");
                }

                publicKey = CryptoUtils.BytesToBase64(publicKeyBytes);
            }

            var version = Assembly.GetExecutingAssembly().GetName().Version;
            return new GetPayload($"mn{version.Major}.{version.Minor}.{version.Revision}", clientId, publicKey, recordsFilter);
        }

        [SuppressMessage("ReSharper", "StringLiteralTypo")]
        private static readonly byte[][] KeeperPublicKeys =
        {
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
            CryptoUtils.WebSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
        };

        private static TransmissionKey GenerateTransmissionKey(IKeyValueStorage storage)
        {
            var transmissionKey = CryptoUtils.GetRandomBytes(32);
            var keyNumberString = storage.GetString(KeyServerPubicKeyId);
            var keyNumber = keyNumberString == null ? 1 : int.Parse(keyNumberString);
            var encryptedKey = CryptoUtils.PublicEncrypt(transmissionKey, KeeperPublicKeys[keyNumber - 1]);
            return new TransmissionKey(keyNumber, transmissionKey, encryptedKey);
        }

        private static Tuple<byte[], byte[]> EncryptAndSignPayload<T>(IKeyValueStorage storage,
            TransmissionKey transmissionKey, T payload)
        {
            var payloadBytes = JsonUtils.SerializeJson(payload);
            var encryptedPayload = CryptoUtils.Encrypt(payloadBytes, transmissionKey.Key);
            var privateKey = storage.GetBytes(KeyPrivateKey);
            if (privateKey == null)
            {
                throw new Exception("Private key is missing from the storage");
            }

            var signatureBase = transmissionKey.EncryptedKey.Concat(encryptedPayload).ToArray();
            var signature = CryptoUtils.Sign(signatureBase, privateKey);
            return new Tuple<byte[], byte[]>(encryptedPayload, signature);
        }

        private static async Task<byte[]> PostQuery<T>(IKeyValueStorage storage, string path, T payload)
        {
            var hostName = storage.GetString(KeyHostname);
            if (hostName == null)
            {
                throw new Exception("hostname is missing from the storage");
            }

            var url = $"https://{hostName}/api/rest/sm/v1/{path}";
            while (true)
            {
                var request = (HttpWebRequest) WebRequest.Create(url);
                request.ServerCertificateValidationCallback += (_, _, _, _) => true;
                var transmissionKey = GenerateTransmissionKey(storage);
                var (encryptedPayload, signature) = EncryptAndSignPayload(storage, transmissionKey, payload);
                // request.UserAgent = "KeeperSDK.Net/" + ClientVersion;
                request.ContentType = "application/octet-stream";
                request.Headers["PublicKeyId"] = transmissionKey.PublicKeyId.ToString();
                request.Headers["TransmissionKey"] = CryptoUtils.BytesToBase64(transmissionKey.EncryptedKey);
                request.Headers["Authorization"] = $"Signature {CryptoUtils.BytesToBase64(signature)}";
                request.Method = "POST";

                HttpWebResponse response;
                try
                {
                    using (var requestStream = request.GetRequestStream())
                    {
                        await requestStream.WriteAsync(encryptedPayload, 0, encryptedPayload.Length);
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
                    try
                    {
                        var error = JsonSerializer.Deserialize<KeeperError>(errorMsg);
                        if (error?.error == "key")
                        {
                            storage.SaveString(KeyServerPubicKeyId, error.key_id.ToString());
                            continue;
                        }
                    }
                    catch
                    {
                        // ignored
                    }

                    throw new Exception(errorMsg);
                }

                using var responseStream = response.GetResponseStream();
                if (responseStream == null)
                {
                    throw new Exception("server response does not contain data");
                }

                using var ms = new MemoryStream();
                await responseStream.CopyToAsync(ms);
                return CryptoUtils.Decrypt(ms.ToArray(), transmissionKey.Key);
            }
        }
    }
}