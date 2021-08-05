using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("SecretsManager.Test.Core")]

namespace SecretsManager
{
    using QueryFunction = Func<string, TransmissionKey, EncryptedPayload, Task<KeeperHttpResponse>>;
    using GetRandomBytesFunction = Func<int, byte[]>;

    public interface IKeyValueStorage
    {
        string GetString(string key);
        byte[] GetBytes(string key);
        void SaveString(string key, string value);
        void SaveBytes(string key, byte[] value);
        void Delete(string key);
    }

    public class SecretsManagerOptions
    {
        public IKeyValueStorage Storage { get; }
        public QueryFunction QueryFunction { get; }

        public SecretsManagerOptions(IKeyValueStorage storage, QueryFunction queryFunction = null)
        {
            Storage = storage;
            QueryFunction = queryFunction;
        }
    }

    public class TransmissionKey
    {
        public int PublicKeyId { get; }
        public byte[] Key { get; set; }
        public byte[] EncryptedKey { get; }

        public TransmissionKey(int publicKeyId, byte[] key, byte[] encryptedKey)
        {
            PublicKeyId = publicKeyId;
            Key = key;
            EncryptedKey = encryptedKey;
        }
    }

    public class KeeperHttpResponse
    {
        public byte[] Data { get; }
        public bool IsError { get; }

        public KeeperHttpResponse(byte[] data, bool isError)
        {
            Data = data;
            IsError = isError;
        }
    }

    public class EncryptedPayload
    {
        public byte[] Payload { get; }
        public byte[] Signature { get; }

        public EncryptedPayload(byte[] payload, byte[] signature)
        {
            Payload = payload;
            Signature = signature;
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

        public static async Task<KeeperSecrets> GetSecrets(SecretsManagerOptions options, string[] recordsFilter = null)
        {
            var (keeperSecrets, justBound) = await FetchAndDecryptSecrets(options, recordsFilter);
            if (justBound)
            {
                try
                {
                    await FetchAndDecryptSecrets(options, recordsFilter);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e);
                }
            }

            return keeperSecrets;
        }

        private static async Task<Tuple<KeeperSecrets, bool>> FetchAndDecryptSecrets(SecretsManagerOptions options, string[] recordsFilter)
        {
            var storage = options.Storage;
            var payload = PrepareGetPayload(storage, recordsFilter);
            var responseData = await PostQuery(options, "get_secret", payload);
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
        private static Dictionary<int, byte[]> InitKeeperKeys()
        {
            var keyId = 7;
            return new[]
                {
                    "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM",
                    "BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ",
                    "BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g",
                    "BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg",
                    "BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk",
                    "BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY",
                    "BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI",
                    "BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE",
                    "BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8",
                    "BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c",
                    "BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU"
                }
                .ToDictionary(_ => keyId++, CryptoUtils.WebSafe64ToBytes);
        }

        private static readonly Dictionary<int, byte[]> KeeperPublicKeys = InitKeeperKeys();

        private static TransmissionKey GenerateTransmissionKey(IKeyValueStorage storage)
        {
            var transmissionKey = TransmissionKeyStub == null
                ? CryptoUtils.GetRandomBytes(32)
                : TransmissionKeyStub(32);
            var keyNumberString = storage.GetString(KeyServerPubicKeyId);
            var keyNumber = keyNumberString == null ? 7 : int.Parse(keyNumberString);
            if (!KeeperPublicKeys.TryGetValue(keyNumber, out var keeperPublicKey))
            {
                throw new Exception($"Key number {keyNumber} is not supported");
            }

            var encryptedKey = CryptoUtils.PublicEncrypt(transmissionKey, keeperPublicKey);
            return new TransmissionKey(keyNumber, transmissionKey, encryptedKey);
        }

        [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
        [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
        internal static GetRandomBytesFunction TransmissionKeyStub { get; set; }

        private static EncryptedPayload EncryptAndSignPayload<T>(IKeyValueStorage storage,
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
            return new EncryptedPayload(encryptedPayload, signature);
        }

        public static async Task<KeeperHttpResponse> CachingPostFunction(string url, TransmissionKey transmissionKey, EncryptedPayload payload)
        {
            try
            {
                var response = await PostFunction(url, transmissionKey, payload, false);
                if (!response.IsError)
                {
                    CacheStorage.SaveCachedValue(transmissionKey.Key.Concat(response.Data).ToArray());
                }
                return response;
            }
            catch (Exception)
            {
                var cachedData = CacheStorage.GetCachedValue();
                var cachedTransmissionKey = cachedData.Take(32).ToArray();
                transmissionKey.Key = cachedTransmissionKey;
                var data = cachedData.Skip(32).ToArray();
                return new KeeperHttpResponse(data, false);
            }
        }

        [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
        public static async Task<KeeperHttpResponse> PostFunction(string url, TransmissionKey transmissionKey, EncryptedPayload payload, bool allowUnverifiedCertificate)
        {
            static byte[] StreamToBytes(Stream stream)
            {
                using var memoryStream = new MemoryStream();
                stream.CopyTo(memoryStream);
                return memoryStream.ToArray();
            }

            var request = (HttpWebRequest)WebRequest.Create(url);
            if (allowUnverifiedCertificate)
            {
                request.ServerCertificateValidationCallback += (_, _, _, _) => true;
            }

            request.ContentType = "application/octet-stream";
            request.Headers["PublicKeyId"] = transmissionKey.PublicKeyId.ToString();
            request.Headers["TransmissionKey"] = CryptoUtils.BytesToBase64(transmissionKey.EncryptedKey);
            request.Headers["Authorization"] = $"Signature {CryptoUtils.BytesToBase64(payload.Signature)}";
            request.Method = "POST";

            HttpWebResponse response;
            try
            {
                using (var requestStream = request.GetRequestStream())
                {
                    await requestStream.WriteAsync(payload.Payload, 0, payload.Payload.Length);
                }

                response = (HttpWebResponse)request.GetResponse();
            }
            catch (WebException e)
            {
                if (e.Response == null) throw;
                var errorResponseStream = ((HttpWebResponse)e.Response).GetResponseStream();
                if (errorResponseStream == null)
                {
                    throw new InvalidOperationException("Response was expected but not received");
                }

                return new KeeperHttpResponse(StreamToBytes(errorResponseStream), true);
            }

            using var responseStream = response.GetResponseStream();
            return new KeeperHttpResponse(StreamToBytes(responseStream), false);
        }

        private static async Task<byte[]> PostQuery<T>(SecretsManagerOptions options, string path, T payload)
        {
            var hostName = options.Storage.GetString(KeyHostname);
            if (hostName == null)
            {
                throw new Exception("hostname is missing from the storage");
            }

            var url = $"https://{hostName}/api/rest/sm/v1/{path}";
            while (true)
            {
                var transmissionKey = GenerateTransmissionKey(options.Storage);
                var encryptedPayload = EncryptAndSignPayload(options.Storage, transmissionKey, payload);
                var response = options.QueryFunction == null
                    ? await PostFunction(url, transmissionKey, encryptedPayload, false)
                    : await options.QueryFunction(url, transmissionKey, encryptedPayload);
                if (response.IsError)
                {
                    try
                    {
                        var error = JsonSerializer.Deserialize<KeeperError>(response.Data);
                        if (error?.error == "key")
                        {
                            options.Storage.SaveString(KeyServerPubicKeyId, error.key_id.ToString());
                            continue;
                        }
                    }
                    catch
                    {
                        // ignored
                    }

                    throw new Exception(CryptoUtils.BytesToString(response.Data));
                }

                return CryptoUtils.Decrypt(response.Data, transmissionKey.Key);
            }
        }
    }
}