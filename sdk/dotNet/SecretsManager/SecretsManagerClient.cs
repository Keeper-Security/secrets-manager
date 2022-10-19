using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("SecretsManager.Test.Core")]

namespace SecretsManager
{
    using GetRandomBytesFunction = Func<int, byte[]>;
    using QueryFunction = Func<string, TransmissionKey, EncryptedPayload, Task<KeeperHttpResponse>>;

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
        public bool AllowUnverifiedCertificate { get; }
        public IKeyValueStorage Storage { get; }
        public QueryFunction QueryFunction { get; }

        public SecretsManagerOptions(IKeyValueStorage storage, QueryFunction queryFunction = null, bool allowUnverifiedCertificate = false)
        {
            Storage = storage;
            QueryFunction = queryFunction;
            AllowUnverifiedCertificate = allowUnverifiedCertificate;
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
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    internal class UpdatePayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string recordUid { get; }
        public string data { get; }
        public long revision { get; }

        public UpdatePayload(string clientVersion, string clientId, string recordUid, string data, long revision)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.recordUid = recordUid;
            this.data = data;
            this.revision = revision;
        }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    internal class DeletePayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string[] recordUids { get; }

        public DeletePayload(string clientVersion, string clientId, string[] recordUids)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.recordUids = recordUids;
        }
    }
    
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    internal class CreatePayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string recordUid { get; }
        public string recordKey { get; }
        public string folderUid { get; }
        public string folderKey { get; }
        public string data { get; }

        public CreatePayload(string clientVersion, string clientId, string recordUid, string recordKey, string folderUid, string folderKey, string data)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.recordUid = recordUid;
            this.recordKey = recordKey;
            this.folderUid = folderUid;
            this.folderKey = folderKey;
            this.data = data;
        }
    }
    
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    internal class FileUploadPayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string fileRecordUid { get; }
        public string fileRecordKey { get; }
        public string fileRecordData { get; }
        public string ownerRecordUid { get; }
        public string ownerRecordData { get; }
        public string linkKey { get; }
        public int fileSize { get; }

        public FileUploadPayload(string clientVersion, string clientId, 
            string fileRecordUid, string fileRecordKey, string fileRecordData, 
            string ownerRecordUid, string ownerRecordData, string linkKey, int fileSize)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.fileRecordUid = fileRecordUid;
            this.fileRecordKey = fileRecordKey;
            this.fileRecordData = fileRecordData;
            this.ownerRecordUid = ownerRecordUid;
            this.ownerRecordData = ownerRecordData;
            this.linkKey = linkKey;
            this.fileSize = fileSize;
        }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    public class SecretsManagerResponse
    {
        public string appData { get; set; }
        public string encryptedAppKey { get; set; }
        public string appOwnerPublicKey { get; set; }
        public SecretsManagerResponseFolder[] folders { get; set; }
        public SecretsManagerResponseRecord[] records { get; set; }
        public long expiresOn { get; set; }
        public string[] warnings { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
    public class SecretsManagerAddFileResponse
    {
        public string url { get; set; }
        public string parameters { get; set; }
        public int successStatusCode { get; set; }
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
        public long revision { get; set; }
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
        public AppData AppData { get; }
        public DateTimeOffset? ExpiresOn { get; }
        public KeeperRecord[] Records { get; }
        public string[] Warnings { get; set; } 

        public KeeperSecrets(AppData appData, DateTimeOffset? expiresOn, KeeperRecord[] records)
        {
            AppData = appData;
            ExpiresOn = expiresOn;
            Records = records;
        }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    public class AppData
    {
        public string title { get; set; }
        public string type { get; set; }
    }

    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    public class KeeperRecord
    {
        public KeeperRecord(byte[] recordKey, string recordUid, string folderUid, byte[] folderKey, KeeperRecordData data, long revision, KeeperFile[] files)
        {
            RecordKey = recordKey;
            RecordUid = recordUid;
            FolderUid = folderUid;
            FolderKey = folderKey;
            Data = data;
            Revision = revision;
            Files = files;
        }

        public byte[] RecordKey { get; }
        public string RecordUid { get; }
        public string FolderUid { get; }
        public byte[] FolderKey { get; }
        public KeeperRecordData Data { get; }
        public long Revision { get; }
        public KeeperFile[] Files { get; }

        public object FieldValue(string fieldType)
        {
            return Data.fields.Concat(Data.custom ?? new KeeperRecordField[] { }).FirstOrDefault(x => x.type == fieldType)?.value[0];
        }

        public void UpdateFieldValue(string fieldType, object value)
        {
            var field = Data.fields.Concat(Data.custom ?? new KeeperRecordField[] { }).FirstOrDefault(x => x.type == fieldType);
            if (field == null)
            {
                return;
            }

            field.value[0] = value;
        }

        public KeeperFile GetFileByName(string fileName)
        {
            return Files.FirstOrDefault(x => x.Data.name == fileName);
        }

        /**
         * Return file by title
         */
        public KeeperFile GetFileByTitle(string fileTitle)
        {
            return Files.FirstOrDefault(f => f.Data.title == fileTitle);
        }

        public KeeperFile GetFileByUid(string fileUid)
        {
            return Files.FirstOrDefault(x => x.FileUid == fileUid);
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

    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    public class KeeperFileUpload
    {
        public string Name { get; }
        public string Title { get; }
        public string Type { get; }
        public byte[] Data { get; }

        public KeeperFileUpload(string name, string title, string type, byte[] data)
        {
            Name = name;
            Title = title;
            Type = type;
            Data = data;
        }
    }
    
    public static class SecretsManagerClient
    {
        private const string KeyHostname = "hostname"; // base url for the Secrets Manager service
        private const string KeyServerPubicKeyId = "serverPublicKeyId";
        private const string KeyClientId = "clientId";
        private const string KeyClientKey = "clientKey"; // The key that is used to identify the client before public key
        private const string KeyAppKey = "appKey"; // The application key with which all secrets are encrypted
        private const string KeyOwnerPublicKey = "appOwnerPublicKey"; // The application owner public key, to create records
        private const string KeyPrivateKey = "privateKey"; // The client's private key

        private const string ClientIdHashTag = "KEEPER_SECRETS_MANAGER_CLIENT_ID"; // Tag for hashing the client key to client id

        public static void InitializeStorage(IKeyValueStorage storage, string oneTimeToken, string hostName = null)
        {
            var tokenParts = oneTimeToken.Split(':');
            string host;
            string clientKey;
            if (tokenParts.Length == 1)
            {
                host = hostName ?? throw new Exception($"The hostname must be present in the token or as a parameter");
                clientKey = oneTimeToken;
            }
            else
            {
                host = tokenParts[0].ToUpper() switch
                {
                    "US" => "keepersecurity.com",
                    "EU" => "keepersecurity.eu",
                    "AU" => "keepersecurity.com.au",
                    "GOV" => "govcloud.keepersecurity.us",
                    "JP" => "keepersecurity.jp",
                    "CA" => "keepersecurity.ca",
                    _ => tokenParts[0]
                };
                clientKey = tokenParts[1];
            }

            var clientKeyBytes = CryptoUtils.WebSafe64ToBytes(clientKey);
            var clientKeyHash = CryptoUtils.Hash(clientKeyBytes, ClientIdHashTag);
            var clientId = CryptoUtils.BytesToBase64(clientKeyHash);
            var existingClientId = storage.GetString(KeyClientId);
            if (existingClientId != null)
            {
                if (existingClientId == clientId)
                {
                    return; // the storage is already initialized
                }

                throw new Exception($"The storage is already initialized with a different client Id ({existingClientId})");
            }

            storage.SaveString(KeyHostname, host);
            storage.SaveString(KeyClientId, clientId);
            storage.SaveBytes(KeyClientKey, clientKeyBytes);
            storage.SaveBytes(KeyPrivateKey, CryptoUtils.GenerateKeyPair());
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

        public static IEnumerable<KeeperRecord> FindSecretsByTitle(IEnumerable<KeeperRecord> records, string recordTitle)
        {
            return records.Where(r => r.Data.title == recordTitle);
        }
        public static KeeperRecord FindSecretByTitle(IEnumerable<KeeperRecord> records, string recordTitle)
        {
            return records.FirstOrDefault(r => r.Data.title == recordTitle);
        }

        public static async Task<IEnumerable<KeeperRecord>> GetSecretsByTitle(SecretsManagerOptions options, string recordTitle)
        {
            var keeperSecrets = await GetSecrets(options);
            return FindSecretsByTitle(keeperSecrets.Records, recordTitle);
        }

        public static async Task<KeeperRecord> GetSecretByTitle(SecretsManagerOptions options, string recordTitle)
        {
            var keeperSecrets = await GetSecrets(options);
            return FindSecretByTitle(keeperSecrets.Records, recordTitle);
        }

        public static async Task UpdateSecret(SecretsManagerOptions options, KeeperRecord record)
        {
            var payload = PrepareUpdatePayload(options.Storage, record);
            await PostQuery(options, "update_secret", payload);
        }

        public static async Task DeleteSecret(SecretsManagerOptions options, string[] recordsUids)
        {
            var payload = PrepareDeletePayload(options.Storage, recordsUids);
            await PostQuery(options, "delete_secret", payload);
        }
        
        public static async Task<string> CreateSecret(SecretsManagerOptions options, string folderUid, KeeperRecordData recordData, KeeperSecrets secrets = null)
        {
            secrets ??= await GetSecrets(options);
            
            var payload = PrepareCreatePayload(options.Storage, folderUid, recordData, secrets);
            await PostQuery(options, "create_secret", payload);
            return payload.recordUid;
        }
        
        public static async Task<string> UploadFile(SecretsManagerOptions options, KeeperRecord ownerRecord, KeeperFileUpload file)
        {
            var (payload, encryptedFileData) = PrepareFileUploadPayload(options.Storage, ownerRecord, file);
            var responseData = await PostQuery(options, "add_file", payload);
            var response = JsonUtils.ParseJson<SecretsManagerAddFileResponse>(responseData);
            await UploadFile(response.url, response.parameters, response.successStatusCode, encryptedFileData);
            return payload.fileRecordUid;
        }

        public static byte[] DownloadFile(KeeperFile file)
        {
            return DownloadFile(file, file.Url);
        }

        public static byte[] DownloadThumbnail(KeeperFile file)
        {
            if (file.ThumbnailUrl == null)
            {
                throw new Exception($"Thumbnail does not exist for the file {file.FileUid}");
            }

            return DownloadFile(file, file.Url);
        }

        private static byte[] DownloadFile(KeeperFile file, string url)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            var response = (HttpWebResponse)request.GetResponse();
            using var responseStream = response.GetResponseStream();
            return CryptoUtils.Decrypt(StreamToBytes(responseStream), file.FileKey);
        }
        
        private static async Task UploadFile(string url, string parameters, int successStatusCode, byte[] fileData)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            var boundary = "----------" + DateTime.Now.Ticks.ToString("x");
            var boundaryBytes = Encoding.ASCII.GetBytes("\r\n--" + boundary);
            request.ContentType = "multipart/form-data; boundary=" + boundary;
            var parsedParameters = JsonUtils.ParseJson<Dictionary<string, string>>(CryptoUtils.StringToBytes(parameters));

            using (var requestStream = await Task.Factory.FromAsync(request.BeginGetRequestStream, request.EndGetRequestStream, null))
            {
                const string parameterTemplate = "\r\nContent-Disposition: form-data; name=\"{0}\"\r\n\r\n{1}";
                    foreach (var pair in parsedParameters)
                    {
                        await requestStream.WriteAsync(boundaryBytes, 0, boundaryBytes.Length);
                        var formItem = string.Format(parameterTemplate, pair.Key, pair.Value);
                        var formItemBytes = Encoding.UTF8.GetBytes(formItem);
                        await requestStream.WriteAsync(formItemBytes, 0, formItemBytes.Length);
                    }

                await requestStream.WriteAsync(boundaryBytes, 0, boundaryBytes.Length);
                var fileBytes = Encoding.UTF8.GetBytes("\r\nContent-Disposition: form-data; name=\"file\"\r\nContent-Type: application/octet-stream\r\n\r\n");
                await requestStream.WriteAsync(fileBytes, 0, fileBytes.Length);

                await new MemoryStream(fileData).CopyToAsync(requestStream);

                await requestStream.WriteAsync(boundaryBytes, 0, boundaryBytes.Length);
                var trailer = Encoding.ASCII.GetBytes("--\r\n");
                await requestStream.WriteAsync(trailer, 0, trailer.Length);
            }

            try
            {
                var response = (HttpWebResponse) await Task.Factory.FromAsync(request.BeginGetResponse, request.EndGetResponse, null);
                if ((int) response.StatusCode != successStatusCode)
                {
                    throw new Exception($"Upload failed, code {response.StatusCode}");
                }
            }
            catch (WebException e)
            {
                if (e.Response == null) throw;
                var errorResponseStream = ((HttpWebResponse)e.Response).GetResponseStream();
                if (errorResponseStream == null)
                {
                    throw new InvalidOperationException("Response was expected but not received");
                }
                throw new Exception($"Upload failed ({CryptoUtils.BytesToString(StreamToBytes(errorResponseStream))})");
            }
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
                if (response.appOwnerPublicKey != null)
                {
                    storage.SaveString(KeyOwnerPublicKey, response.appOwnerPublicKey);
                }
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
                        var decryptedRecord = DecryptRecord(record, recordKey, folder.folderUid, folderKey);
                        records.Add(decryptedRecord);
                    }
                }
            }

            var appData = response.appData == null 
                ? null : 
                JsonUtils.ParseJson<AppData>(CryptoUtils.Decrypt(CryptoUtils.WebSafe64ToBytes(response.appData), appKey));
            var secrets = new KeeperSecrets(appData, response.expiresOn == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(response.expiresOn), records.ToArray());
            if (response.warnings is { Length: > 0 })
            {
                secrets.Warnings = response.warnings;
            }
            return new Tuple<KeeperSecrets, bool>(secrets, justBound);
        }

        private static KeeperRecord DecryptRecord(SecretsManagerResponseRecord record, byte[] recordKey, string folderUid = null, byte[] folderKey = null)
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

            return new KeeperRecord(recordKey, record.recordUid, folderUid, folderKey, JsonUtils.ParseJson<KeeperRecordData>(decryptedRecord), record.revision, files.ToArray());
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
                var privateKeyBytes = storage.GetBytes(KeyPrivateKey);
                if (privateKeyBytes == null)
                {
                    throw new Exception("Public key is missing from the storage");
                }

                publicKey = CryptoUtils.BytesToBase64(CryptoUtils.ExportPublicKey(privateKeyBytes));
            }

            return new GetPayload(GetClientVersion(), clientId, publicKey, recordsFilter);
        }

        private static UpdatePayload PrepareUpdatePayload(IKeyValueStorage storage, KeeperRecord record)
        {
            var clientId = storage.GetString(KeyClientId);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            var recordBytes = JsonUtils.SerializeJson(record.Data);
            var encryptedRecord = CryptoUtils.Encrypt(recordBytes, record.RecordKey);
            return new UpdatePayload(GetClientVersion(), clientId, record.RecordUid, CryptoUtils.WebSafe64FromBytes(encryptedRecord), record.Revision);
        }

        private static DeletePayload PrepareDeletePayload(IKeyValueStorage storage, string[] recordsUids)
        {
            var clientId = storage.GetString(KeyClientId);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            return new DeletePayload(GetClientVersion(), clientId, recordsUids);
        }
        
        private static CreatePayload PrepareCreatePayload(IKeyValueStorage storage, string folderUid, KeeperRecordData recordData, KeeperSecrets secrets)
        {
            var clientId = storage.GetString(KeyClientId);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            var ownerPublicKey = storage.GetBytes(KeyOwnerPublicKey);
            if (ownerPublicKey == null)
            {
                throw new Exception("Application owner public key is missing from the configuration");
            }

            var recordFromFolder = secrets.Records.FirstOrDefault(x => x.FolderUid == folderUid);
            if (recordFromFolder?.FolderKey == null)
            {
                throw new Exception($"Unable to create record - folder key for {folderUid} not found");
            }

            var recordBytes = JsonUtils.SerializeJson(recordData);
            var recordKey = CryptoUtils.GetRandomBytes(32);
            var recordUid = CryptoUtils.GetRandomBytes(16);
            var encryptedRecord = CryptoUtils.Encrypt(recordBytes, recordKey);
            var encryptedRecordKey = CryptoUtils.PublicEncrypt(recordKey, ownerPublicKey);
            var encryptedFolderKey = CryptoUtils.Encrypt(recordKey, recordFromFolder.FolderKey);

            return new CreatePayload(GetClientVersion(), clientId,
                CryptoUtils.WebSafe64FromBytes(recordUid), CryptoUtils.BytesToBase64(encryptedRecordKey),
                folderUid, CryptoUtils.BytesToBase64(encryptedFolderKey),
                CryptoUtils.WebSafe64FromBytes(encryptedRecord));
        }
        
        private static Tuple<FileUploadPayload, byte[]> PrepareFileUploadPayload(IKeyValueStorage storage, KeeperRecord ownerRecord, KeeperFileUpload file)
        {
            var clientId = storage.GetString(KeyClientId);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            var ownerPublicKey = storage.GetBytes(KeyOwnerPublicKey);
            if (ownerPublicKey == null)
            {
                throw new Exception("Application owner public key is missing from the configuration");
            }

            var fileData = new KeeperFileData
            {
                title = file.Title,
                name = file.Name,
                type = file.Type,
                size = file.Data.Length,
                lastModified = DateTimeOffset.Now.ToUnixTimeMilliseconds()
            };

            var fileRecordBytes = JsonUtils.SerializeJson(fileData);
            var fileRecordKey = CryptoUtils.GetRandomBytes(32);
            var fileRecordUid = CryptoUtils.WebSafe64FromBytes(CryptoUtils.GetRandomBytes(16));
            var encryptedFileRecord = CryptoUtils.Encrypt(fileRecordBytes, fileRecordKey);
            var encryptedFileRecordKey = CryptoUtils.PublicEncrypt(fileRecordKey, ownerPublicKey);
            var encryptedLinkKey = CryptoUtils.Encrypt(fileRecordKey, ownerRecord.RecordKey);
            var encryptedFileData = CryptoUtils.Encrypt(file.Data, fileRecordKey);

            var fileRef = ownerRecord.Data.fields.FirstOrDefault(x => x.type == "fileRef");
            if (fileRef != null)
            {
                fileRef.value = new List<object>(fileRef.value) { fileRecordUid }.ToArray();
            }
            else
            {
                fileRef = new KeeperRecordField { type = "fileRef", value = new object[] { fileRecordUid } };
                ownerRecord.Data.fields = new List<KeeperRecordField>(ownerRecord.Data.fields) { fileRef }.ToArray();
            }
            var ownerRecordBytes = JsonUtils.SerializeJson(ownerRecord.Data);
            var encryptedOwnerRecord = CryptoUtils.Encrypt(ownerRecordBytes, ownerRecord.RecordKey);
            
            var fileUploadPayload = new FileUploadPayload(GetClientVersion(), clientId,
                fileRecordUid,
                CryptoUtils.BytesToBase64(encryptedFileRecordKey),
                CryptoUtils.WebSafe64FromBytes(encryptedFileRecord),
                ownerRecord.RecordUid, 
                CryptoUtils.WebSafe64FromBytes(encryptedOwnerRecord), 
                CryptoUtils.BytesToBase64(encryptedLinkKey),  
                encryptedFileData.Length);
            return Tuple.Create(fileUploadPayload, encryptedFileData);
        }

        private static string GetClientVersion()
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version;
            return $"mn{version.Major}.{version.Minor}.{version.Build}";
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
            var keyNumber = keyNumberString == null ? 10 : int.Parse(keyNumberString);
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

        private static byte[] StreamToBytes(Stream stream)
        {
            using var memoryStream = new MemoryStream();
            stream.CopyTo(memoryStream);
            return memoryStream.ToArray();
        }

        [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
        public static async Task<KeeperHttpResponse> PostFunction(string url, TransmissionKey transmissionKey, EncryptedPayload payload, bool allowUnverifiedCertificate)
        {
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
                    ? await PostFunction(url, transmissionKey, encryptedPayload, options.AllowUnverifiedCertificate)
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

                return response.Data.Length == 0
                    ? response.Data
                    : CryptoUtils.Decrypt(response.Data, transmissionKey.Key);
            }
        }
    }
}