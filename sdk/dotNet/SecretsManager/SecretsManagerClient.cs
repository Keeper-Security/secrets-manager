using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

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

    public class QueryOptions
    {
        public string[] RecordsFilter { get; }
        public string[] FoldersFilter { get; }

        public QueryOptions(string[] recordsFilter = null, string[] foldersFilter = null)
        {
            RecordsFilter = recordsFilter;
            FoldersFilter = foldersFilter;
        }
    }

    public class CreateOptions
    {
        public string FolderUid { get; }
        public string SubFolderUid { get; }

        public CreateOptions(string folderUid, string subFolderUid = null)
        {
            FolderUid = folderUid;
            SubFolderUid = subFolderUid;
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

    internal class KeeperError
    {
        public int key_id { get; set; }
        public string error { get; set; }
    }

    internal class GetPayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string publicKey { get; }
        public string[] requestedRecords { get; }
        public string[] requestedFolders { get; }

        public GetPayload(string clientVersion, string clientId, string publicKey, string[] requestedRecords, string[] requestedFolders)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.publicKey = publicKey;
            this.requestedRecords = requestedRecords;
            this.requestedFolders = requestedFolders;
        }
    }

    public enum UpdateTransactionType {
        General,
        Rotation
    }

    internal class UpdatePayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string recordUid { get; }
        public string data { get; }
        public long revision { get; }
        public string transactionType { get; }

        public UpdatePayload(string clientVersion, string clientId, string recordUid, string data, long revision, UpdateTransactionType? transactionType = null)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.recordUid = recordUid;
            this.data = data;
            this.revision = revision;
            if (transactionType.HasValue)
            {
                this.transactionType = transactionType.Value.ToString().ToLower();
            }

        }
    }

    internal class CompleteTransactionPayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string recordUid { get; }

        public CompleteTransactionPayload(string clientVersion, string clientId, string recordUid)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.recordUid = recordUid;
        }
    }

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

    internal class DeleteFolderPayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string[] folderUids { get; }
        public bool forceDeletion { get; }

        public DeleteFolderPayload(string clientVersion, string clientId, string[] folderUids, bool forceDeletion)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.folderUids = folderUids;
            this.forceDeletion = forceDeletion;
        }
    }

    internal class CreatePayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string recordUid { get; }
        public string recordKey { get; }
        public string folderUid { get; }
        public string folderKey { get; }
        public string data { get; }
        public string subFolderUid { get; }

        public CreatePayload(string clientVersion, string clientId, string recordUid, string recordKey, string folderUid, string folderKey, string data, string subFolderUid)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.recordUid = recordUid;
            this.recordKey = recordKey;
            this.folderUid = folderUid;
            this.folderKey = folderKey;
            this.data = data;
            this.subFolderUid = subFolderUid;
        }
    }

    internal class CreateFolderPayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string folderUid { get; }
        public string sharedFolderUid { get; }
        public string sharedFolderKey { get; }
        public string data { get; }
        public string parentUid { get; }

        public CreateFolderPayload(string clientVersion, string clientId, string folderUid, string sharedFolderUid, string sharedFolderKey, string data, string parentUid)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.folderUid = folderUid;
            this.sharedFolderUid = sharedFolderUid;
            this.sharedFolderKey = sharedFolderKey;
            this.data = data;
            this.parentUid = parentUid;
        }
    }

    internal class UpdateFolderPayload
    {
        public string clientVersion { get; }
        public string clientId { get; }
        public string folderUid { get; }
        public string data { get; }

        public UpdateFolderPayload(string clientVersion, string clientId, string folderUid, string data)
        {
            this.clientVersion = clientVersion;
            this.clientId = clientId;
            this.folderUid = folderUid;
            this.data = data;
        }
    }

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

    public class SecretsManagerAddFileResponse
    {
        public string url { get; set; }
        public string parameters { get; set; }
        public int successStatusCode { get; set; }
    }

    public class SecretsManagerResponseFolder
    {
        public string folderUid { get; set; }
        public string folderKey { get; set; }
        public string data { get; set; }
        public string parent { get; set; }
        public SecretsManagerResponseRecord[] records { get; set; }
    }

    public class SecretsManagerResponseRecord
    {
        public string recordUid { get; set; }
        public string recordKey { get; set; }
        public string data { get; set; }
        public long revision { get; set; }
        public bool isEditable { get; set; }
        public SecretsManagerResponseFile[] files { get; set; }
        public string innerFolderUid { get; set; }
    }

    public class SecretsManagerResponseFile
    {
        public string fileUid { get; set; }
        public string fileKey { get; set; }
        public string data { get; set; }
        public string url { get; set; }
        public string thumbnailUrl { get; set; }
    }

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

    public class AppData
    {
        public string title { get; set; }
        public string type { get; set; }
    }

    public class KeeperRecord
    {
        public KeeperRecord(byte[] recordKey, string recordUid, string folderUid, byte[] folderKey, string innerFolderUid, KeeperRecordData data, long revision, KeeperFile[] files)
        {
            RecordKey = recordKey;
            RecordUid = recordUid;
            FolderUid = folderUid;
            FolderKey = folderKey;
            InnerFolderUid = innerFolderUid;
            Data = data;
            Revision = revision;
            Files = files;
        }

        public byte[] RecordKey { get; }
        public string RecordUid { get; }
        public string FolderUid { get; }
        public byte[] FolderKey { get; }
        public string InnerFolderUid { get; }
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

        public bool AddCustomField(object field)
        {
            if (field == null) return false;
            if (!KeeperField.IsFieldClass(field))
            {
                Console.Error.WriteLine($"AddCustomField: Field '{field.GetType().Name}' is of unknown field class - skipped.");
                return false;
            }

            Data.custom = Data.custom ?? new KeeperRecordField[] { };

            var json = JsonUtils.SerializeJson(field);
            var krf = JsonUtils.ParseJson<KeeperRecordField>(json);
            Data.custom = Data.custom.Concat(new KeeperRecordField[] { krf }).ToArray();

            return true;
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

    public class KeeperFolder
    {
        public KeeperFolder(byte[] folderKey, string folderUid, string parentUid, string name)
        {
            FolderKey = folderKey;
            FolderUid = folderUid;
            ParentUid = parentUid;
            Name = name;
        }

        public byte[] FolderKey { get; }
        public string FolderUid { get; }
        public string ParentUid { get; }
        public string Name { get; }
    }

    public class KeeperFolderName
    {
        public string name { get; set; }
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

        public byte[] FileKey { get; }
        public string FileUid { get; }
        public KeeperFileData Data { get; }
        public string Url { get; set; }
        public string ThumbnailUrl { get; }
    }

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
            return await GetSecrets2(options, new QueryOptions(recordsFilter));
       }

        public static async Task<KeeperSecrets> GetSecrets2(SecretsManagerOptions options, QueryOptions queryOptions = null)
        {
            var (keeperSecrets, justBound) = await FetchAndDecryptSecrets(options, queryOptions);
            if (justBound)
            {
                try
                {
                    await FetchAndDecryptSecrets(options, queryOptions);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e);
                }
            }

            return keeperSecrets;
        }

        public static async Task<KeeperFolder[]> GetFolders(SecretsManagerOptions options)
        {
            return await FetchAndDecryptFolders(options);
        }


        /// <summary>
        /// TryGetNotationResults returns a string list with all values specified by the notation or empty list on error.
        /// It simply logs any errors and continue returning an empty string list on error.
        /// </summary>
        /// <param name="options"></param>
        /// <param name="notation"></param>
        /// <returns></returns>
        public static async Task<List<string>> TryGetNotationResults(SecretsManagerOptions options, string notation)
        {
            try
            {
                return await GetNotationResults(options, notation);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return new List<string> { };
        }

        // Notation:
        // keeper://<uid|title>/<field|custom_field>/<type|label>[INDEX][PROPERTY]
        // keeper://<uid|title>/file/<filename|fileUID>
        // Record title, field label, filename sections need to escape the delimiters /[]\ -> \/ \[ \] \\
        //
        // GetNotationResults returns selection of the value(s) from a single field as a string list.
        // Multiple records or multiple fields found results in error.
        // Use record UID or unique record titles and field labels so that notation finds a single record/field.
        //
        // If field has multiple values use indexes - numeric INDEX specifies the position in the value list
        // and PROPERTY specifies a single JSON object property to extract (see examples below for usage)
        // If no indexes are provided - whole value list is returned (same as [])
        // If PROPERTY is provided then INDEX must be provided too - even if it's empty [] which means all
        //
        // Extracting two or more but not all field values simultaneously is not supported - use multiple notation requests.
        //
        // Files are returned as URL safe base64 encoded string of the binary content
        //
        // Note: Integrations and plugins usually return single string value - result[0] or ""
        //
        // Examples:
        //  RECORD_UID/file/filename.ext             => ["URL Safe Base64 encoded binary content"]
        //  RECORD_UID/field/url                     => ["127.0.0.1", "127.0.0.2"] or [] if empty
        //  RECORD_UID/field/url[]                   => ["127.0.0.1", "127.0.0.2"] or [] if empty
        //  RECORD_UID/field/url[0]                  => ["127.0.0.1"] or error if empty
        //  RECORD_UID/custom_field/name[first]      => Error, numeric index is required to access field property
        //  RECORD_UID/custom_field/name[][last]     => ["Smith", "Johnson"]
        //  RECORD_UID/custom_field/name[0][last]    => ["Smith"]
        //  RECORD_UID/custom_field/phone[0][number] => "555-5555555"
        //  RECORD_UID/custom_field/phone[1][number] => "777-7777777"
        //  RECORD_UID/custom_field/phone[]          => ["{\"number\": \"555-555...\"}", "{\"number\": \"777...\"}"]
        //  RECORD_UID/custom_field/phone[0]         => ["{\"number\": \"555-555...\"}"]

        /// <summary>
        /// GetNotationResults returns a string list with all values specified by the notation or throws an error.
        /// Use <see cref="TryGetNotationResults" /> to just log errors and continue returning an empty string list on error.
        /// </summary>
        /// <param name="options"></param>
        /// <param name="notation"></param>
        /// <returns></returns>
        public static async Task<List<string>> GetNotationResults(SecretsManagerOptions options, string notation)
        {
            var result = new List<string> { };

            var parsedNotation = Notation.ParseNotation(notation); // prefix, record, selector, footer
            if ((parsedNotation?.Count ?? 0) < 3)
                throw new Exception($"Invalid notation {notation}");

            string selector = parsedNotation[2]?.Text?.Item1; // type|title|notes or file|field|custom_field
            if (selector == null)
                throw new Exception($"Invalid notation {notation}");
            string recordToken = parsedNotation[1]?.Text?.Item1; // UID or Title
            if (recordToken == null)
                throw new Exception($"Invalid notation {notation}");

            // to minimize traffic - if it looks like a Record UID try to pull a single record
            var records = new KeeperRecord[] { };
            if (Regex.IsMatch(recordToken, @"^[A-Za-z0-9_-]{22}$"))
            {
                var secrets = await GetSecrets(options, new string[] { recordToken });
                records = secrets?.Records;
                if ((records?.Count() ?? 0) > 1)
                    throw new Exception($"Notation error - found multiple records with same UID '{recordToken}'");
            }

            // If RecordUID is not found - pull all records and search by title
            if ((records?.Count() ?? 0) < 1)
            {
                var secrets = await GetSecrets(options);
                records = (secrets?.Records != null ? secrets.Records.Where(x => recordToken.Equals(x?.Data?.title)).ToArray() : null);
            }

            if ((records?.Count() ?? 0) > 1)
                throw new Exception($"Notation error - multiple records match record '{recordToken}'");
            if ((records?.Count() ?? 0) < 1)
                throw new Exception($"Notation error - no records match record '{recordToken}'");

            var record = records[0];
            string parameter = parsedNotation[2]?.Parameter?.Item1;
            string index1 = parsedNotation[2]?.Index1?.Item1;
            string index2 = parsedNotation[2]?.Index2?.Item1;

            switch (selector.ToLower())
            {
                case "type": if (record?.Data?.type != null) result.Add(record.Data.type); break;
                case "title": if (record?.Data?.title != null) result.Add(record.Data.title); break;
                case "notes": if (record?.Data?.notes != null) result.Add(record.Data.notes); break;
                case "file":
                    if (parameter == null)
                        throw new Exception($"Notation error - Missing required parameter: filename or file UID for files in record '{recordToken}'");
                    if ((record?.Files?.Count() ?? 0) < 1)
                        throw new Exception($"Notation error - Record {recordToken} has no file attachments.");
                    var files = record.Files;
                    files = files.Where(x => parameter.Equals(x?.Data?.name) || parameter.Equals(x?.Data?.title) || parameter.Equals(x?.FileUid)).ToArray();
                    // file searches do not use indexes and rely on unique file names or fileUid
                    if ((files?.Length ?? 0) > 1)
                        throw new Exception($"Notation error - Record {recordToken} has multiple files matching the search criteria '{parameter}'");
                    if ((files?.Length ?? 0) < 1)
                        throw new Exception($"Notation error - Record {recordToken} has no files matching the search criteria '{parameter}'");
                    var contents = DownloadFile(files[0]);
                    var text = CryptoUtils.WebSafe64FromBytes(contents);
                    result.Add(text);
                    break;
                case "field":
                case "custom_field":
                    if (parameter == null)
                        throw new Exception($"Notation error - Missing required parameter for the field (type or label): ex. /field/type or /custom_field/MyLabel");

                    var fields = selector.ToLower() switch
                    {
                        "field" => record.Data.fields,
                        "custom_field" => record.Data.custom,
                        _ => throw new Exception($"Notation error - Expected /field or /custom_field but found /{selector}")
                    };

                    var flds = fields.Where(x => parameter.Equals(x?.type) || parameter.Equals(x?.label)).ToList();
                    if ((flds?.Count ?? 0) > 1)
                        throw new Exception($"Notation error - Record {recordToken} has multiple fields matching the search criteria '{parameter}'");
                    if ((flds?.Count ?? 0) < 1)
                        throw new Exception($"Notation error - Record {recordToken} has no fields matching the search criteria '{parameter}'");
                    var field = flds[0];
                    var fieldType = field?.type ?? "";

                    var isValid = int.TryParse(index1, out int idx);
                    if (!isValid) idx = -1; // full value
                    // valid only if [] or missing - ex. /field/phone or /field/phone[]
                    if (idx == -1 && !(string.IsNullOrEmpty(parsedNotation[2]?.Index1?.Item2) || parsedNotation[2]?.Index1?.Item2 == "[]"))
                        throw new Exception($"Notation error - Invalid field index {idx}.");

                    var values = (field?.value != null ? new List<object>(field.value) : new List<object>());
                    if (idx >= values.Count)
                        throw new Exception($"Notation error - Field index out of bounds {idx} >= {values.Count} for field {parameter}.");
                    if (idx >= 0) // single index
                        values = new List<object> { values[idx] };

                    bool fullObjValue = (string.IsNullOrEmpty(parsedNotation[2]?.Index2?.Item2) || parsedNotation[2]?.Index2?.Item2 == "[]") ? true : false;
                    string objPropertyName = parsedNotation[2]?.Index2?.Item1 ?? "";

                    var res = new List<string> { };
                    foreach (var fldValue in values)
                    {
                        // Do not throw here to allow for ex. field/name[][middle] to pull [middle] only where present
                        // NB! Not all properties of a value are always required even when the field is marked as required
                        // ex. On a required `name` field only "first" and "last" properties are required but not "middle"
                        // so missing property in a field value is not always an error
                        if (fldValue == null)
                            Console.Error.WriteLine($"Notation error - Empty field value for field {parameter}."); // throw?

                        if (fullObjValue)
                        {
                            res.Add((fldValue is JsonElement je && je.ValueKind == JsonValueKind.String) ?
                                je.ToString() :
                                CryptoUtils.BytesToString(JsonUtils.SerializeJson(fldValue)));
                        }
                        else if (fldValue != null)
                        {
                            if (fldValue is JsonElement je)
                            {
                                if (je.TryGetProperty(objPropertyName, out JsonElement jvalue))
                                    res.Add(jvalue.ValueKind == JsonValueKind.String ?
                                        jvalue.ToString() :
                                        CryptoUtils.BytesToString(JsonUtils.SerializeJson(jvalue)));
                                else
                                    Console.Error.WriteLine($"Notation error - value object has no property '{objPropertyName}'."); // skip
                            }
                        }
                        else
                            Console.Error.WriteLine($"Notation error - Cannot extract property '{objPropertyName}' from null value.");
                    }
                    if (res.Count != values.Count)
                        Console.Error.WriteLine($"Notation warning - extracted {res.Count} out of {values.Count} values for '{objPropertyName}' property.");
                    if (res.Count > 0)
                        result.AddRange(res);
                    break;
                default: throw new Exception($"Invalid notation {notation}");
            }

            return result;
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

        public static async Task UpdateSecret(SecretsManagerOptions options, KeeperRecord record, UpdateTransactionType? transactionType = null)
        {
            var payload = PrepareUpdatePayload(options.Storage, record, transactionType);
            await PostQuery(options, "update_secret", payload);
        }

        public static async Task CompleteTransaction(SecretsManagerOptions options, string recordUid, bool rollback = false)
        {
            var payload = PrepareCompleteTransactionPayload(options.Storage, recordUid);
            var route = (rollback ? "rollback_secret_update" : "finalize_secret_update");
            await PostQuery(options, route, payload);
        }

        public static async Task DeleteSecret(SecretsManagerOptions options, string[] recordsUids)
        {
            var payload = PrepareDeletePayload(options.Storage, recordsUids);
            await PostQuery(options, "delete_secret", payload);
        }

        public static async Task DeleteFolder(SecretsManagerOptions options, string[] folderUids, bool forceDeletion = false)
        {
            var payload = PrepareDeleteFolderPayload(options.Storage, folderUids, forceDeletion);
            await PostQuery(options, "delete_folder", payload);
        }

        public static async Task<string> CreateSecret(SecretsManagerOptions options, string folderUid, KeeperRecordData recordData, KeeperSecrets secrets = null)
        {
            secrets ??= await GetSecrets(options);
            
            var recordFromFolder = secrets.Records.FirstOrDefault(x => x.FolderUid == folderUid);
            if (recordFromFolder?.FolderKey == null)
            {
                throw new Exception($"Unable to create record - folder key for {folderUid} not found");
            }

            var payload = PrepareCreatePayload(options.Storage, new CreateOptions(folderUid), recordData, recordFromFolder.FolderKey);
            await PostQuery(options, "create_secret", payload);
            return payload.recordUid;
        }

        public static async Task<string> CreateSecret2(SecretsManagerOptions options, CreateOptions createOptions, KeeperRecordData recordData, KeeperFolder[] folders = null)
        {
            folders ??= await GetFolders(options);

            var sharedFolder = folders.FirstOrDefault(x => x.FolderUid == createOptions.FolderUid);
            if (sharedFolder?.FolderKey == null)
            {
                throw new Exception($"Unable to create record - folder key for {createOptions.FolderUid} not found");
            }

            var payload = PrepareCreatePayload(options.Storage, createOptions, recordData, sharedFolder.FolderKey);
            await PostQuery(options, "create_secret", payload);
            return payload.recordUid;
        }

        public static async Task<string> CreateFolder(SecretsManagerOptions options, CreateOptions createOptions, string folderName, KeeperFolder[] folders = null)
        {
            folders ??= await GetFolders(options);

            var sharedFolder = folders.FirstOrDefault(x => x.FolderUid == createOptions.FolderUid);
            if (sharedFolder?.FolderKey == null)
            {
                throw new Exception($"Unable to create folder - folder key for {createOptions.FolderUid} not found");
            }

            var payload = PrepareCreateFolderPayload(options.Storage, createOptions, folderName, sharedFolder.FolderKey);
            await PostQuery(options, "create_folder", payload);
            return payload.folderUid;
        }

        public static async Task UpdateFolder(SecretsManagerOptions options, string folderUid, string folderName, KeeperFolder[] folders = null)
        {
            folders ??= await GetFolders(options);

            var sharedFolder = folders.FirstOrDefault(x => x.FolderUid == folderUid);
            if (sharedFolder?.FolderKey == null)
            {
                throw new Exception($"Unable to update folder - folder key for {folderUid} not found");
            }

            var payload = PrepareUpdateFolderPayload(options.Storage, folderUid, folderName, sharedFolder.FolderKey);
            await PostQuery(options, "update_folder", payload);
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
                var response = (HttpWebResponse)await Task.Factory.FromAsync(request.BeginGetResponse, request.EndGetResponse, null);
                if ((int)response.StatusCode != successStatusCode)
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
        
        private static async Task<Tuple<KeeperSecrets, bool>> FetchAndDecryptSecrets(SecretsManagerOptions options, QueryOptions queryOptions)
        {
            var storage = options.Storage;
            var payload = PrepareGetPayload(storage, queryOptions);
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
            var secrets = new KeeperSecrets(appData, response.expiresOn == 0 ? null : DateTimeOffset.FromUnixTimeMilliseconds(response.expiresOn), records.ToArray());
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

            var recordData = JsonUtils.ParseJson<KeeperRecordData>(decryptedRecord);
            return new KeeperRecord(recordKey, record.recordUid, folderUid, folderKey, record.innerFolderUid, recordData, record.revision, files.ToArray());
        }

        private static async Task<KeeperFolder[]> FetchAndDecryptFolders(SecretsManagerOptions options)
        {
            var storage = options.Storage;
            var payload = PrepareGetPayload(storage, null);
            var responseData = await PostQuery(options, "get_folders", payload);
            var response = JsonUtils.ParseJson<SecretsManagerResponse>(responseData);
            var appKey = storage.GetBytes(KeyAppKey);
            if (appKey == null)
            {
                throw new Exception("App key is missing from the storage");
            }

            if (response.folders == null)
            {
                return new KeeperFolder[] {};
            }

            var folders = new List<KeeperFolder>();

            foreach (var folder in response.folders)
            {
                byte[] folderKey;
                if (folder.parent == null)
                {
                    folderKey = CryptoUtils.Decrypt(folder.folderKey, appKey);
                }
                else
                {
                    var sharedFolderKey = GetSharedFolderKey(folders, response.folders, folder.parent);
                    folderKey = CryptoUtils.Decrypt(folder.folderKey, sharedFolderKey, true);
                }

                var folderNameJson = CryptoUtils.Decrypt(folder.data, folderKey, true);
                var folderName = JsonUtils.ParseJson<KeeperFolderName>(folderNameJson);
                folders.Add(new KeeperFolder(folderKey, folder.folderUid, folder.parent, folderName.name));
            }
            return folders.ToArray();
        }

        private static byte[] GetSharedFolderKey(List<KeeperFolder> folders, SecretsManagerResponseFolder[] responseFolders, string parent)
        {
            while (true)
            {
                var parentFolder = responseFolders.FirstOrDefault(x => x.folderUid == parent);
                if (parentFolder == null)
                {
                    return null;
                }
                if (parentFolder.parent == null)
                {
                    var sharedFolder = folders.FirstOrDefault(x => x.FolderUid == parentFolder.folderUid);
                    return sharedFolder?.FolderKey;
                }
                parent = parentFolder.parent;
            }
        }

        private static GetPayload PrepareGetPayload(IKeyValueStorage storage, QueryOptions queryOptions)
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

            return new GetPayload(GetClientVersion(), clientId, publicKey, queryOptions?.RecordsFilter, queryOptions?.FoldersFilter);
        }

        private static UpdatePayload PrepareUpdatePayload(IKeyValueStorage storage, KeeperRecord record, UpdateTransactionType? transactionType = null)
        {
            var clientId = storage.GetString(KeyClientId);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            var recordBytes = JsonUtils.SerializeJson(record.Data);
            var encryptedRecord = CryptoUtils.Encrypt(recordBytes, record.RecordKey);
            var payload = new UpdatePayload(
                GetClientVersion(),
                clientId,
                record.RecordUid,
                CryptoUtils.WebSafe64FromBytes(encryptedRecord),
                record.Revision,
                transactionType);
            return payload;
        }

        private static CompleteTransactionPayload PrepareCompleteTransactionPayload(IKeyValueStorage storage, string recordUid)
        {
            var clientId = storage.GetString(KeyClientId);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            var payload = new CompleteTransactionPayload(
                GetClientVersion(),
                clientId,
                recordUid);
            return payload;
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
        
        private static DeleteFolderPayload PrepareDeleteFolderPayload(IKeyValueStorage storage, string[] folderUids, bool forceDeletion)
        {
            var clientId = storage.GetString(KeyClientId);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            return new DeleteFolderPayload(GetClientVersion(), clientId, folderUids, forceDeletion);
        }

        private static CreatePayload PrepareCreatePayload(IKeyValueStorage storage, CreateOptions createOptions, KeeperRecordData recordData, byte[] folderKey)
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

            var recordBytes = JsonUtils.SerializeJson(recordData);
            var recordKey = CryptoUtils.GetRandomBytes(32);
            var recordUid = CryptoUtils.GetUidBytes();
            var encryptedRecord = CryptoUtils.Encrypt(recordBytes, recordKey);
            var encryptedRecordKey = CryptoUtils.PublicEncrypt(recordKey, ownerPublicKey);
            var encryptedFolderKey = CryptoUtils.Encrypt(recordKey, folderKey);

            return new CreatePayload(GetClientVersion(), clientId,
                CryptoUtils.WebSafe64FromBytes(recordUid), CryptoUtils.BytesToBase64(encryptedRecordKey),
                createOptions.FolderUid, CryptoUtils.BytesToBase64(encryptedFolderKey),
                CryptoUtils.WebSafe64FromBytes(encryptedRecord), createOptions.SubFolderUid);
        }

        private static CreateFolderPayload PrepareCreateFolderPayload(IKeyValueStorage storage, CreateOptions createOptions, string folderName, byte[] sharedFolderKey)
        {
            var clientId = storage.GetString(KeyClientId);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            var folderDataBytes = JsonUtils.SerializeJson(new KeeperFolderName { name = folderName });
            var folderKey = CryptoUtils.GetRandomBytes(32);
            var folderUid = CryptoUtils.GetUidBytes();
            var encryptedFolderData = CryptoUtils.Encrypt(folderDataBytes, folderKey, true);
            var encryptedFolderKey = CryptoUtils.Encrypt(folderKey, sharedFolderKey, true);

            return new CreateFolderPayload(GetClientVersion(), clientId,
                CryptoUtils.WebSafe64FromBytes(folderUid), createOptions.FolderUid,
                CryptoUtils.WebSafe64FromBytes(encryptedFolderKey), CryptoUtils.WebSafe64FromBytes(encryptedFolderData),
                createOptions.SubFolderUid);
        }

        private static UpdateFolderPayload PrepareUpdateFolderPayload(IKeyValueStorage storage, string folderUid, string folderName, byte[] folderKey)
        {
            var clientId = storage.GetString(KeyClientId);
            if (clientId == null)
            {
                throw new Exception("Client Id is missing from the configuration");
            }

            var folderDataBytes = JsonUtils.SerializeJson(new KeeperFolderName { name = folderName });
            var encryptedFolderData = CryptoUtils.Encrypt(folderDataBytes, folderKey, true);

            return new UpdateFolderPayload(GetClientVersion(), clientId, folderUid, CryptoUtils.WebSafe64FromBytes(encryptedFolderData));
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

        public static GetRandomBytesFunction TransmissionKeyStub { get; set; }

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
