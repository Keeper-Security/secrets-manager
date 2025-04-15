#nullable enable

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using SecretsManager;
using Microsoft.Extensions.Logging;
using System.IO;
using System.Text;
using System.Linq;
using Oci.KeymanagementService.Responses;

namespace OracleKeyManagement
{
    public class OracleKeyValueStorage : IKeyValueStorage
    {
        private const string DefaultConfigFileLocation = "client-config.json";

        private OciKmsClient ksmClient;
        private Oci.KeymanagementService.KmsCryptoClient cryptoClient;
        private Oci.KeymanagementService.KmsManagementClient managementClient;
        private Dictionary<string, string> config = new();
        private string lastSavedConfigHash;
        private readonly string configFileLocation = DefaultConfigFileLocation;
        private readonly ILogger logger;

        public string KeyId { get; private set; }
        public string KeyVersionId { get; private set; }

        private bool IsInitialized = false;
        private bool IsAsymmetric;

        public OracleKeyValueStorage(string KeyId, string KeyVersionId, string? configFileLocation = null, OciSessionConfig? ociSessionConfig = null, ILogger? logger = null)
        {
            this.logger = GetLogger(logger);
            this.KeyId = KeyId;
            this.KeyVersionId = KeyVersionId;
            if (configFileLocation == null)
            {
                configFileLocation = Path.GetFullPath(DefaultConfigFileLocation);
            }
            else
            {
                this.configFileLocation = Path.GetFullPath(configFileLocation);
            }

            ksmClient = new OciKmsClient(ociSessionConfig,this.logger);
            cryptoClient = ksmClient.GetCryptoClient();
            managementClient = ksmClient.GetManagementClient();
            lastSavedConfigHash = "";
            
        }

        private async Task InitializeClient(){
            await GetKeyDetailsAsync();
            await LoadConfigAsync();
            IsInitialized =  true;
        }

        private ILogger GetLogger(ILogger? logger){
            return logger ?? LoggerFactory.Create(builder =>
            {
                builder.SetMinimumLevel(LogLevel.Information);
                builder.AddConsole();
            }).CreateLogger<OracleKeyValueStorage>();
        }

        public string? GetString(string key)
        {   
            if (!IsInitialized){
                InitializeClient().Wait();
            }
            if (config.Count == 0)
            {
                LoadConfigAsync().Wait();
            }
            return config.TryGetValue(key, out var value) ? value : null;
        }

        public void SaveString(string key, string value)
        {
            if (!IsInitialized){
                InitializeClient().Wait();
            }
            if (config.Count == 0)
            {
                LoadConfigAsync().Wait();
            }
            config[key] = value;
            SaveConfigAsync(config).Wait();
        }

        public byte[]? GetBytes(string key)
        {
            if (!IsInitialized){
                InitializeClient().Wait();
            }
            if (config.Count == 0)
            {
                LoadConfigAsync().Wait();
            }

            var stringValue = config.TryGetValue(key, out var result) ? result : null;
            return stringValue == null ? null : CryptoUtils.Base64ToBytes(stringValue);
        }

        public void SaveBytes(string key, byte[] value)
        {
            if (!IsInitialized){
                InitializeClient().Wait();
            }
            if (config.Count == 0)
            {
                LoadConfigAsync().Wait();
            }
            config[key] = CryptoUtils.BytesToBase64(value);
            SaveConfigAsync(config).Wait();
        }

        public void Delete(string key)
        {
            if (!IsInitialized){
                InitializeClient().Wait();
            }
            config.Remove(key);
            SaveConfigAsync(config).Wait();
        }

        private async Task CreateConfigFileIfMissingAsync()
        {
            try
            {
                logger.LogDebug("Checking if config file exists at: {Path}", configFileLocation);
                if (File.Exists(configFileLocation))
                {
                    logger.LogInformation("Config file already exists at: {Path}", configFileLocation);
                    return;
                }

                logger.LogInformation("Config file does not exist at: {Path}", configFileLocation);
                string? directory = Path.GetDirectoryName(configFileLocation);
                if (directory != null && !Directory.Exists(directory))
                {
                    logger.LogDebug("Creating directory: {Path}", directory);
                    Directory.CreateDirectory(directory);
                }

                EncryptOptions options = new EncryptOptions
                {
                    KeyId = KeyId,
                    keyVersionId = KeyVersionId,
                    Message = "{}",
                    IsAsymmetric = IsAsymmetric,
                    CryptoClient = cryptoClient
                };
                // Encrypt an empty configuration and write to the file
                byte[] blob = await IntegrationUtils.EncryptBufferAsync(options, logger);
                if (blob.Length != 0)
                {
                    logger.LogDebug("Config file encryption completed");
                    await File.WriteAllBytesAsync(configFileLocation, blob);
                }
                
                logger.LogInformation("Config file created at: {Path}", configFileLocation);
            }
            catch (Exception ex)
            {
                logger.LogError("Error creating config file: {Message}", ex.Message);
            }
        }

        private async Task LoadConfigAsync()
        {
            logger.LogInformation("Loading config file {Path}", configFileLocation);
            await CreateConfigFileIfMissingAsync();
            logger.LogDebug("Created config file in path if missing else validating.. {Path}", configFileLocation);
            // Check if the content is plain JSON
            Dictionary<string, string>? parsedConfig = null;
            Exception? jsonError = null;
            bool decryptionError = false;
            try
            {
                // Read the config file
                byte[] contents;
                try
                {
                    string configData = File.ReadAllText(configFileLocation);

                    parsedConfig = JsonSerializer.Deserialize<Dictionary<string, string>>(configData);
                    contents = Encoding.UTF8.GetBytes(configData);
                    logger.LogDebug("Valid JSON parsed successfully.");
                    if (parsedConfig != null)
                    {
                        config = parsedConfig;
                        await SaveConfigAsync(config);
                        lastSavedConfigHash = ComputeMD5Hash(SerializeConfig(config));
                        return;
                    }
                    logger.LogInformation("Loaded config file {Path}", configFileLocation);
                }
                catch (JsonException ex){
                    logger.LogDebug($"Error parsing valid JSON: {ex.Message}");
                    contents = await File.ReadAllBytesAsync(configFileLocation);
                    jsonError = ex;
                }
                catch (Exception ex)
                {
                    logger.LogError("Failed to load config file {Path}: {Message}", configFileLocation, ex.Message);
                    throw new Exception($"Failed to load config file {configFileLocation}");
                }

                if (contents.Length == 0)
                {
                    logger.LogWarning("Empty config file {Path}", configFileLocation);
                    contents = Encoding.UTF8.GetBytes("{}");
                }

                // If parsing as JSON failed, try decryption
                if (jsonError != null)
                {
                    try
                    {
                        logger.LogDebug("Config file is not a valid JSON file: {Message}", jsonError.Message);
                        DecryptOptions options = new DecryptOptions
                        {
                            KeyId = KeyId,
                            keyVersionId = KeyVersionId,
                            CipherText = contents,
                            IsAsymmetric = IsAsymmetric,
                            CryptoClient = cryptoClient,
                        };
                        string decryptedJson = await IntegrationUtils.DecryptBufferAsync(options, logger);
                        parsedConfig = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedJson);
                        logger.LogDebug("Decrypted config file successfully.");

                        if (parsedConfig != null)
                        {
                            config = parsedConfig;
                            lastSavedConfigHash = ComputeMD5Hash(SerializeConfig(config));
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        decryptionError = true;
                        logger.LogDebug("Failed to parse decrypted config file: {Message}", ex.Message);
                        throw new Exception($"Failed to parse decrypted config file {configFileLocation}");
                    }
                }

                if (jsonError != null && decryptionError)
                {
                    logger.LogError("Config file is not a valid JSON file: {Message}", jsonError.Message);
                    throw new Exception($"{configFileLocation} may contain JSON format problems");
                }
            }
            catch (Exception ex)
            {
                logger.LogError("Error loading config: {Message}", ex.Message);
                throw;
            }
        }

        private async Task GetKeyDetailsAsync()
        {
            try
            {
                logger.LogDebug("Getting key details");
                var requestId = Guid.NewGuid().ToString();
                logger.LogDebug("Get key details Request ID: {RequestId}", requestId);
                var keyDetailsRequest = new Oci.KeymanagementService.Requests.GetKeyRequest
                {
                  KeyId = KeyId  
                };

                GetKeyResponse keyDetailsResponse = await managementClient.GetKey(keyDetailsRequest);
                logger.LogDebug("Get key details Response ID: {RequestId}", requestId);
                var Algorithm = keyDetailsResponse.Key.KeyShape.Algorithm;
                logger.LogDebug("Key Algorithm: {Algorithm}", Algorithm);
                if (Algorithm == Oci.KeymanagementService.Models.KeyShape.AlgorithmEnum.Rsa){
                    IsAsymmetric = true;
                }else if(Algorithm == Oci.KeymanagementService.Models.KeyShape.AlgorithmEnum.Aes){
                    IsAsymmetric = false;
                }else {
                    logger.LogError("Unsupported Key Spec for Oracle KMS Storage");
                    throw new Exception("Unsupported Key Spec for Oracle KMS Storage");
                }
            }
            catch (Exception ex)
            {
                logger.LogError($"Failed to get key details: {ex.Message}");
                throw;
            }
        }

        private async Task SaveConfigAsync(Dictionary<string, string>? updatedConfig = null, bool force = false)
        {
            try
            {
                logger.LogDebug("Saving config");
                // Retrieve current config
                Dictionary<string, string> currentConfig = config ?? new();
                string configJson = SerializeConfig(currentConfig);
                string configHash = ComputeMD5Hash(configJson);
                logger.LogDebug("serialized and computed config hash");
                // Compare updatedConfig hash with current config hash
                if (updatedConfig != null && updatedConfig.Count > 0)
                {
                    string updatedConfigJson = SerializeConfig(updatedConfig);
                    string updatedConfigHash = ComputeMD5Hash(updatedConfigJson);

                    if (updatedConfigHash != configHash)
                    {
                        logger.LogDebug("Updated config hash is different from current config hash");
                        configHash = updatedConfigHash;
                        config = new Dictionary<string, string>(updatedConfig);
                        logger.LogDebug("changed config to provided config");
                    }
                }

                // Check if saving is necessary
                if (!force && configHash == lastSavedConfigHash)
                {
                    logger.LogWarning("Skipped config JSON save. No changes detected.");
                    return;
                }

                // Ensure the config file exists
                await CreateConfigFileIfMissingAsync();

                var serializedConfig = SerializeConfig(config);
                EncryptOptions options = new EncryptOptions
                {
                    KeyId = KeyId,
                    keyVersionId = KeyVersionId,
                    Message = serializedConfig,
                    CryptoClient = cryptoClient,
                    IsAsymmetric = IsAsymmetric
                };
                // Encrypt the config JSON and write to the file
                byte[] blob = await IntegrationUtils.EncryptBufferAsync(options, logger);
                if (blob.Length != 0)
                {
                    logger.LogDebug("Config file encryption completed");
                    await File.WriteAllBytesAsync(configFileLocation, blob);
                }
                logger.LogDebug("Saved config to {File}", configFileLocation);
                // Update the last saved config hash
                lastSavedConfigHash = configHash;
            }
            catch (Exception ex)
            {
                logger.LogError("Error saving config: {Message}", ex.Message);
                throw;
            }
        }

        public async Task<string> DecryptConfigAsync(bool autosave = true)
        {
            if (!IsInitialized){
                InitializeClient().Wait();
            }
            byte[] ciphertext;
            string plaintext = "";

            try
            {
                // Read the config file
                if (!File.Exists(configFileLocation))
                {
                    logger.LogError("Config file not found: {File}", configFileLocation);
                    throw new FileNotFoundException($"Config file not found: {configFileLocation}");
                }

                ciphertext = await File.ReadAllBytesAsync(configFileLocation);
                if (ciphertext.Length == 0)
                {
                    logger.LogWarning("Empty config file {File}", configFileLocation);
                    return plaintext;
                }
            }
            catch (Exception ex)
            {
                logger.LogError("Failed to load config file {File}: {Message}", configFileLocation, ex.Message);
                throw new Exception($"Failed to load config file {configFileLocation}");
            }

            try
            {
                DecryptOptions options = new DecryptOptions
                {
                    CipherText = ciphertext,
                    KeyId = KeyId,
                    keyVersionId = KeyVersionId,
                    IsAsymmetric = IsAsymmetric,
                    CryptoClient = cryptoClient,
                };
                // Decrypt the file contents
                plaintext = await IntegrationUtils.DecryptBufferAsync(options, logger);
                if (string.IsNullOrWhiteSpace(plaintext))
                {
                    logger.LogInformation("Failed to decrypt config file {File}", configFileLocation);
                }
                else if (autosave)
                {
                    // Optionally autosave the decrypted content
                    await File.WriteAllTextAsync(configFileLocation, plaintext);
                }
            }
            catch (Exception ex)
            {
                logger.LogError("Failed to write decrypted config file {File}: {Message}", configFileLocation, ex.Message);
                throw new Exception($"Failed to write decrypted config file {configFileLocation}");
            }

            return plaintext;
        }

        public async Task<bool> ChangeKeyAsync(string newKeyId, string? newKeyVersionId, OciSessionConfig? newOciSessionConfig)
        {
            if (!IsInitialized){
                InitializeClient().Wait();
            }
            logger.LogInformation("Changing key config");
            var oldKeyId = KeyId;
            var oldKeyVersionId = KeyVersionId;
            var oldKmsClient = ksmClient;
            try
            {
                // Check if config needs initialization
                if (config == null || (config is System.Collections.ICollection collection && collection.Count == 0))
                {
                    logger.LogDebug("Initializing config as current config is empty");
                    await LoadConfigAsync();
                }

                KeyId = newKeyId;
                if (!(newKeyVersionId == null || newKeyVersionId == "")){
                    KeyVersionId = newKeyVersionId;
                }
                if (newOciSessionConfig != null){
                    ksmClient =new OciKmsClient(newOciSessionConfig, this.logger);
                }

                await GetKeyDetailsAsync();
                await SaveConfigAsync(new Dictionary<string, string>(), true);
            }
            catch (Exception ex)
            {
                // Restore the previous key config and KMS client if the operation fails
                KeyId = oldKeyId;
                KeyVersionId = oldKeyVersionId;
                ksmClient = oldKmsClient;

                logger.LogError($"Failed to change the key to '{newKeyId}' for config '{configFileLocation}': {ex.Message}");
                throw new InvalidOperationException($"Failed to change the key for {configFileLocation}");
            }
            return true;
        }

        private static string SerializeConfig(Dictionary<string, string>? config)
        {
            if (config == null)
            {
                return "{}";
            }
            var sortedKeys = Enumerable.OrderBy(config.Keys, k => k).ToList();
            var sortedConfig = sortedKeys.ToDictionary(k => k, k => config[k]);
            return JsonSerializer.Serialize(sortedConfig, new JsonSerializerOptions { WriteIndented = true });
        }

        private static string ComputeMD5Hash(string input)
        {
            using var md5 = System.Security.Cryptography.MD5.Create();
            byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }
    }
}
