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
using Google.Cloud.Kms.V1;

namespace GCPKeyManagement
{
    public class GCPKeyValueStorage : IKeyValueStorage
    {
        private const string DefaultConfigFileLocation = "client-config.json";
        private bool IsInitialized = false; private GCPKeyConfig keyConfig;
        private GCPKMSClient ksmClient;
        private KeyManagementServiceClient cryptoClient;
        private Dictionary<string, string> config = new();
        private string lastSavedConfigHash;
        private readonly string configFileLocation = DefaultConfigFileLocation;
        private readonly ILogger logger;
        private bool IsAsymmetric;
        public string? encryptionAlgorithm;
        public string? keyType;

        public GCPKeyValueStorage(GCPKeyConfig keyConfig, GCPKMSClient? credentials = null, string? configFileLocation = null, ILogger<GCPKeyValueStorage>? logger = null)
        {
            this.logger = GetLogger(logger);
            this.keyConfig = keyConfig;
            if (configFileLocation == null)
            {
                this.configFileLocation = Path.GetFullPath(DefaultConfigFileLocation);
            }
            else
            {
                this.configFileLocation = Path.GetFullPath(configFileLocation);
            }

            ksmClient = credentials ?? new GCPKMSClient();
            cryptoClient = ksmClient.GetCryptoClient();
            lastSavedConfigHash = "";
        }

        private async Task InitializeClient()
        {
            await GetKeyDetailsAsync();
            await LoadConfigAsync();
            IsInitialized = true;
        }

        private ILogger GetLogger(ILogger? logger)
        {
            return logger ?? LoggerFactory.Create(builder =>
            {
                builder.SetMinimumLevel(LogLevel.Information);
                builder.AddConsole();
            }).CreateLogger<GCPKeyValueStorage>();
        }

        public string? GetString(string key)
        {
            if (!IsInitialized)
            {
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
            if (!IsInitialized)
            {
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
            if (!IsInitialized)
            {
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
            if (!IsInitialized)
            {
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
            if (!IsInitialized)
            {
                InitializeClient().Wait();
            }
            config.Remove(key);
            SaveConfigAsync(config).Wait();
        }

        private async Task CreateConfigFileIfMissingAsync()
        {
            try
            {
                if (File.Exists(configFileLocation))
                {
                    logger.LogInformation("Config file already exists at: {Path}", configFileLocation);
                    return;
                }

                logger.LogInformation("Config file does not exist at: {Path}", configFileLocation);
                string? directory = Path.GetDirectoryName(configFileLocation);
                if (directory != null && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                EncryptBufferOptions options = new EncryptBufferOptions
                {
                    KeyPurpose = keyType,
                    KeyProperties = keyConfig,
                    Message = "{}",
                    EncryptionAlgorithm = encryptionAlgorithm,
                    IsAsymmetric = IsAsymmetric,
                    CryptoClient = cryptoClient,
                };
                if (keyType == "RawEncryptDecrypt")
                {
                    var token = await ksmClient.getToken();
                    options.token = token;
                }
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
                catch (JsonException ex)
                {
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
                        DecryptBufferOptions options = new()
                        {
                            KeyPurpose = keyType,
                            KeyProperties = keyConfig,
                            Ciphertext = contents,
                            IsAsymmetric = IsAsymmetric,
                            CryptoClient = cryptoClient,
                            EncryptionAlgorithm = encryptionAlgorithm,
                        };
                        if (keyType == "RawEncryptDecrypt")
                        {
                            var token = await ksmClient.getToken();
                            options.token = token;
                        }
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
                var keyName = keyConfig.ToKeyName();
                var request = new GetCryptoKeyRequest { Name = keyName };
                CryptoKey key = await cryptoClient.GetCryptoKeyAsync(request);

                encryptionAlgorithm = key.VersionTemplate?.Algorithm.ToString() ?? string.Empty;
                string keyPurposeDetails = key.Purpose.ToString();

                logger.LogDebug("Key purpose: {KeyPurpose}. encryptionAlgorithm: {EncryptionAlgorithm}", keyPurposeDetails, encryptionAlgorithm);

                var exists = Array.IndexOf(IntegrationConstants.SupportedKeySpecs, keyPurposeDetails);
                if (exists < 0)
                {
                    logger.LogError("Unsupported Key Spec for GCP KMS Storage");
                    throw new InvalidOperationException("Unsupported Key Spec for GCP KMS Storage");
                }

                IsAsymmetric = key.Purpose == CryptoKey.Types.CryptoKeyPurpose.AsymmetricDecrypt;
                keyType = keyPurposeDetails;
            }
            catch (Exception ex)
            {
                logger.LogWarning($"Failed to read key details - key may be incompatible with desired encrypt/decrypt operations  - error:{ex.Message}");
                throw;
            }
        }

        private async Task SaveConfigAsync(Dictionary<string, string>? updatedConfig = null, bool force = false)
        {
            try
            {
                // Retrieve current config
                Dictionary<string, string> currentConfig = config ?? new();
                string configJson = SerializeConfig(currentConfig);
                string configHash = ComputeMD5Hash(configJson);
                logger.LogDebug("Computed config hash after serializing the data received by SaveConfigAsync");
                // Compare updatedConfig hash with current config hash
                if (updatedConfig != null && updatedConfig.Count > 0)
                {
                    string updatedConfigJson = SerializeConfig(updatedConfig);
                    string updatedConfigHash = ComputeMD5Hash(updatedConfigJson);

                    if (updatedConfigHash != configHash)
                    {
                        logger.LogDebug("Updated config as its current config is different from given config");
                        configHash = updatedConfigHash;
                        config = new Dictionary<string, string>(updatedConfig);
                    }
                }

                // Check if saving is necessary
                if (!force && configHash == lastSavedConfigHash)
                {
                    logger.LogWarning("Skipped config JSON save. No changes detected.");
                    return;
                }

                logger.LogDebug("Checking configuration file presence and creating one if its absent");
                // Ensure the config file exists
                await CreateConfigFileIfMissingAsync();

                var serializedConfig = SerializeConfig(config);
                EncryptBufferOptions options = new EncryptBufferOptions
                {
                    KeyPurpose = keyType,
                    KeyProperties = keyConfig,
                    Message = serializedConfig,
                    EncryptionAlgorithm = encryptionAlgorithm,
                    CryptoClient = cryptoClient,
                    IsAsymmetric = IsAsymmetric,
                };
                if (keyType == "RawEncryptDecrypt")
                {
                    options.token = await ksmClient.getToken();
                }
                // Encrypt the config JSON and write to the file
                byte[] blob = await IntegrationUtils.EncryptBufferAsync(options, logger);
                if (blob.Length != 0)
                {
                    await File.WriteAllBytesAsync(configFileLocation, blob);
                    logger.LogDebug("Config file saved successfully");
                }
                // Update the last saved config hash
                lastSavedConfigHash = configHash;
            }
            catch (Exception ex)
            {
                logger.LogError("Error saving config: {Message}", ex.Message);
            }
        }

        public async Task<string> DecryptConfigAsync(bool autosave)
        {
            if (!IsInitialized)
            {
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
                DecryptBufferOptions options = new DecryptBufferOptions
                {
                    Ciphertext = ciphertext,
                    KeyPurpose = keyType,
                    KeyProperties = keyConfig,
                    IsAsymmetric = IsAsymmetric,
                    CryptoClient = cryptoClient,
                    EncryptionAlgorithm = encryptionAlgorithm,
                };
                if (keyType == "RawEncryptDecrypt")
                {
                    options.token = await ksmClient.getToken();
                }
                // Decrypt the file contents
                plaintext = await IntegrationUtils.DecryptBufferAsync(options, logger);
                if (string.IsNullOrWhiteSpace(plaintext))
                {
                    logger.LogInformation("Failed to decrypt config file {File}", configFileLocation);
                }
                else if (autosave)
                {
                    logger.LogDebug("Autosave config flag has been passed as {autosave}, hence saving..", autosave);
                    if (plaintext.Length != 0)
                    {
                        await File.WriteAllTextAsync(configFileLocation, plaintext);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError("Failed to write decrypted config file {File}: {Message}", configFileLocation, ex.Message);
                throw new Exception($"Failed to write decrypted config file {configFileLocation}");
            }

            return plaintext;
        }

        public async Task<bool> ChangeKeyAsync(GCPKeyConfig newGcpKeyConfig)
        {
            if (!IsInitialized)
            {
                InitializeClient().Wait();
            }
            var oldKeyConfig = keyConfig;
            var oldKmsClient = ksmClient;
            logger.LogDebug("changing key configuration");
            try
            {
                // Check if config needs initialization
                if (config == null || (config is System.Collections.ICollection collection && collection.Count == 0))
                {
                    logger.LogDebug("Config is null or empty, initializing it");
                    await LoadConfigAsync();
                }

                keyConfig = newGcpKeyConfig;
                await GetKeyDetailsAsync();
                await SaveConfigAsync(new Dictionary<string, string>(), true);
                logger.LogInformation("Successfully changed the key to '{newGcpKeyConfig}' for config '{configFileLocation}'", newGcpKeyConfig, configFileLocation);
            }
            catch (Exception ex)
            {
                // Restore the previous key config and KMS client if the operation fails
                keyConfig = oldKeyConfig;
                ksmClient = oldKmsClient;

                logger.LogError($"Failed to change the key to '{newGcpKeyConfig}' for config '{configFileLocation}': {ex.Message}");
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
