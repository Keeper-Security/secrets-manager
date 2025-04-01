#nullable enable

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Azure.Identity;
using SecretsManager;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Logging;
using System.IO;
using System.Text;
using System.Linq;
using Azure.Core;

namespace AzureKeyVault
{

    public class AzureKeyValueStorage : IKeyValueStorage
    {
        private const string DefaultConfigFileLocation = "client-config.json";
        private bool IsInitialized = false;
        private string keyId;
        private CryptographyClient cryptoClient;
        private Dictionary<string, string> config = new();
        private string lastSavedConfigHash;
        private readonly string configFileLocation = DefaultConfigFileLocation;
        private ILogger logger;
        public TokenCredential azureCredentials { get; private set; }

        public AzureKeyValueStorage(string keyId, string? configFileLocation = null, AzureSessionConfig? credentials = null, ILogger? logger = null)
        {
            this.keyId = keyId;
            if (configFileLocation == null)
            {
                configFileLocation = Path.GetFullPath(DefaultConfigFileLocation);
            }
            else
            {
                this.configFileLocation = Path.GetFullPath(configFileLocation);
            }


            // Initialize Azure Key Vault CryptographyClient
            if (credentials != null &&
                !string.IsNullOrEmpty(credentials.TenantId) &&
                !string.IsNullOrEmpty(credentials.ClientId) &&
                !string.IsNullOrEmpty(credentials.ClientSecret))
            {
                // Use ClientSecretCredential when all values are provided
                azureCredentials = new ClientSecretCredential(
                    credentials.TenantId,
                    credentials.ClientId,
                    credentials.ClientSecret);
            }
            else
            {
                // Fallback to DefaultAzureCredential
                azureCredentials = new DefaultAzureCredential();
            }
            cryptoClient = new CryptographyClient(new Uri(keyId), azureCredentials);
            this.logger = GetLogger(logger);
            lastSavedConfigHash = "";
        }

        private async Task InitializeClient(){
            await LoadConfigAsync();
            IsInitialized =  true;
        }

        private ILogger GetLogger(ILogger? logger){
            return logger ?? LoggerFactory.Create(builder =>
            {
                builder.SetMinimumLevel(LogLevel.Information);
                builder.AddConsole();
            }).CreateLogger<AzureKeyValueStorage>();
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

        public async Task CreateConfigFileIfMissingAsync()
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

                // Encrypt an empty configuration and write to the file
                byte[] blob = await IntegrationUtils.EncryptBufferAsync(cryptoClient, "{}", logger);
                await File.WriteAllBytesAsync(configFileLocation, blob);

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
                        
                        string decryptedJson = await IntegrationUtils.DecryptBufferAsync(cryptoClient, contents, logger);
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

        private async Task SaveConfigAsync(Dictionary<string, string>? updatedConfig = null, bool force = false)
        {
            try
            {
                // Retrieve current config
                Dictionary<string, string> currentConfig = config ?? new();
                string configJson = SerializeConfig(currentConfig);
                string configHash = ComputeMD5Hash(configJson);

                // Compare updatedConfig hash with current config hash
                if (updatedConfig != null && updatedConfig.Count > 0)
                {
                    string updatedConfigJson = SerializeConfig(updatedConfig);
                    string updatedConfigHash = ComputeMD5Hash(updatedConfigJson);

                    if (updatedConfigHash != configHash)
                    {
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

                // Ensure the config file exists
                await CreateConfigFileIfMissingAsync();

                // Encrypt the config JSON and write to the file
                byte[] blob = await IntegrationUtils.EncryptBufferAsync(cryptoClient, SerializeConfig(config), logger);
                await File.WriteAllBytesAsync(configFileLocation, blob);

                // Update the last saved config hash
                lastSavedConfigHash = configHash;
            }
            catch (Exception ex)
            {
                logger.LogError("Error saving config: {Message}", ex.Message);
            }
        }

        public async Task<string> DecryptConfigAsync(bool autosave = true)
        {
            byte[] ciphertext;
            string plaintext = "";
            if (!IsInitialized){
                InitializeClient().Wait();
            }
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
                    return "";
                }
            }
            catch (Exception ex)
            {
                logger.LogError("Failed to load config file {File}: {Message}", configFileLocation, ex.Message);
                throw new Exception($"Failed to load config file {configFileLocation}");
            }

            try
            {
                // Decrypt the file contents
                plaintext = await IntegrationUtils.DecryptBufferAsync(cryptoClient, ciphertext, logger);
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

        public async Task<bool> ChangeKeyAsync(string newKeyId)
        {
            if (!IsInitialized){
                InitializeClient().Wait();
            }
            string oldKeyId = keyId;
            CryptographyClient oldCryptoClient = cryptoClient;
            if (!IsInitialized){
                InitializeClient().Wait();
            }
            try
            {
                // Update the key and reinitialize the CryptographyClient
                keyId = newKeyId;
                cryptoClient = new CryptographyClient(new Uri(keyId), azureCredentials);

                await SaveConfigAsync(force: true);
            }
            catch (Exception ex)
            {
                // Restore the previous key and crypto client if the operation fails
                keyId = oldKeyId;
                cryptoClient = oldCryptoClient;

                logger.LogError("Failed to change the key to '{NewKeyId}' for config '{ConfigFile}': {Message}", newKeyId, "config.json", ex.Message);
                throw new Exception($"Failed to change the key for config.json");
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