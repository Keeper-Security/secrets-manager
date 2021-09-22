using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Management.Automation;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.PowerShell.SecretStore;
using SecretsManager;

namespace SecretManagement.Keeper
{
    public static class Client
    {
        public static async Task<KeeperResult> SetVaultConfig(string oneTimeToken, string vaultName)
        {
            string errorMsg;
            LocalSecretStore localStore = null;
            try
            {
                localStore = LocalSecretStore.GetInstance();
                var configName = "KeeperVault." + vaultName;
                if (!localStore.WriteObject(configName, "test", out errorMsg))
                {
                    return new KeeperResult($"Error accessing the local secret storage: {errorMsg}");
                }

                var storage = new InMemoryStorage();
                SecretsManagerClient.InitializeStorage(storage, oneTimeToken, "keepersecurity.com");
                await SecretsManagerClient.GetSecrets(new SecretsManagerOptions(storage));
                return LocalSecretStore.GetInstance().WriteObject("KeeperVault." + vaultName, storage.AsHashTable(), out errorMsg)
                    ? new KeeperResult()
                    : new KeeperResult(errorMsg);
            }
            catch (Exception e)
            {
                if (localStore != null)
                {
                    localStore.DeleteObject(vaultName, out errorMsg);
                }

                return new KeeperResult($"Error connecting to the Keeper Vault: {e.Message}");
            }
        }

        [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
        [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
        public class KeeperResult
        {
            public bool IsFailure { get; }
            public string ErrorMsg { get; }

            public KeeperResult()
            {
            }

            public KeeperResult(string errorMsg)
            {
                IsFailure = true;
                ErrorMsg = errorMsg;
            }
        }

        public static async Task<object> GetSecret(string name, string vaultName)
        {
            var parts = name.Split('.');
            var (records, _) = await GetKeeperSecrets(vaultName);
            var found = records.FirstOrDefault(x => x.Data.title == parts[0]);
            if (found == null)
            {
                return null;
            }

            var dict = new Dictionary<string, object>();
            if (parts.Length > 1)
            {
                if (parts[1].StartsWith("Files[", true, CultureInfo.InvariantCulture))
                {
                    var fileIdx = int.Parse(parts[1].Substring(6, parts[1].IndexOf(']') - 6));
                    if (found.Files == null || found.Files.Length < fileIdx + 1)
                    {
                        return null;
                    }

                    return SecretsManagerClient.DownloadFile(found.Files[fileIdx]);
                }

                var field = found.Data.fields.FirstOrDefault(x => (x.label ?? x.type).Equals(parts[1], StringComparison.OrdinalIgnoreCase));
                return field?.value[0].ToString();
            }

            foreach (var field in found.Data.fields)
            {
                if (field.type == "fileRef" || field.value.Length == 0)
                {
                    continue;
                }

                dict[field.label ?? field.type] = field.value[0].ToString();
            }

            if (found.Files != null)
            {
                dict["Files"] = found.Files.Select(x => x.Data.title).ToArray();
            }

            return new Hashtable(dict);
        }

        public static async Task<string[]> GetSecretsInfo(string filter, string vaultName)
        {
            var (records, _) = await GetKeeperSecrets(vaultName);
            var filterPattern = new WildcardPattern(
                pattern: filter,
                options: WildcardOptions.IgnoreCase);
            return records
                .Where(x => filterPattern.IsMatch(x.Data.title))
                .Select(x => x.Data.title).ToArray();
        }

        public static async Task<KeeperResult> SetSecret(string name, object secret, string vaultName)
        {
            var parts = name.Split('.');
            if (parts.Length == 1)
            {
                return new KeeperResult("Set-Secret can be used only on a single field");
            }

            var (records, options) = await GetKeeperSecrets(vaultName);
            var found = records.FirstOrDefault(x => x.Data.title == parts[0]);
            if (found == null)
            {
                return new KeeperResult("Set-Secret can only be used to update existing Keeper secrets");
            }

            var field = found.Data.fields.FirstOrDefault(x => (x.label ?? x.type).Equals(parts[1], StringComparison.OrdinalIgnoreCase));
            if (field == null)
            {
                return new KeeperResult("Set-Secret can only be used to update existing Keeper secrets");
            }

            var fieldValueJson = (JsonElement)field.value[0];
            
            // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
            var typeMismatch = false;
            switch (fieldValueJson.ValueKind)
            {
                case JsonValueKind.String:
                    if (!(secret is string))
                    {
                        typeMismatch = true;
                    }
                    break;
                case JsonValueKind.Number:
                    if (!(secret is int))
                    {
                        typeMismatch = true;
                    }
                    break;
                default:
                    return new KeeperResult($"Setting values for the field {parts[1]} is not supported");
            } 
            if (typeMismatch)
            {
                return new KeeperResult($"The new value for field {parts[1]} does not match the existing type");
            }
            field.value[0] = secret;

            try
            {
                await SecretsManagerClient.UpdateSecret(options, found);
            }
            catch (Exception e)
            {
                return new KeeperResult(e.Message);
            }

            return new KeeperResult();
        }
        
        public static async Task<bool> TestVault(string vaultName)
        {
            try
            {
                await GetKeeperSecrets(vaultName);
                return true;
            }
            catch 
            {
                return false;
            }
        }

        private static async Task<Tuple<KeeperRecord[], SecretsManagerOptions>> GetKeeperSecrets(string vaultName)
        {
            if (!LocalSecretStore.GetInstance().ReadObject("KeeperVault." + vaultName, out var config, out _))
            {
                throw new Exception($"Keeper Vault {vaultName} does not have a valid local config. Use Register-KeeperVault command to register.");
            }

            var storage = new InMemoryStorage(config as Hashtable);
            var options = new SecretsManagerOptions(storage);
            var secrets = await SecretsManagerClient.GetSecrets(options);
            return new Tuple<KeeperRecord[], SecretsManagerOptions>(secrets.Records, options);
        }
    }
}