using System;
using System.Collections;
using System.Linq;
using System.Net;
using System.Security;
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
                return Microsoft.PowerShell.SecretStore.LocalSecretStore.GetInstance().WriteObject("KeeperVault." + vaultName, storage.AsHashTable(), out errorMsg)
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

        public static int SetVaultConfig1(string oneTimeToken, string vaultName)
        {
            throw new Exception("test");
            return 1;
        }


        public static async Task<Hashtable> GetSecret(string name, string vaultName, Hashtable additionalParameters)
        {
            var records = await GetKeeperSecrets(vaultName);
            var found = records.FirstOrDefault(x => x.Data.title == name);
            if (found == null)
            {
                return null;
            }

            var dict = found.Data.fields
                .Where(x => x.value.Length > 0)
                .ToDictionary(x => x.label ?? x.type, y => y.value[0].ToString());
            return new Hashtable(dict);
        }

        private static async Task<KeeperRecord[]> GetKeeperSecrets(string vaultName)
        {
            if (!Microsoft.PowerShell.SecretStore.LocalSecretStore.GetInstance().ReadObject("KeeperVault." + vaultName, out var config, out var errorMsg))
            {
                throw new Exception($"Keeper Vault {vaultName} does not have a valid local config. Use Register-KeeperVault command to register.");
            }

            try
            {
                var storage = new InMemoryStorage(config as Hashtable);
                var secrets = await SecretsManagerClient.GetSecrets(new SecretsManagerOptions(storage));
                return secrets.Records;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public static async Task<string[]> GetSecretsInfo(string filter, string vaultName, Hashtable additionalParameters)
        {
            var records = await GetKeeperSecrets(vaultName);
            return records.Select(x => x.Data.title).ToArray();
        }
    }

    public static class Extensions
    {
        public static string ToPlainString(this SecureString secureStr)
        {
            string plainStr = new NetworkCredential(string.Empty, secureStr).Password;
            return plainStr;
        }

        public static SecureString ToSecureString(this string plainStr)
        {
            var secStr = new SecureString();
            secStr.Clear();
            foreach (var c in plainStr)
            {
                secStr.AppendChar(c);
            }

            return secStr;
        }
    }
}