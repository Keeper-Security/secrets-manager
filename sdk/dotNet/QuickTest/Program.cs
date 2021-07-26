using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SecretsManager;

namespace QuickTest
{
    class LocalConfigStorage : IKeyValueStorage
    {
        private readonly Dictionary<string, string> strings = new();
        private readonly Dictionary<string, byte[]> bytes = new();

        public string GetString(string key)
        {
            return strings.TryGetValue(key, out var result) ? result : null;
        }

        public byte[] GetBytes(string key)
        {
            return bytes.TryGetValue(key, out var result) ? result : null;
        }

        public void SaveString(string key, string value)
        {
            strings[key] = value;
        }

        public void SaveBytes(string key, byte[] value)
        {
            bytes[key] = value;
        }
    }
    
    public static class Program
    {
        static void Main(string[] args)
        {
            // Console.WriteLine(SecretsManagerClient.GetSecrets());
            try
            {
                GetSecrets().Wait();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        static async Task<string> GetSecrets()
        {
            var storage = new LocalConfigStorage();
            SecretsManagerClient.InitializeStorage(storage, "kI5mVsDFtt7SvfV5FDMhkj8qqbESUxwVRhnRxiX9jM8", "dev.keepersecurity.com");
            var resp = await SecretsManagerClient.FetchAndDecryptSecrets(storage);
            Console.WriteLine(resp);
            return resp;
        }
    }
}