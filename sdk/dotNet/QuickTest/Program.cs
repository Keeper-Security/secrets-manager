using System;
using System.Threading.Tasks;
using SecretsManager;

namespace QuickTest
{
    class LocalConfigStorage : IKeyValueStorage
    {
        public string GetString(string key)
        {
            return key;
        }
    }
    
    
    public static class Program
    {
        static void Main(string[] args)
        {
            // Console.WriteLine(SecretsManagerClient.GetSecrets());
            GetSecrets().Wait();
        }

        static async Task<string> GetSecrets()
        {
            var resp = await SecretsManagerClient.FetchAndDecryptSecrets(new LocalConfigStorage());
            Console.WriteLine(resp);
            return resp;
        }
    }
}