using System;
using System.Threading.Tasks;
using SecretsManager;

namespace QuickTest
{
   
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
            var storage = new LocalConfigStorage("config.txt");
            SecretsManagerClient.InitializeStorage(storage, "3WBJhiyKJ6nlHrRRKfOIowOPrSht40qdSF03erP45LU", "local.keepersecurity.com");
            var resp = await SecretsManagerClient.FetchAndDecryptSecrets(storage);
            return "";
        }
    }
}