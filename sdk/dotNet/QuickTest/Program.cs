using System;
using System.Threading.Tasks;
using SecretsManager;

namespace QuickTest
{
    public static class Program
    {
        private static void Main()
        {
            try
            {
                GetSecrets().Wait();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        private static async Task<string> GetSecrets()
        {
            var storage = new LocalConfigStorage("config.json");
            // SecretsManagerClient.InitializeStorage(storage, "jvoHXRYYdf7cpxFISeqf9O0L4N9Tbr3e1a7wV2a4zPE", "qa.keepersecurity.com");
            var secrets = await SecretsManagerClient.GetSecrets(storage);
            var password = secrets.Records[0].FieldValue("password").ToString();
            Console.WriteLine(password);
            return password;
        }
    }
}