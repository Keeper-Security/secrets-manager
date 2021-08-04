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
            SecretsManagerClient.InitializeStorage(storage, "sHD0o4yFny3trdJBz5JKutILElLezHvRuIPHY254o5M", "dev.keepersecurity.com");
            var options = new SecretsManagerOptions(storage);
            var secrets = await SecretsManagerClient.GetSecrets(options);
            var password = secrets.Records[0].FieldValue("password").ToString();
            Console.WriteLine(password);
            return password;
        }
    }
}