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

        private static async Task GetSecrets()
        {
            var storage = new LocalConfigStorage("config.json");
            // ReSharper disable once StringLiteralTypo
            SecretsManagerClient.InitializeStorage(storage, "g6lUTlCcFZz15hgIqQ02krBZ3ltv868xRlI1Q3NLcgI", "keepersecurity.com");
            var options = new SecretsManagerOptions(storage);
            // var options = new SecretsManagerOptions(storage, SecretsManagerClient.CachingPostFunction);
            var secrets = await SecretsManagerClient.GetSecrets(options);
            var password = secrets.Records[0].FieldValue("password").ToString();
            Console.WriteLine(password);

            var file = SecretsManager.DownloadFile(secrets.Records[0].Files[0]);
        }
    }
}