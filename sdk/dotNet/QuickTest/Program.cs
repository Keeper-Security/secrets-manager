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
            var storage = new LocalConfigStorage("config-prod1.json");
            // ReSharper disable once StringLiteralTypo
            // SecretsManagerClient.InitializeStorage(storage, "g6lUTlCcFZz15hgIqQ02krBZ3ltv868xRlI1Q3NLcgI", "keepersecurity.com");
            var options = new SecretsManagerOptions(storage);
            // var options = new SecretsManagerOptions(storage, SecretsManagerClient.CachingPostFunction);
            var secrets = await SecretsManagerClient.GetSecrets(options);
            // var password = Notation.GetValue(secrets, "BediNKCMG21ztm5xGYgNww/field/password");
            var firstRecord = secrets.Records[0]; 
            var password = firstRecord.FieldValue("password").ToString();
            Console.WriteLine(password);
            // var fileBytes = SecretsManagerClient.DownloadFile(firstRecord.Files[0]);
            // Console.WriteLine(fileBytes.Length);
            firstRecord.UpdateFieldValue("password", "111111111");
            await SecretsManagerClient.UpdateSecret(options, firstRecord);
        }
    }
}