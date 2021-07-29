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
            var storage = new LocalConfigStorage("config.txt");
            SecretsManagerClient.InitializeStorage(storage, "R7bJVTU_xGRDBo-BNRs-WVLTeqX-qNIob8MBw-VNvaw", "dev.keepersecurity.com");
            var secrets = await SecretsManagerClient.GetSecrets(storage);
            var password = secrets.Records[0].FieldValue("password").ToString();
            Console.WriteLine(password);
            secrets.Records[1].UpdateCustomFieldValue("date", 123123);
            var serialized = CryptoUtils.BytesToString(JsonUtils.SerializeJson(secrets.Records[1].Data));
            Console.WriteLine(serialized);
            return password;
        }
    }
}