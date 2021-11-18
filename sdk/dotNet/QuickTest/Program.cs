using SecretsManager;
using System;
using System.Threading.Tasks;

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
            var storage = new LocalConfigStorage("config-dev-msp.json");
            // ReSharper disable once StringLiteralTypo
            SecretsManagerClient.InitializeStorage(storage, "dev.keepersecurity.com:kpsySedoEYM52vq8aoM6IBbNIxiWHtTwcou0FRQ4GkE");
            var options = new SecretsManagerOptions(storage);
            // var options = new SecretsManagerOptions(storage, SecretsManagerClient.CachingPostFunction);
            var secrets = await SecretsManagerClient.GetSecrets(options);
            // var password = Notation.GetValue(secrets, "BediNKCMG21ztm5xGYgNww/field/password");
            var firstRecord = secrets.Records[0];
            var password = firstRecord.FieldValue("password").ToString();
            Console.WriteLine(password);
            // if (firstRecord.FolderUid != null)
            // {
            //     firstRecord.Data.title += ".Net Copy";
            //     var recordUid = await SecretsManagerClient.CreateSecret(options, firstRecord.FolderUid, firstRecord.Data, secrets);
            //     Console.WriteLine(recordUid);
            // }
            // var fileBytes = SecretsManagerClient.DownloadFile(firstRecord.Files[0]);
            // Console.WriteLine(fileBytes.Length);
            // firstRecord.UpdateFieldValue("password", "111111111");
            // await SecretsManagerClient.UpdateSecret(options, firstRecord);
        }
    }
}