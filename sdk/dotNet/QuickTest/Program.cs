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
            var storage = new LocalConfigStorage("test_config_storage.json");
            // Initialize Storage only once - generates config.json from one-time token
            // SecretsManagerClient.InitializeStorage(storage, "US:ONE_TIME_TOKEN");
            var options = new SecretsManagerOptions(storage);
            // var options = new SecretsManagerOptions(storage, SecretsManagerClient.CachingPostFunction);
            var secrets = await SecretsManagerClient.GetSecrets(options);
            // var password = Notation.GetValue(secrets, "RECORD_UID/field/password");
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
            // firstRecord.AddCustomField(new Text("Additional notes") { label = "Custom notes" });
            // await SecretsManagerClient.UpdateSecret(options, firstRecord);
        }
    }
}
