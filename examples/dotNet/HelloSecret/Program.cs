using System;
using System.IO;
using System.Threading.Tasks;
using SecretsManager;

namespace HelloSecret
{
    public static class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: dotnet run %config_name% %client_key");
                Console.WriteLine("F.e. dotnet run config.json EvdTdbH1xbHuRcja7QG3wMOyLUbvoQgF9WkkrHTdkh");
                Console.WriteLine("Use %client_key% only once to initialize the config. For subsequent runs, dotnet run %config_name%");
                return;
            }

            try
            {
                GetSecrets(args[0], args.Length > 1 ? args[1] : null).Wait();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        private static async Task GetSecrets(string configName, string clientKey)
        {
            var storage = new LocalConfigStorage(configName);
            Console.WriteLine($"Local Config Storage opened from the file {configName}");
            if (clientKey != null)
            {
                Console.WriteLine($"Local Config Storage initialized with the Client Key ${clientKey}");
                // if your Keeper Account is in other region than US, update the hostname accordingly  
                SecretsManagerClient.InitializeStorage(storage, clientKey, "keepersecurity.com");
            }

            var options = new SecretsManagerOptions(storage);
            // var options = new SecretsManagerOptions(storage, SecretsManagerClient.CachingPostFunction);
            var secrets = await SecretsManagerClient.GetSecrets(options);
            // var secrets = await SecretsManagerClient.GetSecrets(options, new[] { "UlzQ-jKQTgQcEvpJI9vxxQ" }));
            Console.WriteLine($"Received {secrets.Records.Length} record(s)");

            // get the password from the first record
            var firstRecord = secrets.Records[0];
            var password = firstRecord.FieldValue("password").ToString();
            Console.WriteLine($"Password: {password}");

            // alternative way to get field value
            // var password = Notation.GetValue(secrets, "BediNKCMG21ztm5xGYgNww/field/password");

            // download the file from the 1st record
            var file = firstRecord.GetFileByName("acme.cer");
            if (file != null)
            {
                var fileBytes = SecretsManagerClient.DownloadFile(file);
                await File.WriteAllBytesAsync(file.Data.name, fileBytes);
            }

            firstRecord.UpdateFieldValue("password", "aP1$t367QOCvL$eM$bG#");
            await SecretsManagerClient.UpdateSecret(options, firstRecord);
        }
    }
}