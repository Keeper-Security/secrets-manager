using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecretsManager;

// This is basic example of creating custom caching function
// ⓘ CacheStorage only stores last request, however you can use any tool to extend this functionality
// ⓘ Stale cache entries can cause version mismatches if records are updated from other keepersecurity utils. Prefer fresh reads

namespace HelloSecretCustomCaching
{
    public static class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: dotnet run %config_name% %client_key%");
                Console.WriteLine("F.e. dotnet run config.json US:EXAMPLE_ONE_TIME_TOKEN");
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

        private static async Task<KeeperHttpResponse> CachingPostFunction(string url, TransmissionKey transmissionKey, EncryptedPayload payload)
        {
            try
            {
                var allowUnverifiedCertificate = false;
                var response = await SecretsManagerClient.PostFunction(url, transmissionKey, payload, allowUnverifiedCertificate);
                if (!response.IsError)
                {
                    CacheStorage.SaveCachedValue(transmissionKey.Key.Concat(response.Data).ToArray());
                }

                return response;
            }
            catch (Exception)
            {
                Console.WriteLine("Using cache data");

                var cachedData = CacheStorage.GetCachedValue();
                var cachedTransmissionKey = cachedData.Take(32).ToArray();
                transmissionKey.Key = cachedTransmissionKey;
                var data = cachedData.Skip(32).ToArray();
                return new KeeperHttpResponse(data, false);
            }
        }

        private static async Task GetSecrets(string configName, string clientKey)
        {
            var storage = new LocalConfigStorage(configName);
            Console.WriteLine($"Local Config Storage opened from the file {configName}");
            if (clientKey != null)
            {
                Console.WriteLine($"Local Config Storage initialized with the Client Key {clientKey}");
                SecretsManagerClient.InitializeStorage(storage, clientKey, "keepersecurity.com");
            }

            var options = new SecretsManagerOptions(storage, CachingPostFunction);
            var secrets = await SecretsManagerClient.GetSecrets(options);
            Console.WriteLine($"Received {secrets.Records.Length} record(s)");

            foreach (var record in secrets.Records)
            {
                Console.WriteLine(record);
            }
        }
    }
}