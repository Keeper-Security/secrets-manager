using System;
using System.Threading.Tasks;
using NUnit.Framework;

namespace SecretsManager.Test
{
    public class SecretsManagerClientTests
    {
        [Test]
        public async Task GetSecretsE2E()
        {
            var storage = new LocalConfigStorage();
            SecretsManagerClient.InitializeStorage(storage, "sHD0o4yFny3trdJBz5JKutILElLezHvRuIPHY254o5M", "dev.keepersecurity.com");
            var secrets = await SecretsManagerClient.GetSecrets(new SecretsManagerOptions(storage));
            var password = secrets.Records[0].FieldValue("password").ToString();
            Console.WriteLine(password);
            // Assert.AreEqual(jsonIn, jsonOut);
        }
    }
}