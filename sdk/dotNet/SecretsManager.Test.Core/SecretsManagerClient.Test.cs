using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading.Tasks;
using NUnit.Framework;

namespace SecretsManager.Test
{
    using QueryFunction = Func<string, TransmissionKey, EncryptedPayload, Task<KeeperHttpResponse>>;

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    [SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
    public class TestResponse
    {
        public string transmissionKey { get; set; }
        public string data { get; set; }
        public int statusCode { get; set; }
    }
    
    public class SecretsManagerClientTests
    {
        [Test]
        public async Task GetSecretsE2E()
        {
            var fileBytes = await File.ReadAllBytesAsync("../../../../../test_data.json");
            var testResponses = JsonUtils.ParseJson<TestResponse[]>(fileBytes);
            var responseNo = 0;
            SecretsManagerClient.TransmissionKeyStub = _ => CryptoUtils.Base64ToBytes(testResponses[responseNo].transmissionKey);

            Task<KeeperHttpResponse> TestPostFunction(string s, TransmissionKey transmissionKey, EncryptedPayload encryptedPayload)
            {
                var response = testResponses[responseNo++];
                return Task.FromResult(new KeeperHttpResponse(CryptoUtils.Base64ToBytes(response.data), response.statusCode != 200));
            }

            var storage = new LocalConfigStorage();
            SecretsManagerClient.InitializeStorage(storage, "VB3sGkzVyRB9Lup6WE7Rx-ETFZxyWR2zqY2b9f2zwBo", "local.keepersecurity.com");
            var options = new SecretsManagerOptions(storage, TestPostFunction);
            var secrets = await SecretsManagerClient.GetSecrets(options);
            var password = secrets.Records[1].FieldValue("password").ToString();
            // ReSharper disable once StringLiteralTypo
            Assert.AreEqual("N$B!lkoOrVL1RUNDBvn2", password);
        }
    }
}