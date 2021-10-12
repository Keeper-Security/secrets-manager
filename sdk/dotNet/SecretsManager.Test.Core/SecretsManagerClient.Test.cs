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

        [Test]
        public void TestStoragePrefixes()
        {
            var storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "US:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw");
            Assert.AreEqual("keepersecurity.com", storage.GetString("hostname"));

            storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "EU:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw");
            Assert.AreEqual("keepersecurity.eu", storage.GetString("hostname"));

            storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "AU:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw");
            Assert.AreEqual("keepersecurity.com.au", storage.GetString("hostname"));

            storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "eu:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw");
            Assert.AreEqual("keepersecurity.eu", storage.GetString("hostname"));

            storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "local.keepersecurity.com:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw");
            Assert.AreEqual("local.keepersecurity.com", storage.GetString("hostname"));
        }

        [Test]
        public void TestStorageBase64Config()
        {
            string base64Config = "eyAgICAgImFwcEtleSI6ICI4S3gyNVN2dGtSU3NFWUl1cjdtSEt0THFBTkZOQjdBWlJhOWNxaTJQU1FFPSIsICAgICAiY2x" +
                "pZW50SWQiOiAiNEgvVTVKNkRjZktMWUJJSUFWNVl3RUZHNG4zWGhpRHZOdG9Qa21TTUlUZVROWnNhL0VKMHpUYnBBQ1J0bU" +
                "5VQlJIK052UisyNHNRaFU5dUdqTFRaSHc9PSIsICAgICAiaG9zdG5hbWUiOiAia2VlcGVyc2VjdXJpdHkuY29tIiwgICAgI" +
                "CJwcml2YXRlS2V5IjogIk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ3VoekRJNGlW" +
                "UzVCdzlsNWNmZkZYcFArRmh1bE5INDFHRFdWY3NiZ1h5aU9oUkFOQ0FBVGsxZnpvTDgvVkxwdVl1dTEzd0VsUE5wM2FHMmd" +
                "sRmtFUHp4YWlNZ1ArdnRVZDRnWjIzVHBHdTFzMXRxS2FFZTloN1ZDVk1qd3ZEQTMxYW5mTWxZRjUiLCAgICAgInNlcnZlcl" +
                "B1YmxpY0tleUlkIjogIjEwIiB9";
            var storage = new InMemoryStorage(base64Config);
            Assert.AreEqual("keepersecurity.com", storage.GetString("hostname"));
        }
    }
}