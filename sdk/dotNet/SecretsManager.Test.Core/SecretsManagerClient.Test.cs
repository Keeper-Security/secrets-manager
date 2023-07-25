using NUnit.Framework;
using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading.Tasks;

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
            var fileBytes = await File.ReadAllBytesAsync("../../../../../fake_data.json");
            var testResponses = JsonUtils.ParseJson<TestResponse[]>(fileBytes);
            var responseNo = 0;
            SecretsManagerClient.TransmissionKeyStub = _ => CryptoUtils.Base64ToBytes(testResponses[responseNo].transmissionKey);

            Task<KeeperHttpResponse> TestPostFunction(string s, TransmissionKey transmissionKey, EncryptedPayload encryptedPayload)
            {
                var response = testResponses[responseNo++];
                return Task.FromResult(new KeeperHttpResponse(CryptoUtils.Base64ToBytes(response.data), response.statusCode != 200));
            }

            var storage = new LocalConfigStorage();

            var fakeOneTimeCode = "YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c";
                
            SecretsManagerClient.InitializeStorage(storage, fakeOneTimeCode, "fake.keepersecurity.com");
            
            var options = new SecretsManagerOptions(storage, TestPostFunction);
            var secrets = await SecretsManagerClient.GetSecrets(options);
            var password = secrets.Records[1].FieldValue("password").ToString();
            // ReSharper disable once StringLiteralTypo
            Assert.AreEqual("Lex1S++Wx6g^,LC.(Vp<", password);
        }

        [Test]
        public void TestStoragePrefixes()
        {
            var storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "US:ONE_TIME_TOKEN");
            Assert.AreEqual("keepersecurity.com", storage.GetString("hostname"));

            storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "EU:ONE_TIME_TOKEN");
            Assert.AreEqual("keepersecurity.eu", storage.GetString("hostname"));

            storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "AU:ONE_TIME_TOKEN");
            Assert.AreEqual("keepersecurity.com.au", storage.GetString("hostname"));

            storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "GOV:ONE_TIME_TOKEN");
            Assert.AreEqual("govcloud.keepersecurity.us", storage.GetString("hostname"));

            storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "JP:ONE_TIME_TOKEN");
            Assert.AreEqual("keepersecurity.jp", storage.GetString("hostname"));

            storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "CA:ONE_TIME_TOKEN");
            Assert.AreEqual("keepersecurity.ca", storage.GetString("hostname"));

            storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "eu:ONE_TIME_TOKEN");
            Assert.AreEqual("keepersecurity.eu", storage.GetString("hostname"));

            storage = new InMemoryStorage();
            SecretsManagerClient.InitializeStorage(storage, "fake.keepersecurity.com:ONE_TIME_TOKEN");
            Assert.AreEqual("fake.keepersecurity.com", storage.GetString("hostname"));
        }

        [Test]
        public void TestStorageBase64Config()
        {
            string fakeBase64Config = "eyJhcHBLZXkiOiAiRkFLRV9BUFBfS0VZIiwgICAgICJjbGllbnRJZCI6ICJGQUtFX0NMSUVOVF9LRV" +
                                      "kiLCAgICAgImhvc3RuYW1lIjogImZha2Uua2VlcGVyc2VjdXJpdHkuY29tIiwgICAgICJwcml2YXRl" +
                                      "S2V5IjogIkZBS0VfUFJJVkFURV9LRVkiLCAgICAKInNlcnZlclB1YmxpY0tleUlkIjogIjEwIiB9";
            
            var storage = new InMemoryStorage(fakeBase64Config);
            Assert.AreEqual("fake.keepersecurity.com", storage.GetString("hostname"));
        }
    }
}