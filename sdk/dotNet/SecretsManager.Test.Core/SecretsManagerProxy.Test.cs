using NUnit.Framework;
using System;
using System.Threading.Tasks;
using System.IO;

namespace SecretsManager.Test
{
    public class SecretsManagerProxyTests
    {
        [Test]
        public async Task PostFunction_UsesProxyUrl_WhenProvided()
        {
            var storage = new InMemoryStorage();
            var proxyUrl = "http://localhost:8888";

            var fileBytes = await File.ReadAllBytesAsync("../../../../../fake_data.json");
            var testResponses = JsonUtils.ParseJson<TestResponse[]>(fileBytes);
            var responseNo = 0;
            SecretsManagerClient.TransmissionKeyStub = _ => CryptoUtils.Base64ToBytes(testResponses[responseNo].transmissionKey);
            string usedProxyUrl = null;

            Task<KeeperHttpResponse> TestPostFunction(string s, TransmissionKey transmissionKey, EncryptedPayload encryptedPayload, string proxyUrl = null)
            {
                var response = testResponses[responseNo++];
                usedProxyUrl = proxyUrl;
                return Task.FromResult(new KeeperHttpResponse(CryptoUtils.Base64ToBytes(response.data), response.statusCode != 200));
            }

            var fakeOneTimeCode = "YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c";

            SecretsManagerClient.InitializeStorage(storage, fakeOneTimeCode, "fake.keepersecurity.com");

            var options = new SecretsManagerOptions(storage, TestPostFunction, proxyUrl: proxyUrl);
            var secrets = await SecretsManagerClient.GetSecrets(options);
            
            Assert.That(usedProxyUrl, Is.EqualTo(proxyUrl));
        }
    }
}
