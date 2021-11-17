using NUnit.Framework;

namespace SecretsManager.Test
{
    public class JsonUtilsTests
    {
        [Test]
        public void ParseAndSerializeShouldNotChangeTheData()
        {
            const string jsonIn = "{\"title\":\"MyHomeLogin\",\"type\":\"Login2\",\"fields\":[{\"type\":\"login\",\"label\":\"Login\",\"value\":[\"Login 1\"],\"required\":true,\"privacyScreen\":true},{\"type\":\"password\",\"label\":\"Password\",\"value\":[\"3[OJ%sc7n].wX6+k5GY)6\"],\"required\":true,\"privacyScreen\":true,\"enforceGeneration\":true,\"complexity\":{\"length\":21,\"caps\":5,\"lowercase\":5,\"digits\":5,\"special\":5}},{\"type\":\"url\",\"label\":\"URL\",\"value\":[\"https://asdfjkasdfkdsa.com\"],\"required\":true,\"privacyScreen\":true},{\"type\":\"securityQuestion\",\"label\":\"Security Question & Answer\",\"value\":[{\"question\":\"asdf\",\"answer\":\"asdf\"}],\"required\":true,\"privacyScreen\":true},{\"type\":\"fileRef\",\"label\":\"File or Photo\",\"value\":[]},{\"type\":\"oneTimeCode\",\"label\":\"Two-Factor Code\",\"value\":[]}],\"custom\":[]}";
            var recordData = JsonUtils.ParseJson<KeeperRecordData>(CryptoUtils.StringToBytes(jsonIn));
            var jsonOut = CryptoUtils.BytesToString(JsonUtils.SerializeJson(recordData));
            Assert.AreEqual(jsonIn, jsonOut);
        }
    }
}