using NUnit.Framework;

namespace SecretsManager.Test
{
    public class JsonUtilsTests
    {
        [Test]
        public void ParseAndSerializeShouldNotChangeTheData()
        {
            var rec = new KeeperRecordData
            {
                type = "Login2",
                title = "MyHomeLogin",
                notes = "MyNotes",
                fields = new KeeperRecordField[] {
                    new KeeperRecordField { type = "login", label = "Login", value = new string[] { "Login 1" }, required=true, privacyScreen=true },
                    new KeeperRecordField { type = "password", label = "Password", value = new string[] { "3[OJ%sc7n].wX6+k5GY)6" }, required=true, privacyScreen=true, enforceGeneration=true, complexity=new PasswordComplexity{ length=21, caps=5, lowercase=5, digits=5, special=5}  },
                    new KeeperRecordField { type = "url", label = "URL", value = new string[] { "https://asdfjkasdfkdsa.com" }, required=true, privacyScreen=true },
                    new KeeperRecordField { type = "securityQuestion", label = "Security Question & Answer", value = new SecurityQuestion[] { new SecurityQuestion { question= "asdf", answer= "asdf" } }, required=true, privacyScreen=true },
                    new KeeperRecordField { type = "fileRef", label = "File or Photo", value = new object[] { } },
                    new KeeperRecordField { type = "oneTimeCode", label = "Two-Factor Code", value = new object[] { } },
                },
                custom = new KeeperRecordField[] { }
            };
            var jsonIn = CryptoUtils.BytesToString(JsonUtils.SerializeJson(rec));
            //const string jsonIn = "{\"title\":\"MyHomeLogin\",\"type\":\"Login2\",\"fields\":[{\"type\":\"login\",\"label\":\"Login\",\"value\":[\"Login 1\"],\"required\":true,\"privacyScreen\":true},{\"type\":\"password\",\"label\":\"Password\",\"value\":[\"3[OJ%sc7n].wX6+k5GY)6\"],\"required\":true,\"privacyScreen\":true,\"enforceGeneration\":true,\"complexity\":{\"length\":21,\"caps\":5,\"lowercase\":5,\"digits\":5,\"special\":5}},{\"type\":\"url\",\"label\":\"URL\",\"value\":[\"https://asdfjkasdfkdsa.com\"],\"required\":true,\"privacyScreen\":true},{\"type\":\"securityQuestion\",\"label\":\"Security Question & Answer\",\"value\":[{\"question\":\"asdf\",\"answer\":\"asdf\"}],\"required\":true,\"privacyScreen\":true},{\"type\":\"fileRef\",\"label\":\"File or Photo\",\"value\":[]},{\"type\":\"oneTimeCode\",\"label\":\"Two-Factor Code\",\"value\":[]}],\"custom\":[],\"notes\":\"MyNotes\"}";
            var recordData = JsonUtils.ParseJson<KeeperRecordData>(CryptoUtils.StringToBytes(jsonIn));
            var jsonOut = CryptoUtils.BytesToString(JsonUtils.SerializeJson(recordData));
            Assert.That(jsonIn, Is.EqualTo(jsonOut));
            Assert.That(recordData.fields[1].value[0].ToString(), Is.EqualTo(rec.fields[1].value[0]));
        }
        [Test]
        public void ParseAndSerializeShouldPreserveDiacritics()
        {
            string recordTitle = "MySpéciàlHomèL°gin";
            var krdin = new KeeperRecordData { title = recordTitle, type = "login" };
            var krdout = JsonUtils.ParseJson<KeeperRecordData>(JsonUtils.SerializeJson(krdin));
            Assert.That(krdin.title, Is.EqualTo(krdout.title));
        }
    }
}
