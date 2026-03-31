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
        public void DefaultCustomField_ShouldSerializeAsEmptyArray()
        {
            // KSM-822: RecordCreate with no custom fields must include "custom":[] in JSON payload
            var recordData = new KeeperRecordData
            {
                title = "Test Record",
                type = "login",
                fields = new KeeperRecordField[]
                {
                    new KeeperRecordField { type = "login", value = new object[] { "user@example.com" } }
                }
                // custom is intentionally NOT set — this is the bug scenario
            };

            var json = CryptoUtils.BytesToString(JsonUtils.SerializeJson(recordData));

            Assert.That(json, Does.Contain("\"custom\":[]"),
                "KSM-822: Serialized payload must include 'custom':[] even when custom is not explicitly set");
        }

        [Test]
        public void DefaultCustomField_ShouldNotBeNull()
        {
            // KSM-822: custom must default to empty array, not null
            var recordData = new KeeperRecordData();
            Assert.That(recordData.custom, Is.Not.Null);
            Assert.That(recordData.custom, Is.Empty);
        }

        [Test]
        public void DefaultCustomField_RoundTrip_ShouldPreserveEmptyArray()
        {
            // KSM-822: Round-trip serialization must preserve empty custom array
            var recordData = new KeeperRecordData
            {
                title = "Round Trip Test",
                type = "login",
                fields = new KeeperRecordField[] { }
            };

            var jsonBytes = JsonUtils.SerializeJson(recordData);
            var deserialized = JsonUtils.ParseJson<KeeperRecordData>(jsonBytes);

            Assert.That(deserialized.custom, Is.Not.Null);
            Assert.That(deserialized.custom, Is.Empty);
        }

        [Test]
        public void ParseAndSerializeShouldPreserveDiacritics()
        {
            string recordTitle = "MySp�ci�lHom�L�gin";
            var krdin = new KeeperRecordData { title = recordTitle, type = "login" };
            var krdout = JsonUtils.ParseJson<KeeperRecordData>(JsonUtils.SerializeJson(krdin));
            Assert.That(krdin.title, Is.EqualTo(krdout.title));
        }
    }
}
