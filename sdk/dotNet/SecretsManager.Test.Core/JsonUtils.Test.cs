using NUnit.Framework;

namespace SecretsManager.Test
{
    public class Tests
    {
        [Test]
        public void ParseAndSerializeShouldNotChangeTheData()
        {
            const string jsonIn = "{\"title\":\"RF12\",\"type\":\"login\",\"fields\":[{\"type\":\"login\",\"value\":[]},{\"type\":\"password\",\"value\":[\"]O6S0x!W;13}!XER9+IO\"]},{\"type\":\"url\",\"label\":\"Url\",\"value\":[\"https://cnn.com\"]},{\"type\":\"fileRef\",\"value\":[]},{\"type\":\"oneTimeCode\",\"value\":[\"otpauth://totp/Codeship:charles.brown@foo.com?secret=d7j6snxdu6d56bru&issuer=Codeship\"]}],\"custom\":[{\"type\":\"date\",\"label\":\"Birthday\",\"value\":[1626978427384]},{\"type\":\"cardRef\",\"label\":\"Payments\",\"value\":[\"SONdHjxl_nIFyZXrFg8sOg\"]},{\"type\":\"text\",\"label\":\"Free\",\"value\":[\"abcd\"]},{\"type\":\"securityQuestion\",\"label\":\"Q&A\",\"value\":[{\"question\":\"Question\",\"answer\":\"Answer\"}]},{\"type\":\"multiline\",\"label\":\"Multi-line\",\"value\":[\"line1\\nline2\\nline3\"]},{\"type\":\"email\",\"label\":\"E-mail\",\"value\":[\"charles@gmail.com\"]},{\"type\":\"name\",\"label\":\"Friend\",\"value\":[{\"first\":\"Charles\",\"middle\":\"Robert\",\"last\":\"Brown\"}]},{\"type\":\"addressRef\",\"label\":\"My Address\",\"value\":[\"jk1AXCSzXLETVqrsaTmOQQ\"]},{\"type\":\"pinCode\",\"label\":\"Pin Code!\",\"value\":[\"123123\"]},{\"type\":\"phone\",\"value\":[{\"number\":\"111-1111111\",\"ext\":\"23\",\"type\":\"Home\",\"region\":\"GB\"}]},{\"type\":\"secret\",\"label\":\"Hidden Field !\",\"value\":[\"dfhkjsefj\"]}],\"notes\":\"Notes\"}";
            var recordData = JsonUtils.ParseJson<KeeperRecordData>(CryptoUtils.StringToBytes(jsonIn));
            var jsonOut = CryptoUtils.BytesToString(JsonUtils.SerializeJson(recordData));
            Assert.AreEqual(jsonIn, jsonOut);
        }
    }
}