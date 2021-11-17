using NUnit.Framework;
using System;

namespace SecretsManager.Test
{
    public class NotationTests
    {
        private const string RecordUid = "k9qMpcO0aszz9w3li5XbaQ";

        [Test]
        public void NotationsWork()
        {
            const string testRecordDataJson =
                "{\"title\":\"My Record 1\",\"type\":\"login\",\"fields\":[{\"type\":\"login\",\"value\":[\"My Login 1\"]},{\"type\":\"password\",\"value\":[\"My Password 1\"]}],\"custom\":[{\"type\":\"text\",\"label\":\"My Custom 1\",\"value\":[\"custom1\"]},{\"type\":\"text\",\"label\":\"My Custom 1\",\"value\":[\"custom1\"]},{\"type\":\"text\",\"label\":\"My Custom 2\",\"value\":[\"one\",\"two\",\"three\"]},{\"type\":\"phone\",\"label\":\"phone\",\"value\":[{\"number\":\"555-5555555\",\"ext\":\"55\"},{\"number\":\"777-7777777\",\"ext\":\"77\"},{\"number\":\"888-8888888\",\"ext\":\"\",\"type\":\"Home\"},{\"number\":\"999-9999999\",\"type\":\"Work\"}]},{\"type\":\"name\",\"label\":\"name\",\"value\":[{\"first\":\"Jenny\",\"middle\":\"X\",\"last\":\"Smith\"}]}]}";
            var recordData = JsonUtils.ParseJson<KeeperRecordData>(CryptoUtils.StringToBytes(testRecordDataJson));
            var secrets = new KeeperSecrets(new[]
            {
                new KeeperRecord(null, RecordUid, null, null, recordData, 0, null)
            });

            var value = Notation.GetValue(secrets, $"keeper://{RecordUid}/field/login");
            Assert.AreEqual("My Login 1", value);

            value = Notation.GetValue(secrets, $"{RecordUid}/field/login");
            Assert.AreEqual("My Login 1", value);

            value = Notation.GetValue(secrets, $"keeper://{RecordUid}/field/login[0]");
            Assert.AreEqual("My Login 1", value);

            try
            {
                Notation.GetValue(secrets, $"keeper://{RecordUid}/field/login[1]");
                Assert.Fail("Getting wrong index did not throw");
            }
            catch (Exception)
            {
                // ignored
            }

            value = Notation.GetValue(secrets, $"keeper://{RecordUid}/field/login[]");
            Assert.AreEqual("[\"My Login 1\"]", value);

            value = Notation.GetValue(secrets, $"keeper://{RecordUid}/custom_field/My Custom 1");
            Assert.AreEqual("custom1", value);

            value = Notation.GetValue(secrets, $"keeper://{RecordUid}/custom_field/My Custom 2");
            Assert.AreEqual("one", value);

            value = Notation.GetValue(secrets, $"keeper://{RecordUid}/custom_field/My Custom 2[1]");
            Assert.AreEqual("two", value);

            value = Notation.GetValue(secrets, $"keeper://{RecordUid}/custom_field/My Custom 2[]");
            Assert.AreEqual("[\"one\",\"two\",\"three\"]", value);

            value = Notation.GetValue(secrets, $"keeper://{RecordUid}/custom_field/phone[0][number]");
            Assert.AreEqual("555-5555555", value);

            value = Notation.GetValue(secrets, $"keeper://{RecordUid}/custom_field/phone[1][number]");
            Assert.AreEqual("777-7777777", value);

            value = Notation.GetValue(secrets, $"keeper://{RecordUid}/custom_field/phone[2]");
            Assert.AreEqual("{\"number\":\"888-8888888\",\"ext\":\"\",\"type\":\"Home\"}", value);

            value = Notation.GetValue(secrets, $"keeper://{RecordUid}/custom_field/name[first]");
            Assert.AreEqual("Jenny", value);

            value = Notation.GetValue(secrets, $"keeper://{RecordUid}/custom_field/name[last]");
            Assert.AreEqual("Smith", value);
        }
    }
}