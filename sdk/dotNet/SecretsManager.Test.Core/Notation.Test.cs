using NUnit.Framework;
using System;

namespace SecretsManager.Test
{
    public class NotationTests
    {
        private const string RecordUid = "k9qMpcO0aszz9w3li5XbaQ";
        private const string testRecordDataJson =
            "{\"title\":\"My Record 1\",\"type\":\"login\",\"fields\":[{\"type\":\"login\",\"value\":[\"My Login 1\"]},{\"type\":\"password\",\"value\":[\"My Password 1\"]}],\"custom\":[{\"type\":\"text\",\"label\":\"My Custom 1\",\"value\":[\"custom1\"]},{\"type\":\"text\",\"label\":\"My Custom 1\",\"value\":[\"custom1\"]},{\"type\":\"text\",\"label\":\"My Custom 2\",\"value\":[\"one\",\"two\",\"three\"]},{\"type\":\"phone\",\"label\":\"phone\",\"value\":[{\"number\":\"555-5555555\",\"ext\":\"55\"},{\"number\":\"777-7777777\",\"ext\":\"77\"},{\"number\":\"888-8888888\",\"ext\":\"\",\"type\":\"Home\"},{\"number\":\"999-9999999\",\"type\":\"Work\"}]},{\"type\":\"name\",\"label\":\"name\",\"value\":[{\"first\":\"Jenny\",\"middle\":\"X\",\"last\":\"Smith\"}]}]}";

        [Test]
        public void NotationsWork()
        {
            var recordData = JsonUtils.ParseJson<KeeperRecordData>(CryptoUtils.StringToBytes(testRecordDataJson));
            var secrets = new KeeperSecrets(null, null, new[]
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

        [Test]
        public void NotationParserWork()
        {
            try
            {
                Notation.ParseNotation("/file"); // file requires parameters
                Assert.Fail("Parsing bad notation did not throw");
            }
            catch (Exception) { }

            try
            {
                Notation.ParseNotation("/type/extra"); // extra characters after last section
                Assert.Fail("Parsing bad notation did not throw");
            }
            catch (Exception) { }

            var res = Notation.ParseNotation("/type");
            Assert.AreEqual("type", res[2].Text.Item1);

            res = Notation.ParseNotation("/title");
            Assert.AreEqual("title", res[2].Text.Item1);

            res = Notation.ParseNotation("/notes");
            Assert.AreEqual("notes", res[2].Text.Item1);

            res = Notation.ParseNotation("/file/filename.ext");
            Assert.AreEqual("file", res[2].Text.Item1);
            Assert.AreEqual("filename.ext", res[2].Parameter.Item1);

            res = Notation.ParseNotation("/field/text");
            Assert.AreEqual("field", res[2].Text.Item1);
            Assert.AreEqual("text", res[2].Parameter.Item1);

            res = Notation.ParseNotation(@"/custom_field/label with \[[0][middle]");
            Assert.AreEqual("", res[1].Text.Item1); // empty title
            Assert.AreEqual("custom_field", res[2].Text.Item1);
            Assert.AreEqual(@"label with [", res[2].Parameter.Item1);
            Assert.AreEqual("0", res[2].Index1.Item1);
            Assert.AreEqual("middle", res[2].Index2.Item1);

            res = Notation.ParseNotation(@"title with \[\]\//custom_field/label with \[[0][middle]");
            Assert.AreEqual(@"title with []/", res[1].Text.Item1);
            Assert.AreEqual("custom_field", res[2].Text.Item1);
            Assert.AreEqual(@"label with [", res[2].Parameter.Item1);
            Assert.AreEqual("0", res[2].Index1.Item1);
            Assert.AreEqual("middle", res[2].Index2.Item1);
        }
    }
}
