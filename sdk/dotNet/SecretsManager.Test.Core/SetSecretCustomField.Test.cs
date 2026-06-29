using NUnit.Framework;
using SecretManagement.Keeper;
using SecretsManager;
using System.Text.Json;

namespace SecretsManager.Test
{
    [TestFixture]
    public class SetSecretCustomFieldTests
    {
        private static KeeperRecordField Field(string type, string label, params object[] values)
        {
            return new KeeperRecordField { type = type, label = label, value = values };
        }

        [Test]
        public void FindRecordField_FindsCustomFieldForSetSecret()
        {
            var data = new KeeperRecordData
            {
                title = "TestSecretsManagerEditFeature",
                type = "login",
                fields = new[] { Field("password", "password", JsonSerializer.SerializeToElement("secret")) },
                custom = new[] { Field("text", "API Key", JsonSerializer.SerializeToElement("sk-old-key-123")) }
            };

            var field = Client.FindRecordField(data, "API Key");

            Assert.That(field, Is.Not.Null);
            Assert.That(field.value[0].ToString(), Is.EqualTo("sk-old-key-123"));
        }

        [Test]
        public void TryPrepareFieldUpdate_StringField_AcceptsString()
        {
            var field = Field("text", "API Key", JsonSerializer.SerializeToElement("old"));
            Assert.That(Client.TryPrepareFieldUpdate(field, "new", out var prepared, out _), Is.True);
            Assert.That(prepared, Is.EqualTo("new"));
        }

        [Test]
        public void TryPrepareFieldUpdate_DateField_AcceptsLongTimestamp()
        {
            var field = Field("date", null, JsonSerializer.SerializeToElement(1014402600000L));
            Assert.That(Client.TryPrepareFieldUpdate(field, 1014402600001L, out var prepared, out _), Is.True);
            Assert.That(prepared, Is.EqualTo(1014402600001L));
        }

        [Test]
        public void TryPrepareFieldUpdate_PhoneField_AcceptsJsonObject()
        {
            var field = Field("phone", "Phone",
                JsonSerializer.SerializeToElement(new { region = "IN", number = "1223455555" }));

            const string updatedJson = "{\"region\":\"IN\",\"number\":\"9999999999\"}";
            Assert.That(Client.TryPrepareFieldUpdate(field, updatedJson, out var prepared, out _), Is.True);
            Assert.That(((JsonElement)prepared).GetProperty("number").GetString(), Is.EqualTo("9999999999"));
        }

        [Test]
        public void TryPrepareFieldUpdate_SecurityQuestion_AcceptsJsonObject()
        {
            var field = Field("securityQuestion", null,
                JsonSerializer.SerializeToElement(new { question = "why", answer = "due to this" }));

            const string updatedJson = "{\"question\":\"why updated\",\"answer\":\"new answer\"}";
            Assert.That(Client.TryPrepareFieldUpdate(field, updatedJson, out var prepared, out _), Is.True);
            Assert.That(((JsonElement)prepared).GetProperty("answer").GetString(), Is.EqualTo("new answer"));
        }
    }
}
