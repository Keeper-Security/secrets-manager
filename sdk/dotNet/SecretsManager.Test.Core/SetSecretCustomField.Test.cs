using NUnit.Framework;
using SecretManagement.Keeper;
using System.Text.Json;

namespace SecretsManager.Test
{
    public class SetSecretCustomFieldTests
    {
        [Test]
        public void FindRecordField_FindsCustomFieldByLabel()
        {
            var data = new KeeperRecordData
            {
                title = "Record",
                type = "login",
                fields = new[]
                {
                    new KeeperRecordField { type = "password", value = new object[] { JsonSerializer.SerializeToElement("secret") } }
                },
                custom = new[]
                {
                    new KeeperRecordField { type = "text", label = "API Key", value = new object[] { JsonSerializer.SerializeToElement("old") } }
                }
            };

            var field = Client.FindRecordField(data, "API Key");

            Assert.That(field, Is.Not.Null);
            Assert.That(field.value[0].ToString(), Is.EqualTo("old"));
        }

        [Test]
        public void FindRecordField_MatchesStandardFieldWithEmptyLabel()
        {
            var data = new KeeperRecordData
            {
                title = "Record",
                type = "login",
                fields = new[]
                {
                    new KeeperRecordField { type = "password", label = "", value = new object[] { JsonSerializer.SerializeToElement("secret") } }
                },
                custom = new KeeperRecordField[0]
            };

            var field = Client.FindRecordField(data, "password");

            Assert.That(field, Is.Not.Null);
        }

        [Test]
        public void FindSettableField_ReturnsNullWhenFieldHasNoValue()
        {
            var data = new KeeperRecordData
            {
                title = "Record",
                type = "login",
                fields = new[]
                {
                    new KeeperRecordField { type = "url", value = new object[0] }
                },
                custom = new KeeperRecordField[0]
            };

            Assert.That(Client.FindSettableField(data, "url"), Is.Null);
        }
    }
}
