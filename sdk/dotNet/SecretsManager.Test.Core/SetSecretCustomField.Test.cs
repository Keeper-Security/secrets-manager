using NUnit.Framework;
using SecretManagement.Keeper;
using SecretsManager;
using System.Text.Json;

namespace SecretsManager.Test
{
    [TestFixture]
    public class SetSecretCustomFieldTests
    {
        [Test]
        public void FindRecordField_FindsCustomFieldForSetSecret()
        {
            var data = new KeeperRecordData
            {
                title = "TestSecretsManagerEditFeature",
                type = "login",
                fields = new[]
                {
                    new KeeperRecordField
                    {
                        type = "password",
                        label = "password",
                        value = new object[] { JsonSerializer.SerializeToElement("secret") }
                    }
                },
                custom = new[]
                {
                    new KeeperRecordField
                    {
                        type = "text",
                        label = "API Key",
                        value = new object[] { JsonSerializer.SerializeToElement("sk-old-key-123") }
                    }
                }
            };

            var field = Client.FindRecordField(data, "API Key");

            Assert.That(field, Is.Not.Null);
            Assert.That(field.value[0].ToString(), Is.EqualTo("sk-old-key-123"));
        }
    }
}
