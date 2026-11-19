using NUnit.Framework;

namespace SecretsManager.Test
{
    public class PamSettingsConnectionTests
    {
        // Parsing into KeeperRecordField keeps pamSettings as raw JSON and never lost the value.
        // Only the typed classes dropped unknown properties, so the test goes through them.
        [Test]
        public void DbConnectionMethod_ShouldSurviveTypedRoundTrip()
        {
            const string jsonIn = "{\"connection\":[{\"protocol\":\"mysql\",\"dbConnectionMethod\":\"keeperDB\"}]}";

            var setting = JsonUtils.ParseJson<PamSetting>(CryptoUtils.StringToBytes(jsonIn));
            var jsonOut = CryptoUtils.BytesToString(JsonUtils.SerializeJson(setting));

            Assert.That(jsonOut, Does.Contain("\"dbConnectionMethod\":\"keeperDB\""));
        }
    }
}
