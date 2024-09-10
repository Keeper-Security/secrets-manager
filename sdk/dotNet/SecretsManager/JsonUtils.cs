using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretsManager
{
    public static class JsonUtils
    {
        private static readonly JsonSerializerOptions Options = new()
        {
            //Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping, // bad for strings with diacritics
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault
        };

        public static T ParseJson<T>(byte[] json)
        {
            return JsonSerializer.Deserialize<T>(json, Options);
        }

        public static byte[] SerializeJson<T>(T obj)
        {
            return CryptoUtils.StringToBytes(JsonSerializer.Serialize(obj, Options));
        }
    }
}
