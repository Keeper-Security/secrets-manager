using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretsManager
{
    public static class JsonUtils
    {
        private static readonly JsonSerializerOptions Options = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        public static T ParseJson<T>(byte[] json)
        {
            return JsonSerializer.Deserialize<T>(json);
        }

        public static byte[] SerializeJson<T>(T obj)
        {
            return CryptoUtils.StringToBytes(JsonSerializer.Serialize(obj, Options));
        }
    }
}