using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace SecretsManager
{
    public static class JsonUtils
    {
        private static readonly DataContractJsonSerializerSettings JsonSettings = new DataContractJsonSerializerSettings
        {
            UseSimpleDictionaryFormat = true,
            EmitTypeInformation = EmitTypeInformation.Never
        };

        public static T ParseJson<T>(byte[] json)
        {
            var serializer = new DataContractJsonSerializer(typeof(T), JsonSettings);
            using (var ms = new MemoryStream(json))
            {
                return (T) serializer.ReadObject(ms);
            }
        }

        public static byte[] SerializeJson<T>(T obj)
        {
            var serializer = new DataContractJsonSerializer(typeof(T), JsonSettings);
            using (var ms = new MemoryStream())
            {
                using (var writer = JsonReaderWriterFactory.CreateJsonWriter(ms, Encoding.UTF8, false, true))
                {
                    serializer.WriteObject(writer, obj);
                }
                return ms.ToArray();
            }
        }
    }
}