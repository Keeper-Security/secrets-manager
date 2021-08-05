using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Encodings.Web;

namespace SecretsManager
{
    public class LocalConfigStorage : IKeyValueStorage
    {
        private readonly Dictionary<string, string> strings = new();
        private readonly string fileName;

        public LocalConfigStorage(string configName = null)
        {
            fileName = configName;
            if (fileName == null || !File.Exists(fileName))
                return;
            var bytes = File.ReadAllBytes(fileName);
            var reader = new Utf8JsonReader(bytes);
            string propertyName = null;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        propertyName = reader.GetString();
                        break;
                    case JsonTokenType.String:
                        if (propertyName != null)
                        {
                            strings[propertyName] = reader.GetString();
                        }

                        break;
                }
            }
        }

        private void SaveToFile()
        {
            if (fileName == null)
            {
                return;
            }

            using var stream = File.Create(fileName);
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Indented = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
            writer.WriteStartObject();
            foreach (var kv in strings)
            {
                writer.WriteString(kv.Key, kv.Value);
            }

            writer.WriteEndObject();
            writer.Flush();
        }

        public string GetString(string key)
        {
            return strings.TryGetValue(key, out var result) ? result : null;
        }

        public void SaveString(string key, string value)
        {
            strings[key] = value;
            SaveToFile();
        }

        public byte[] GetBytes(string key)
        {
            var stringValue = strings.TryGetValue(key, out var result) ? result : null;
            return stringValue == null ? null : CryptoUtils.Base64ToBytes(stringValue);
        }

        public void SaveBytes(string key, byte[] value)
        {
            SaveString(key, CryptoUtils.BytesToBase64(value));
        }

        public void Delete(string key)
        {
            strings.Remove(key);
            SaveToFile();
        }
    }

    public class CacheStorage
    {
        public static void SaveCachedValue(byte[] data)
        {
            File.WriteAllBytes("cache.dat", data);
        }

        public static byte[] GetCachedValue()
        {
            return File.ReadAllBytes("cache.dat");
        }
    }
}