using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Encodings.Web;

namespace SecretsManager
{
    public class InMemoryStorage : IKeyValueStorage
    {
        internal readonly Dictionary<string, string> Strings = new();

        public InMemoryStorage(string configJson = null)
        {
            if (configJson == null)
                return;
            var bytes = CryptoUtils.StringToBytes(configJson);
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
                            Strings[propertyName] = reader.GetString();
                        }

                        break;
                }
            }
        }

        public string GetString(string key)
        {
            return Strings.TryGetValue(key, out var result) ? result : null;
        }

        public void SaveString(string key, string value)
        {
            Strings[key] = value;
        }

        public byte[] GetBytes(string key)
        {
            var stringValue = Strings.TryGetValue(key, out var result) ? result : null;
            return stringValue == null ? null : CryptoUtils.Base64ToBytes(stringValue);
        }

        public void SaveBytes(string key, byte[] value)
        {
            Strings[key] = CryptoUtils.BytesToBase64(value);
        }

        public void Delete(string key)
        {
            Strings.Remove(key);
        }
    }

    public class LocalConfigStorage : IKeyValueStorage
    {
        private readonly InMemoryStorage storage;
        private readonly string fileName;

        public LocalConfigStorage(string configName = null)
        {
            fileName = configName;
            if (fileName == null || !File.Exists(fileName))
            {
                storage = new InMemoryStorage();
                return;
            }
            var json = File.ReadAllText(fileName);
            storage = new InMemoryStorage(json);
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
            foreach (var kv in storage.Strings)
            {
                writer.WriteString(kv.Key, kv.Value);
            }

            writer.WriteEndObject();
            writer.Flush();
        }

        public string GetString(string key)
        {
            return storage.GetString(key);
        }

        public void SaveString(string key, string value)
        {
            storage.SaveString(key, value);
            SaveToFile();
        }

        public byte[] GetBytes(string key)
        {
            return storage.GetBytes(key);
        }

        public void SaveBytes(string key, byte[] value)
        {
            storage.SaveBytes(key, value);
            SaveToFile();
        }

        public void Delete(string key)
        {
            storage.Delete(key);
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