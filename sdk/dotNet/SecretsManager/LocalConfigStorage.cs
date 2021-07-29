using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SecretsManager
{
    public class LocalConfigStorage: IKeyValueStorage
    {
        private readonly Dictionary<string, string> strings = new();
        private readonly string fileName;

        public LocalConfigStorage(string configName = null)
        {
            fileName = configName;
            if (configName != null && File.Exists(configName))
            {
                var lines = File.ReadAllLines(configName);
                foreach (var line in lines)
                {
                    var kv = line.Split(new[] {": "}, StringSplitOptions.None);
                    strings[kv[0]] = kv[1];
                }
            }
        }

        private void SaveToFile()
        {
            if (fileName == null)
            {
                return;
            }

            var lines = strings.Select(x => $"{x.Key}: {x.Value}");
            File.WriteAllLines(fileName, lines);
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
}