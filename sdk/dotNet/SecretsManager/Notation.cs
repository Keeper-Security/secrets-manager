using System;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecretsManager
{
    public static class Notation
    {
        public static string GetValue(KeeperSecrets secrets, string notation)
        {
            var query = notation;
            var schemaNotation = query.Split(new[] { "://" }, StringSplitOptions.None);
            if (schemaNotation.Length > 1)
            {
                if (schemaNotation[0] != "keeper")
                {
                    throw new Exception($"Invalid notation schema: {schemaNotation[0]}");
                }

                query = query.Substring(9);
            }

            var queryParts = query.Split('/');
            if (queryParts.Length < 3)
            {
                throw new Exception($"Invalid notation {notation}");
            }

            var record = secrets.Records.FirstOrDefault(x => x.RecordUid == queryParts[0]);
            if (record == null)
            {
                throw new Exception($"Record {queryParts[0]} not found");
            }

            var fields = queryParts[1] switch
            {
                "field" => record.Data.fields,
                "custom_field" => record.Data.custom,
                _ => throw new Exception($"Expected /field or /custom_field but found /{queryParts[1]}")
            };

            KeeperRecordField FindField(string fieldName)
            {
                var field = fields.FirstOrDefault(x => x.label == fieldName || x.type == fieldName);
                if (field == null)
                {
                    throw new Exception($"Field {fieldName} not found in the record {record.RecordUid}");
                }

                return field;
            }

            KeeperRecordField field;
            if (queryParts[2].EndsWith("[]"))
            {
                field = FindField(queryParts[2].Substring(0, queryParts[2].Length - 2));
                return CryptoUtils.BytesToString(JsonUtils.SerializeJson(field.value));
            }

            var fieldParts = new Regex(@"[\[\]]")
                .Replace(queryParts[2], "/")
                .Split('/')
                .Where(x => x.Length > 0)
                .ToArray();

            field = FindField(fieldParts[0]);

            if (fieldParts.Length == 1)
            {
                return field.value[0].ToString();
            }

            var fieldHasIndex = int.TryParse(fieldParts[1], out var fieldValueIdx);
            if (!fieldHasIndex)
            {
                return ((JsonElement)field.value[0]).GetProperty(fieldParts[1]).ToString();
            }

            if (fieldValueIdx < 0 || fieldValueIdx >= field.value.Length)
            {
                throw new Exception($"The index {fieldValueIdx} for field value of ${fieldParts[0]} in the record {record.RecordUid} is out of range (${field.value.Length - 1})");
            }

            return fieldParts.Length == 2
                ? field.value[fieldValueIdx].ToString()
                : ((JsonElement)field.value[fieldValueIdx]).GetProperty(fieldParts[2]).ToString();
        }
    }
}