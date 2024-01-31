using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecretsManager
{
    public static class Notation
    {
        public static string GetValue(KeeperSecrets secrets, string notation)
        {
            var parsedNotation = ParseNotation(notation, true); // prefix, record, selector, footer
            if ((parsedNotation?.Count ?? 0) < 3)
                throw new Exception($"Invalid notation {notation}");

            string selector = parsedNotation[2]?.Text?.Item1; // type|title|notes or file|field|custom_field
            if (selector == null)
                throw new Exception($"Invalid notation {notation}");
            string recordToken = parsedNotation[1]?.Text?.Item1; // UID or Title
            if (recordToken == null)
                throw new Exception($"Invalid notation {notation}");
            var record = secrets.Records.FirstOrDefault(x => recordToken.Equals(x?.RecordUid) || recordToken.Equals(x?.Data?.title));
            if (record == null)
                throw new Exception($"Record '{recordToken}' not found");

            string parameter = parsedNotation[2]?.Parameter?.Item1;
            string index1 = parsedNotation[2]?.Index1?.Item1;
            string index2 = parsedNotation[2]?.Index2?.Item1;

            switch (selector.ToLower())
            {
                case "type": return record?.Data?.type ?? "";
                case "title": return record?.Data?.title ?? "";
                case "notes": return record?.Data?.notes ?? "";
                case "file":
                    if (parameter == null)
                        throw new Exception($"Notation error - Missing required parameter: filename or file UID for files in record '{recordToken}'");
                    if ((record?.Files?.Count() ?? 0) < 1)
                        throw new Exception($"Notation error - Record {recordToken} has no file attachments.");
                    var files = record.Files;
                    files = files.Where(x => parameter.Equals(x?.Data?.name) || parameter.Equals(x?.Data?.title) || parameter.Equals(x?.FileUid)).ToArray();
                    // file searches do not use indexes and rely on unique file names or fileUid
                    if ((files?.Length ?? 0) > 1)
                        throw new Exception($"Notation error - Record {recordToken} has multiple files matching the search criteria '{parameter}'");
                    if ((files?.Length ?? 0) < 1)
                        throw new Exception($"Notation error - Record {recordToken} has no files matching the search criteria '{parameter}'");
                    var contents = SecretsManagerClient.DownloadFile(files[0]);
                    var text = CryptoUtils.WebSafe64FromBytes(contents);
                    return text;
                case "field":
                case "custom_field":
                    if (parameter == null)
                        throw new Exception($"Notation error - Missing required parameter for the field (type or label): ex. /field/type or /custom_field/MyLabel");

                    var fields = selector.ToLower() switch
                    {
                        "field" => record.Data.fields,
                        "custom_field" => record.Data.custom,
                        _ => throw new Exception($"Notation error - Expected /field or /custom_field but found /{selector}")
                    };

                    KeeperRecordField FindField(string fieldName)
                    {
                        var field = fields.FirstOrDefault(x => x.label == fieldName || x.type == fieldName);
                        if (field == null)
                            throw new Exception($"Field {fieldName} not found in the record {record.RecordUid}");

                        return field;
                    }
                    var field = FindField(parameter);

                    // /<type|label>[index1][index2], ex. /url == /url[] == /url[][] == full value
                    var isValid = int.TryParse(index1, out int idx);
                    if (!isValid) idx = -1; // full value
                    // valid only if [] or missing - ex. /field/phone or /field/phone[]
                    if (idx == -1 && !(string.IsNullOrEmpty(parsedNotation[2]?.Index1?.Item2) || parsedNotation[2]?.Index1?.Item2 == "[]"))
                        throw new Exception($"Notation error - Invalid field index {idx}.");

                    var values = (field?.value != null ? new List<object>(field.value) : new List<object>());
                    if (idx >= values.Count)
                        throw new Exception($"Notation error - Field index out of bounds {idx} >= {values.Count} for field {parameter}.");
                    if (idx >= 0) // single index
                        values = new List<object> { values[idx] };

                    bool fullObjValue = (string.IsNullOrEmpty(parsedNotation[2]?.Index2?.Item2) || parsedNotation[2]?.Index2?.Item2 == "[]") ? true : false;
                    string objPropertyName = parsedNotation[2]?.Index2?.Item1 ?? "";
                    // legacy compatibility mode - no indexes, ex. /url returns value[0]
                    if (string.IsNullOrEmpty(parsedNotation[2]?.Index1?.Item2) && string.IsNullOrEmpty(parsedNotation[2]?.Index2?.Item2))
                        return field.value[0].ToString();
                    // legacy compatibility mode - empty index, ex. /url[] returns ["value"]
                    if ("[]".Equals(parsedNotation[2]?.Index1?.Item2) && string.IsNullOrEmpty(index2))
                        return CryptoUtils.BytesToString(JsonUtils.SerializeJson(field.value));
                    // legacy compatibility mode - index2 only, ex. /name[first] returns value[0][first]
                    if (string.IsNullOrEmpty(index1) && !string.IsNullOrEmpty(index2))
                        return ((JsonElement)field.value[0]).GetProperty(index2).ToString();
                    if (idx == -1 && fullObjValue)
                        return CryptoUtils.BytesToString(JsonUtils.SerializeJson(field.value));
                    foreach (var fldValue in values)
                    {
                        // legacy compatibility mode - returns only single field value
                        return string.IsNullOrEmpty(index2) ? fldValue.ToString() : ((JsonElement)fldValue).GetProperty(objPropertyName).ToString(); ;
                    }
                    return "";
                default: throw new Exception($"Invalid notation {notation}");
            }
        }

        // data class to represent parsed notation section
        public class NotationSection
        {
            public string Section = null;   // section name - ex. prefix
            public bool IsPresent = false;  // presence flag
            public int StartPos = -1;       // section start position in URI
            public int EndPos = -1;         // section end position in URI
            public Tuple<string, string> Text = null;       // <unescaped, raw> text
            public Tuple<string, string> Parameter = null;  // <field type>|<field label>|<file name>
            public Tuple<string, string> Index1 = null;     // numeric index [N] or []
            public Tuple<string, string> Index2 = null;     // property index - ex. field/name[0][middle]
            public NotationSection(string section)
            {
                Section = section;
            }
        }

        const char EscapeChar = '\\';
        const string EscapeChars = @"/[]\"; // /[]\ -> \/ ,\[, \], \\
        // Escape the characters in plaintext sections only - title, label or filename
        private static Tuple<string, string> ParseSubsection(string text, int pos, string delimiters, bool escaped = false)
        {
            // raw string excludes start delimiter (if '/') but includes end delimiter or both (if '[',']')
            if (string.IsNullOrEmpty(text) || pos < 0 || pos >= text.Length)
                return null;
            if (string.IsNullOrEmpty(delimiters) || delimiters.Length > 2)
                throw new Exception($"Notation parser: Internal error - Incorrect delimiters count. Delimiters: '{delimiters}'");

            string token = "";
            string raw = "";
            while (pos < text.Length)
            {
                if (escaped && EscapeChar == text[pos])
                {
                    // notation cannot end in single char incomplete escape sequence
                    // and only escape_chars should be escaped
                    if (((pos + 1) >= text.Length) || !EscapeChars.Contains(text[pos + 1]))
                        throw new Exception($"Notation parser: Incorrect escape sequence at position {pos}");
                    // copy the properly escaped character
                    token += text[pos + 1];
                    raw += "" + text[pos] + text[pos + 1];
                    pos += 2;
                }
                else // escaped == false || EscapeChar != text[pos]
                {
                    raw += text[pos]; // delimiter is included in raw text
                    if (delimiters.Length == 1)
                    {
                        if (text[pos] == delimiters[0])
                            break;
                        else
                            token += text[pos];
                    }
                    else // 2 delimiters
                    {
                        if (raw[0] != delimiters[0])
                            throw new Exception(@"Notation parser: Index sections must start with '['");
                        if (raw.Length > 1 && text[pos] == delimiters[0])
                            throw new Exception(@"Notation parser: Index sections do not allow extra '[' inside.");
                        if (!delimiters.Contains(text[pos]))
                            token += text[pos];
                        else if (text[pos] == delimiters[1])
                            break;
                    }
                    pos++;
                }
            }
            //pos = (pos < text.Length) ? pos : text.Length - 1;
            if (delimiters.Length == 2 && (
                    (raw.Length < 2 || raw[0] != delimiters[0] || raw[raw.Length - 1] != delimiters[1]) ||
                    (escaped && raw[raw.Length - 2] == EscapeChar)))
                throw new Exception(@"Notation parser: Index sections must be enclosed in '[' and ']'");

            return Tuple.Create(token, raw);
        }

        private static NotationSection ParseSection(string notation, string section, int pos)
        {
            if (string.IsNullOrEmpty(notation))
                throw new Exception($"Keeper notation parsing error - missing notation URI");

            string sectionName = (section ?? "").ToLower();
            var sections = new List<string> { "prefix", "record", "selector", "footer" };
            if (!sections.Contains(sectionName))
                throw new Exception($"Keeper notation parsing error - unknown section: '{sectionName}'");

            var result = new NotationSection(section);
            result.StartPos = pos;

            switch (sectionName)
            {
                case "prefix":
                    // prefix "keeper://" is not mandatory
                    string uriPrefix = "keeper://";
                    if (notation.StartsWith(uriPrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        result.IsPresent = true;
                        result.StartPos = 0;
                        result.EndPos = uriPrefix.Length - 1;
                        result.Text = Tuple.Create(notation.Substring(0, uriPrefix.Length), notation.Substring(0, uriPrefix.Length));
                    }
                    break;
                case "footer":
                    // footer should not be present - used only for verification
                    result.IsPresent = (pos < notation.Length ? true : false);
                    if (result.IsPresent)
                    {
                        result.StartPos = pos;
                        result.EndPos = notation.Length - 1;
                        result.Text = Tuple.Create(notation.Substring(pos), notation.Substring(pos));
                    }
                    break;
                case "record":
                    // record is always present - either UID or title
                    result.IsPresent = (pos < notation.Length ? true : false);
                    if (result.IsPresent)
                    {
                        var parsed = ParseSubsection(notation, pos, "/", true);
                        if (parsed != null)
                        {
                            result.StartPos = pos;
                            result.EndPos = pos + parsed.Item2.Length - 1;
                            result.Text = parsed;
                        }
                    }
                    break;
                case "selector":
                    // selector is always present - type|title|notes | field|custom_field|file
                    result.IsPresent = (pos < notation.Length ? true : false);
                    if (result.IsPresent)
                    {
                        var parsed = ParseSubsection(notation, pos, "/", false);
                        if (parsed != null)
                        {
                            result.StartPos = pos;
                            result.EndPos = pos + parsed.Item2.Length - 1;
                            result.Text = parsed;

                            // selector.parameter - <field type>|<field label> | <file name>
                            // field/name[0][middle], custom_field/my label[0][middle], file/my file[0]
                            var longSelectors = new List<string> { "field", "custom_field", "file" };
                            if (longSelectors.Contains(parsed.Item1.ToLower()))
                            {
                                // TODO: File metadata extraction: ex. filename[1][size] - that requires filename to be escaped
                                parsed = ParseSubsection(notation, result.EndPos + 1, "[", true);
                                if (parsed != null)
                                {
                                    result.Parameter = parsed; // <field type>|<field label> | <filename>
                                    int plen = parsed.Item2.Length - (parsed.Item2.EndsWith("[") && !parsed.Item2.EndsWith(@"\[") ? 1 : 0);
                                    result.EndPos += plen;

                                    parsed = ParseSubsection(notation, result.EndPos + 1, "[]", true);
                                    if (parsed != null)
                                    {
                                        result.Index1 = parsed; // selector.index1 [int] or []
                                        result.EndPos += parsed.Item2.Length;
                                        parsed = ParseSubsection(notation, result.EndPos + 1, "[]", true);
                                        if (parsed != null)
                                        {
                                            result.Index2 = parsed; // selector.index2 [str]
                                            result.EndPos += parsed.Item2.Length;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break;
                default: throw new Exception($"Keeper notation parsing error - unknown section: {sectionName}");
            }

            return result;
        }

        public static List<NotationSection> ParseNotation(string notation, bool legacyMode = false)
        {
            if (string.IsNullOrEmpty(notation))
                throw new Exception("Keeper notation is missing or invalid.");

            // Notation is either plaintext keeper URI format or URL safe base64 string (UTF8)
            // auto detect format - '/' is not part of base64 URL safe alphabet
            if (!notation.Contains('/'))
            {
                try
                {
                    var bytes = CryptoUtils.WebSafe64ToBytes(notation);
                    var plaintext = Encoding.UTF8.GetString(bytes);
                    notation = plaintext;
                }
                catch (Exception) {
                    throw new Exception("Keeper notation is in invalid format - plaintext URI or URL safe base64 string expected.");
                }
            }

            var prefix = ParseSection(notation, "prefix", 0); // keeper://
            int pos = (prefix.IsPresent ? prefix.EndPos + 1 : 0); // prefix is optional
            var record = ParseSection(notation, "record", pos); // <UID> or <Title>
            pos = (record.IsPresent ? record.EndPos + 1 : notation.Length); // record is required
            var selector = ParseSection(notation, "selector", pos); // type|title|notes | field|custom_field|file
            pos = (selector.IsPresent ? selector.EndPos + 1 : notation.Length); // selector is required, indexes are optional
            var footer = ParseSection(notation, "footer", pos); // Any text after the last section

            // verify parsed query
            // prefix is optional, record UID/Title and selector are mandatory
            var shortSelectors = new List<string> { "type", "title", "notes" };
            var fullSelectors = new List<string> { "field", "custom_field", "file" };
            var selectors = new List<string> { "type", "title", "notes", "field", "custom_field", "file" };
            if (!record.IsPresent || !selector.IsPresent)
                throw new Exception("Keeper notation URI missing information about the uid, file, field type, or field key.");
            if (footer.IsPresent)
                throw new Exception("Keeper notation is invalid - extra characters after last section.");
            if (!selectors.Contains(selector?.Text?.Item1?.ToLower() ?? ""))
                throw new Exception("Keeper notation is invalid - bad selector, must be one of (type, title, notes, field, custom_field, file).");
            if (shortSelectors.Contains(selector?.Text?.Item1?.ToLower() ?? "") && selector?.Parameter != null)
                throw new Exception("Keeper notation is invalid - selectors (type, title, notes) do not have parameters.");
            if (fullSelectors.Contains(selector?.Text?.Item1?.ToLower() ?? ""))
            {
                if (selector?.Parameter == null)
                    throw new Exception("Keeper notation is invalid - selectors (field, custom_field, file) require parameters.");
                if ("file" == (selector?.Text?.Item1?.ToLower() ?? "") && (selector?.Index1 != null || selector?.Index2 != null))
                    throw new Exception("Keeper notation is invalid - file selectors don't accept indexes.");
                if ("file" != (selector?.Text?.Item1?.ToLower() ?? "") && selector?.Index1 == null && selector?.Index2 != null)
                    throw new Exception("Keeper notation is invalid - two indexes required.");
                if (selector?.Index1 != null && !Regex.IsMatch(selector?.Index1?.Item2 ?? "", @"^\[\d*\]$"))
                {
                    if (!legacyMode)
                        throw new Exception("Keeper notation is invalid - first index must be numeric: [n] or [].");
                    if (selector?.Index2 == null)
                    {   // in legacy mode convert /name[middle] to name[][middle]
                        selector.Index2 = selector.Index1;
                        selector.Index1 = Tuple.Create("", "[]");
                    }
                }
            }

            return new List<NotationSection> { prefix, record, selector, footer };
        }
    }
}
