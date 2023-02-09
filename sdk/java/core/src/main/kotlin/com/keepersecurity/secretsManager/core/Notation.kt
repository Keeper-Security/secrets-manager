@file:JvmName("Notation")

package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.reflect.full.memberProperties

@Deprecated(message = "Use getNotationResults instead.")
@ExperimentalSerializationApi
fun getValue(secrets: KeeperSecrets, notation: String): String {
    val parsedNotation = parseNotation(notation, true) // prefix, record, selector, footer
    if (parsedNotation.size < 3) {
        throw Exception("Invalid notation $notation")
    }

    val selector = parsedNotation[2].text?.first ?: // type|title|notes or file|field|custom_field
        throw Exception("Invalid notation $notation")
    val recordToken = parsedNotation[1].text?.first ?: // UID or Title
        throw Exception("Invalid notation $notation")
    val record = secrets.records.find { (it.recordUid == recordToken) || (it.data.title == recordToken) } ?:
        throw Exception("Record '$recordToken' not found")

    val parameter = parsedNotation[2].parameter?.first
    val index1 = parsedNotation[2].index1?.first
    val index2 = parsedNotation[2].index2?.first

    when (selector.lowercase()) {
        "type" -> { return record.data.type }
        "title" -> { return record.data.title }
        "notes" -> { return record.data.notes ?: "" }
        "file" -> {
            if (parameter == null)
                throw Exception("Notation error - Missing required parameter: filename or file UID for files in record '$recordToken'")
            if (record.files.isNullOrEmpty())
                throw Exception("Notation error - Record $recordToken has no file attachments.")
            // file searches do not use indexes and rely on unique file names or fileUid
            val files = record.files.filter { (it.data.name == parameter) || (it.data.title == parameter) || (it.fileUid == parameter) }
            if (files.size > 1)
                throw Exception("Notation error - Record $recordToken has multiple files matching the search criteria '$parameter'")
            if (files.isEmpty())
                throw Exception("Notation error - Record $recordToken has no files matching the search criteria '$parameter'")
            val contents = downloadFile(files[0])
            return webSafe64FromBytes(contents)
        }
        "field", "custom_field" -> {
            if (parameter == null)
                throw Exception("Notation error - Missing required parameter for the field (type or label): ex. /field/type or /custom_field/MyLabel")

            val fields = when(selector.lowercase()) {
                "field" -> record.data.fields
                "custom_field" -> record.data.custom ?: mutableListOf()
                else -> throw Exception("Notation error - Expected /field or /custom_field but found /$selector")
            }

            val field = fields.find { parameter == fieldType(it) || parameter == it.label } ?:
                throw Exception("Field $parameter not found in the record ${record.recordUid}")

            // /<type|label>[index1][index2], ex. /url == /url[] == /url[][] == full value
            val idx = index1?.toIntOrNull() ?: -1 // -1 full value
            // valid only if [] or missing - ex. /field/phone or /field/phone[]
            if (idx == -1 && !(parsedNotation[2].index1?.second.isNullOrEmpty() || parsedNotation[2].index1?.second == "[]"))
                throw Exception("Notation error - Invalid field index $idx")

            val valuesCount = getFieldValuesCount(field)
            if (idx >= valuesCount)
                throw Exception("Notation error - Field index out of bounds $idx >= $valuesCount for field $parameter")

            //val fullObjValue = (parsedNotation[2].index2?.second.isNullOrEmpty() || parsedNotation[2].index2?.second == "[]")
            val objPropertyName = parsedNotation[2].index2?.first

            // Legacy compat. - full field JSON value only if explicitly specified - ex. /url[]
            //if (idx == -1 && fullObjValue) return getFieldJsonValue(field)

            // legacy compatibility mode - empty index, ex. /url[] returns ["value"]
            if ("[]" == (parsedNotation[2].index1?.second ?: "") && index2.isNullOrEmpty())
                return getFieldJsonValue(field)
            // legacy compatibility mode - index2 only, ex. /name[first] returns value[0][first]
            //if (index1.isNullOrEmpty() && !index2.isNullOrEmpty()) {...}
            // handled by parseNotation w/ legacyMode=true converts /name[middle] to name[][middle]
            // and return first string only

            val expectedSize = if (idx >= 0) 1 else valuesCount
            val res = getFieldStringValues(field, idx, objPropertyName)
            if (res.size != expectedSize)
                print("Notation warning - extracted ${res.size} out of $valuesCount values for '$objPropertyName' property.")
            if (res.isNotEmpty()) {
                // legacy compatibility mode - no indexes, ex. /url returns value[0]
                if(parsedNotation[2].index1?.second.isNullOrEmpty() && parsedNotation[2].index2?.second.isNullOrEmpty())
                    return res[0]
                // legacy compatibility mode - returns only single field value
                return res[0]
            }
            return ""
        }
        else -> throw Exception("Invalid notation $notation")
    }
}

fun getFile(secrets: KeeperSecrets, notation: String): KeeperFile {
    val (record, queryParts) = getRecord(secrets, notation)
    if (queryParts[1] == "file") {
        val fileId = queryParts[2]
        return record.files?.find { x -> x.data.name == fileId || x.data.title == fileId || x.fileUid == fileId }
            ?: throw Exception("File $fileId not found in the record ${record.recordUid}")
    } else {
        throw Exception("Notation should include file tag")
    }
}

private data class RecordAndNotation(val record: KeeperRecord, val queryParts: List<String>)

private fun getRecord(secrets: KeeperSecrets, notation: String): RecordAndNotation {
    var query = notation
    val schemaNotation = query.split("://")
    if (schemaNotation.size > 1) {
        if (schemaNotation[0] != "keeper") {
            throw Exception("Invalid notation schema: ${schemaNotation[0]}")
        }
        query = query.slice(9 until query.length)
    }
    val queryParts = query.split('/')
    if (queryParts.size < 3) {
        throw Exception("invalid notation $notation")
    }
    val record = secrets.getRecordByUid(queryParts[0]) ?: throw Error("Record ${queryParts[0]} not found")
    return RecordAndNotation(record, queryParts)
}

internal fun fieldType(field: KeeperRecordField): String {
    return (field::class.annotations.find { x -> x is SerialName } as SerialName).value
}

@ExperimentalSerializationApi
internal fun getFieldValuesCount(field: KeeperRecordField): Int {
    return when (field) {
        is AccountNumber -> field.value.size
        is AddressRef -> field.value.size
        is Addresses -> field.value.size
        is BankAccounts -> field.value.size
        is BirthDate -> field.value.size
        is CardRef -> field.value.size
        is Date -> field.value.size
        is Email -> field.value.size
        is ExpirationDate -> field.value.size
        is FileRef -> field.value.size
        is HiddenField -> field.value.size
        is Hosts -> field.value.size
        is KeyPairs -> field.value.size
        is LicenseNumber -> field.value.size
        is Login -> field.value.size
        is Multiline -> field.value.size
        is Names -> field.value.size
        is OneTimeCode -> field.value.size
        is OneTimePassword -> field.value.size
        is Password -> field.value.size
        is PaymentCards -> field.value.size
        is Phones -> field.value.size
        is PinCode -> field.value.size
        is SecureNote -> field.value.size
        is SecurityQuestions -> field.value.size
        is Text -> field.value.size
        is Url -> field.value.size
    }
}

// Returns selected parts of the field value
// if index < 0 returns all items from the value array otherwise only the specified index
// if property is not null returns only specified object property of selected items - null if missing
@ExperimentalSerializationApi
internal fun getFieldStringValues(field: KeeperRecordField, index: Int = -1, property: String? = null): List<String> {
    val emptyRes = listOf<String>()
    return when (field) {
        is AccountNumber -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is AddressRef -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is Addresses -> if (index >= field.value.size) emptyRes
            else if (index < 0) {
                if (property == null) field.value.map { Json.encodeToString(it) }.toList()
                else field.value.map { getObjectProperty(it, property) }.toList()
            } else {
                if (property == null) listOf(Json.encodeToString(field.value[index]))
                else listOf(getObjectProperty(field.value[index], property))
            }
        is BankAccounts -> if (index >= field.value.size) emptyRes
        else if (index < 0) {
            if (property == null) field.value.map { Json.encodeToString(it) }.toList()
            else field.value.map { getObjectProperty(it, property) }.toList()
        } else {
            if (property == null) listOf(Json.encodeToString(field.value[index]))
            else listOf(getObjectProperty(field.value[index], property))
        }
        is BirthDate -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value.map { it.toString() }.toList() else listOf(field.value[index].toString())
        is CardRef -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is Date -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value.map { it.toString() }.toList() else listOf(field.value[index].toString())
        is Email -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is ExpirationDate -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value.map { it.toString() }.toList() else listOf(field.value[index].toString())
        is FileRef -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is HiddenField -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is Hosts -> if (index >= field.value.size) emptyRes
            else if (index < 0) {
                if (property == null) field.value.map { Json.encodeToString(it) }.toList()
                else field.value.map { getObjectProperty(it, property) }.toList()
            } else {
                if (property == null) listOf(Json.encodeToString(field.value[index]))
                else listOf(getObjectProperty(field.value[index], property))
            }
        is KeyPairs -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value.map { it.toString() }.toList() else listOf(field.value[index].toString())
        is LicenseNumber -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is Login -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is Multiline -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is Names -> if (index >= field.value.size) emptyRes
            else if (index < 0) {
                if (property == null) field.value.map { Json.encodeToString(it) }.toList()
                else field.value.map { getObjectProperty(it, property) }.toList()
            } else {
                if (property == null) listOf(Json.encodeToString(field.value[index]))
                else listOf(getObjectProperty(field.value[index], property))
            }
        is OneTimeCode -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is OneTimePassword -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is Password -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is PaymentCards -> if (index >= field.value.size) emptyRes
            else if (index < 0) {
                if (property == null) field.value.map { Json.encodeToString(it) }.toList()
                else field.value.map { getObjectProperty(it, property) }.toList()
            } else {
                if (property == null) listOf(Json.encodeToString(field.value[index]))
                else listOf(getObjectProperty(field.value[index], property))
            }
        is Phones -> if (index >= field.value.size) emptyRes
            else if (index < 0) {
                if (property == null) field.value.map { Json.encodeToString(it) }.toList()
                else field.value.map { getObjectProperty(it, property) }.toList()
            } else {
                if (property == null) listOf(Json.encodeToString(field.value[index]))
                else listOf(getObjectProperty(field.value[index], property))
            }
        is PinCode -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is SecureNote -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is SecurityQuestions -> if (index >= field.value.size) emptyRes
            else if (index < 0) {
                if (property == null) field.value.map { Json.encodeToString(it) }.toList()
                else field.value.map { getObjectProperty(it, property) }.toList()
            } else {
                if (property == null) listOf(Json.encodeToString(field.value[index]))
                else listOf(getObjectProperty(field.value[index], property))
            }
        is Text -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
        is Url -> if (index >= field.value.size || property != null) emptyRes
            else if (index < 0) field.value else listOf(field.value[index])
    }
}

@ExperimentalSerializationApi
private fun getFieldStringValue(field: KeeperRecordField, valueIdx: Int): String {
    return when (field) {
        is AccountNumber -> field.value[valueIdx]
        is AddressRef -> field.value[valueIdx]
        is Addresses -> Json.encodeToString(field.value[valueIdx])
        is BankAccounts -> Json.encodeToString(field.value[valueIdx])
        is BirthDate -> field.value[valueIdx].toString()
        is CardRef -> field.value[valueIdx]
        is Date -> field.value[valueIdx].toString()
        is Email -> field.value[valueIdx]
        is ExpirationDate -> field.value[valueIdx].toString()
        is FileRef -> field.value[valueIdx]
        is HiddenField -> field.value[valueIdx]
        is Hosts -> Json.encodeToString(field.value[valueIdx])
        is KeyPairs -> field.value[valueIdx].toString()
        is LicenseNumber -> field.value[valueIdx]
        is Login -> field.value[valueIdx]
        is Multiline -> field.value[valueIdx]
        is Names -> Json.encodeToString(field.value[valueIdx])
        is OneTimeCode -> field.value[valueIdx]
        is OneTimePassword -> field.value[valueIdx]
        is Password -> field.value[valueIdx]
        is PaymentCards -> Json.encodeToString(field.value[valueIdx])
        is Phones -> Json.encodeToString(field.value[valueIdx])
        is PinCode -> field.value[valueIdx]
        is SecureNote -> field.value[valueIdx]
        is SecurityQuestions -> Json.encodeToString(field.value[valueIdx])
        is Text -> field.value[valueIdx]
        is Url -> field.value[valueIdx]
    }
}

private fun getFieldValueProperty(field: KeeperRecordField, valueIdx: Int, propertyName: String): String {
    return when (field) {
        is Addresses -> getObjectProperty(field.value[valueIdx], propertyName)
        is BankAccounts -> getObjectProperty(field.value[valueIdx], propertyName)
        is Hosts -> getObjectProperty(field.value[valueIdx], propertyName)
        is Names -> getObjectProperty(field.value[valueIdx], propertyName)
        is PaymentCards -> getObjectProperty(field.value[valueIdx], propertyName)
        is Phones -> getObjectProperty(field.value[valueIdx], propertyName)
        is SecurityQuestions -> getObjectProperty(field.value[valueIdx], propertyName)
        else -> throw Exception("Property name notation is not supported for ${fieldType(field)}")
    }
}

private fun getObjectProperty(obj: Any, propertyName: String): String {
    return obj.javaClass.kotlin.memberProperties.first { it.name == propertyName }.get(obj).toString()
}

@ExperimentalSerializationApi
private fun getFieldJsonValue(field: KeeperRecordField): String {
    return when (field) {
        is AccountNumber -> Json.encodeToString(field.value)
        is AddressRef -> Json.encodeToString(field.value)
        is Addresses -> Json.encodeToString(field.value)
        is BankAccounts -> Json.encodeToString(field.value)
        is BirthDate -> Json.encodeToString(field.value)
        is CardRef -> Json.encodeToString(field.value)
        is Date -> Json.encodeToString(field.value)
        is Email -> Json.encodeToString(field.value)
        is ExpirationDate -> Json.encodeToString(field.value)
        is FileRef -> Json.encodeToString(field.value)
        is HiddenField -> Json.encodeToString(field.value)
        is Hosts -> Json.encodeToString(field.value)
        is KeyPairs -> Json.encodeToString(field.value)
        is LicenseNumber -> Json.encodeToString(field.value)
        is Login -> Json.encodeToString(field.value)
        is Multiline -> Json.encodeToString(field.value)
        is Names -> Json.encodeToString(field.value)
        is OneTimeCode -> Json.encodeToString(field.value)
        is OneTimePassword -> Json.encodeToString(field.value)
        is Password -> Json.encodeToString(field.value)
        is PaymentCards -> Json.encodeToString(field.value)
        is Phones -> Json.encodeToString(field.value)
        is PinCode -> Json.encodeToString(field.value)
        is SecureNote -> Json.encodeToString(field.value)
        is SecurityQuestions -> Json.encodeToString(field.value)
        is Text -> Json.encodeToString(field.value)
        is Url -> Json.encodeToString(field.value)
    }
}

// data class to represent parsed notation section
internal data class NotationSection(
    var section: String? = null,     // section name - ex. prefix
    var isPresent: Boolean = false,  // presence flag
    var startPos: Int = -1,          // section start position in URI
    var endPos: Int = -1,            // section end position in URI
    var text: Pair<String, String>? = null,      // <unescaped, raw> text
    var parameter: Pair<String, String>? = null, // <field type>|<field label>|<file name>
    var index1: Pair<String, String>? = null,    // numeric index [N] or []
    var index2: Pair<String, String>? = null     // property index - ex. field/name[0][middle]
)

const val ESCAPE_CHAR = '\\'
const val ESCAPE_CHARS = """/[]\""" // /[]\ -> \/ ,\[, \], \\
// Escape the characters in plaintext sections only - title, label or filename

private fun parseSubsection(text: String, position: Int, delimiters: String, escaped: Boolean = false): Pair<String, String>? {
    // raw string excludes start delimiter (if '/') but includes end delimiter or both (if '[',']')
    var pos = position
    if (text.isEmpty() || pos < 0 || pos >= text.length)
        return null
    if (delimiters.isEmpty() || delimiters.length > 2)
        throw Exception("Notation parser: Internal error - Incorrect delimiters count. Delimiters: '$delimiters'")

    var token = ""
    var raw = ""
    while (pos < text.length) {
        if (escaped && ESCAPE_CHAR == text[pos]) {
            // notation cannot end in single char incomplete escape sequence
            // and only escape_chars should be escaped
            if (((pos + 1) >= text.length) || !ESCAPE_CHARS.contains(text[pos + 1]))
                throw Exception("Notation parser: Incorrect escape sequence at position $pos")
            // copy the properly escaped character
            token += text[pos + 1]
            raw += "" + text[pos] + text[pos + 1]
            pos += 2
        } else { // escaped == false || ESCAPE_CHAR != text[pos]
            raw += text[pos] // delimiter is included in raw text
            if (delimiters.length == 1) {
                if (text[pos] == delimiters[0])
                    break
                else
                    token += text[pos]
            } else { // 2 delimiters
                if (raw[0] != delimiters[0])
                    throw Exception("Notation parser: Index sections must start with '['")
                if (raw.length > 1 && text[pos] == delimiters[0])
                    throw Exception("Notation parser: Index sections do not allow extra '[' inside.")
                if (!delimiters.contains(text[pos]))
                    token += text[pos]
                else if (text[pos] == delimiters[1])
                    break
            }
            pos++
        }
    }
    //pos = if (pos < text.length) pos else text.length - 1
    if (delimiters.length == 2 && (
            (raw.length < 2 || raw[0] != delimiters[0] || raw[raw.length - 1] != delimiters[1]) ||
            (escaped && raw[raw.length - 2] == ESCAPE_CHAR)))
        throw Exception("Notation parser: Index sections must be enclosed in '[' and ']'")

    return Pair(token, raw)
}

private fun parseSection(notation: String, section: String, pos: Int): NotationSection {
    if (notation.isEmpty())
        throw Exception("Keeper notation parsing error - missing notation URI")

    val sectionName = section.lowercase()
    val sections: List<String> = listOf("prefix", "record", "selector", "footer")
    if (!sections.contains(sectionName))
        throw Exception("Keeper notation parsing error - unknown section: '$sectionName'")

    val result = NotationSection(section)
    result.startPos = pos
    when (sectionName) {
        "prefix" -> {
            // prefix "keeper://" is not mandatory
            val uriPrefix = "keeper://"
            if (notation.startsWith(uriPrefix, true)) {
                result.isPresent = true
                result.startPos = 0
                result.endPos = uriPrefix.length - 1
                result.text = Pair(notation.substring(0, uriPrefix.length), notation.substring(0, uriPrefix.length))
            }
        }
        "footer" -> {
            // footer should not be present - used only for verification
            result.isPresent = (pos < notation.length)
            if (result.isPresent)
            {
                result.startPos = pos
                result.endPos = notation.length - 1
                result.text = Pair(notation.substring(pos), notation.substring(pos))
            }
        }
        "record" -> {
            // record is always present - either UID or title
            result.isPresent = (pos < notation.length)
            if (result.isPresent)
            {
                val parsed = parseSubsection(notation, pos, "/", true)
                if (parsed != null)
                {
                    result.startPos = pos
                    result.endPos = pos + parsed.second.length - 1
                    result.text = parsed
                }
            }
        }
        "selector" -> {
            // selector is always present - type|title|notes | field|custom_field|file
            result.isPresent = (pos < notation.length)
            if (result.isPresent) {
                var parsed = parseSubsection(notation, pos, "/", false)
                if (parsed != null) {
                    result.startPos = pos
                    result.endPos = pos + parsed.second.length - 1
                    result.text = parsed

                    // selector.parameter - <field type>|<field label> | <file name>
                    // field/name[0][middle], custom_field/my label[0][middle], file/my file[0]
                    val longSelectors: List<String> = listOf("field", "custom_field", "file")
                    if (longSelectors.contains(parsed.first.lowercase())) {
                        // TODO: File metadata extraction: ex. filename[1][size] - that requires filename to be escaped
                        parsed = parseSubsection(notation, result.endPos + 1, "[", true)
                        if (parsed != null) {
                            result.parameter = parsed // <field type>|<field label> | <filename>
                            val parsedLen = parsed.second.length - (if (parsed.second.endsWith("[") && !parsed.second.endsWith("""\[""")) 1 else 0)
                            result.endPos += parsedLen

                            parsed = parseSubsection(notation, result.endPos + 1, "[]", true)
                            if (parsed != null) {
                                result.index1 = parsed // selector.index1 [int] or []
                                result.endPos += parsed.second.length
                                parsed = parseSubsection(notation, result.endPos + 1, "[]", true)
                                if (parsed != null) {
                                    result.index2 = parsed // selector.index2 [str]
                                    result.endPos += parsed.second.length
                                }
                            }
                        }
                    }
                }
            }
        }
        else -> throw Exception("Keeper notation parsing error - unknown section: '$sectionName'")
    }
    return result
}

internal fun parseNotation(notationUri: String, legacyMode: Boolean = false): List<NotationSection> {
    var notation = notationUri
    if (notation.isEmpty())
        throw Exception("Keeper notation is missing or invalid.")

    // Notation is either plaintext keeper URI format or URL safe base64 string (UTF-8)
    // auto-detect format - '/' is not part of base64 URL safe alphabet
    if (!notation.contains('/')) {
        try {
            val bytes = webSafe64ToBytes(notation)
            val plaintext = bytes.decodeToString(0, bytes.size, true)
            notation = plaintext
        } catch (e: Exception) {
            throw Exception("Keeper notation is in invalid format - plaintext URI or URL safe base64 string expected.")
        }
    }

    val prefix = parseSection(notation, "prefix", 0) // keeper://
    var pos = if (prefix.isPresent) prefix.endPos + 1 else 0 // prefix is optional
    val record = parseSection(notation, "record", pos) // <UID> or <Title>
    pos = if (record.isPresent) record.endPos + 1 else notation.length // record is required
    val selector = parseSection(notation, "selector", pos) // type|title|notes | field|custom_field|file
    pos = if (selector.isPresent) selector.endPos + 1 else notation.length // selector is required, indexes are optional
    val footer = parseSection(notation, "footer", pos) // Any text after the last section

    // verify parsed query
    // prefix is optional, record UID/Title and selector are mandatory
    val shortSelectors: List<String> = listOf("type", "title", "notes")
    val fullSelectors: List<String> = listOf("field", "custom_field", "file")
    val selectors: List<String> = listOf("type", "title", "notes", "field", "custom_field", "file")
    if (!record.isPresent || !selector.isPresent)
        throw Exception("Keeper notation URI missing information about the uid, file, field type, or field key.")
    if (footer.isPresent)
        throw Exception("Keeper notation is invalid - extra characters after last section.")
    if (!selectors.contains(selector.text?.first?.lowercase() ?: ""))
        throw Exception("Keeper notation is invalid - bad selector, must be one of (type, title, notes, field, custom_field, file).")
    if (shortSelectors.contains(selector.text?.first?.lowercase() ?: "") && selector.parameter != null)
        throw Exception("Keeper notation is invalid - selectors (type, title, notes) do not have parameters.")
    if (fullSelectors.contains(selector.text?.first?.lowercase() ?: "")) {
        if (selector.parameter == null)
            throw Exception("Keeper notation is invalid - selectors (field, custom_field, file) require parameters.")
        if ("file" == (selector.text?.first?.lowercase() ?: "") && (selector.index1 != null || selector.index2 != null))
            throw Exception("Keeper notation is invalid - file selectors don't accept indexes.")
        if ("file" != (selector.text?.first?.lowercase() ?: "") && selector.index1 == null && selector.index2 != null)
            throw Exception("Keeper notation is invalid - two indexes required.")
        if (selector.index1 != null && !(selector.index1?.second ?: "").matches(Regex("""^\[\d*\]$"""))) {
            if (!legacyMode)
                throw Exception("Keeper notation is invalid - first index must be numeric: [n] or [].")
            if (selector.index2 == null) {   // in legacy mode convert /name[middle] to name[][middle]
                selector.index2 = selector.index1
                selector.index1 = Pair("", "[]")
            }
        }
    }

    return listOf(prefix, record, selector, footer)
}
