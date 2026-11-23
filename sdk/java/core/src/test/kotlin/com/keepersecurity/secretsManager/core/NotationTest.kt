package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.fail

@ExperimentalSerializationApi
internal class NotationTest {

    private val recordUID = "k9qMpcO0aszz9w3li5XbaQ"

    private val recordData = KeeperRecordData(
        "My Record 1",
        "login",
        mutableListOf(
            Login(value = mutableListOf("My Login 1")),
            Password(value = mutableListOf("My Password 1"))
        ),
        mutableListOf(
            Text(label = "My Custom 1", value = mutableListOf("custom1")),
            Text(label = "My Custom 1", value = mutableListOf("custom1")),
            Text(label = "My Custom 2", value = mutableListOf("one", "two", "three")),
            Phones(
                label = "phone", value = mutableListOf(
                    Phone(number = "555-5555555", ext = "22"),
                    Phone(number = "777-7777777", ext = "77"),
                    Phone(number = "888-8888888", ext = "", type = "Home"),
                    Phone(number = "555-5555555", type = "Work")
                )
            ),
            Names(label = "name", value = mutableListOf(Name("Jenny", "X", "Smith")))
        )
    )

    private val recordFiles = listOf<KeeperFile>(
        KeeperFile(
            ByteArray(0), "HKGdx7dSrtuTfA67wiEZkw",
            KeeperFileData("QR Code", "qr.png", "image/png", 53926, 1629142801191),
            "QR Code File Url", null
        )
    )

    private val secrets = KeeperSecrets(
        AppData("", ""),
        listOf(KeeperRecord(ByteArray(0), recordUID, data = recordData, revision = 0, files = recordFiles))
    )

    @Test
    fun notationsWork() {
        var value: String = getValue(secrets, "keeper://${recordUID}/field/login")
        assertEquals("My Login 1", value)

        value = getValue(secrets, "${recordUID}/field/login")
        assertEquals("My Login 1", value)

        value = getValue(secrets, "keeper://${recordUID}/field/login[0]")
        assertEquals("My Login 1", value)

        try {
            getValue(secrets, "keeper://${recordUID}/field/login[1]")
            fail("Getting wrong index did not throw")
        } catch (_: Exception) {
        }
        value = getValue(secrets, "keeper://${recordUID}/field/login[]")
        assertEquals("[\"My Login 1\"]", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/My Custom 1")
        assertEquals("custom1", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/My Custom 2")
        assertEquals("one", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/My Custom 2[1]")
        assertEquals("two", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/My Custom 2[]")
        assertEquals("[\"one\",\"two\",\"three\"]", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/phone[0][number]")
        assertEquals("555-5555555", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/phone[1][number]")
        assertEquals("777-7777777", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/phone[2]")
        assertEquals("{\"number\":\"888-8888888\",\"ext\":\"\",\"type\":\"Home\"}", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/name[first]")
        assertEquals("Jenny", value)

        value = getValue(secrets, "keeper://${recordUID}/custom_field/name[last]")
        assertEquals("Smith", value)

        var file = getFile(secrets, "keeper://${recordUID}/file/QR Code")
        assertEquals("HKGdx7dSrtuTfA67wiEZkw", file.fileUid)
        assertEquals("QR Code File Url", file.url)

        file = getFile(secrets, "keeper://${recordUID}/file/qr.png")
        assertEquals("HKGdx7dSrtuTfA67wiEZkw", file.fileUid)
        assertEquals("QR Code File Url", file.url)
    }

    @Test
    fun getFileWorksWithRecordTitle() {
        // Test getFile should work with record titles, not just UIDs
        
        // Test getFile with record TITLE instead of UID
        var file = getFile(secrets, "My Record 1/file/QR Code")
        assertEquals("HKGdx7dSrtuTfA67wiEZkw", file.fileUid)
        assertEquals("QR Code File Url", file.url)

        file = getFile(secrets, "My Record 1/file/qr.png")
        assertEquals("HKGdx7dSrtuTfA67wiEZkw", file.fileUid)
        assertEquals("QR Code File Url", file.url)

        // Test with keeper:// prefix and title
        file = getFile(secrets, "keeper://My Record 1/file/QR Code")
        assertEquals("HKGdx7dSrtuTfA67wiEZkw", file.fileUid)
        assertEquals("QR Code File Url", file.url)

        file = getFile(secrets, "keeper://My Record 1/file/qr.png")
        assertEquals("HKGdx7dSrtuTfA67wiEZkw", file.fileUid)
        assertEquals("QR Code File Url", file.url)
    }

    @Test
    fun notationParserWork() {
        try {
            parseNotation("/file") // file requires parameters
            fail("Parsing bad notation did not throw")
        } catch (_: Exception) {
        }

        try {
            parseNotation("/type/extra") // extra characters after last section
            fail("Parsing bad notation did not throw")
        } catch (_: Exception) {
        }

        var res = parseNotation("/type")
        assertEquals("type", res[2].text!!.first)

        res = parseNotation("/title")
        assertEquals("title", res[2].text!!.first)

        res = parseNotation("/notes")
        assertEquals("notes", res[2].text!!.first)

        res = parseNotation("/file/filename.ext")
        assertEquals("file", res[2].text!!.first)
        assertEquals("filename.ext", res[2].parameter!!.first)

        res = parseNotation("/field/text")
        assertEquals("field", res[2].text!!.first)
        assertEquals("text", res[2].parameter!!.first)

        res = parseNotation("""/custom_field/label with \[[0][middle]""")
        assertEquals("", res[1].text!!.first) // empty title
        assertEquals("custom_field", res[2].text!!.first)
        assertEquals("""label with [""", res[2].parameter!!.first)
        assertEquals("0", res[2].index1!!.first)
        assertEquals("middle", res[2].index2!!.first)

        res = parseNotation("""title with \[\]\//custom_field/label with \[[0][middle]""")
        assertEquals("""title with []/""", res[1].text!!.first)
        assertEquals("custom_field", res[2].text!!.first)
        assertEquals("""label with [""", res[2].parameter!!.first)
        assertEquals("0", res[2].index1!!.first)
        assertEquals("middle", res[2].index2!!.first)
    }

    @Test
    fun handlesDuplicateUIDs() {
        // When a KSM application has access to both an original record and its shortcut,
        // the same UID appears multiple times but should not be treated as ambiguous
        val duplicateUID = "ABC123XYZ123456789AB"

        val secretsWithDuplicates = KeeperSecrets(
            AppData("", ""),
            listOf(
                KeeperRecord(
                    ByteArray(0), duplicateUID,
                    data = KeeperRecordData(
                        "Original Record",
                        "login",
                        mutableListOf(
                            Login(value = mutableListOf("testuser")),
                            Password(value = mutableListOf("testpass"))
                        ),
                        mutableListOf()
                    ),
                    revision = 0
                ),
                KeeperRecord(
                    ByteArray(0), duplicateUID,  // Same UID (shortcut scenario)
                    data = KeeperRecordData(
                        "Shortcut Record",
                        "login",
                        mutableListOf(
                            Login(value = mutableListOf("testuser")),
                            Password(value = mutableListOf("testpass"))
                        ),
                        mutableListOf()
                    ),
                    revision = 0
                )
            )
        )

        // Should not throw error, should deduplicate and return value
        var value = getValue(secretsWithDuplicates, "keeper://${duplicateUID}/field/login")
        assertEquals("testuser", value)

        value = getValue(secretsWithDuplicates, "keeper://${duplicateUID}/field/password")
        assertEquals("testpass", value)
    }

    // Synthetic key text with newlines, quotes, and backslashes. These are not real keys.
    // The markers PUBLIC1, PUBLIC2, PRIVATE-1, PRIVATE-2, and PRIVATE-3 find leaks in diagnostics.
    private val publicKey1 = "ssh-ed25519 PUBLIC1 \"quoted\" one@example.test"
    private val privateKey1 = "synthetic key PRIVATE-1\nline \"two\" with \\backslash\\\n"
    private val publicKey2 = "ssh-rsa PUBLIC2 two@example.test"
    private val privateKey2 = "synthetic key PRIVATE-2\r\nliteral \\n is not a newline"
    private val privateKey3 = "synthetic key PRIVATE-3\nlast line"
    private val keyMarkers = listOf("PUBLIC1", "PUBLIC2", "PRIVATE-1", "PRIVATE-2", "PRIVATE-3")

    private val keyRecordUid = "SshKeyPairRecordUid001"
    private val url1 = "https://example.test"
    private val url2 = "https://two.example.test"
    private val phone1 = buildJsonObject {
        put("number", "555-5555555")
        put("ext", "22")
    }
    private val phone2 = buildJsonObject {
        put("number", "777-7777777")
        put("type", "Work")
    }

    private fun keyPairJson(publicKey: String, privateKey: String): JsonObject = buildJsonObject {
        put("publicKey", publicKey)
        put("privateKey", privateKey)
    }

    private val pair1 = keyPairJson(publicKey1, privateKey1)
    private val pair2 = keyPairJson(publicKey2, privateKey2)

    // Record JSON as the server stores it. The SDK decodes it into typed fields.
    private val keyRecordJson = buildJsonObject {
        put("title", "SSH Test")
        put("type", "sshKeys")
        putJsonArray("fields") {
            addJsonObject {
                put("type", "keyPair")
                putJsonArray("value") {
                    add(pair1)
                    add(pair2)
                }
            }
            addJsonObject {
                put("type", "url")
                putJsonArray("value") {
                    add(url1)
                    add(url2)
                }
            }
        }
        putJsonArray("custom") {
            addJsonObject {
                put("type", "keyPair")
                put("label", "Deploy Key")
                putJsonArray("value") { add(keyPairJson("", privateKey3)) }
            }
            addJsonObject {
                put("type", "keyPair")
                put("label", "Empty Pair")
                putJsonArray("value") { }
            }
            addJsonObject {
                put("type", "phone")
                put("label", "Phone")
                putJsonArray("value") {
                    add(phone1)
                    add(phone2)
                }
            }
        }
    }

    // The query function answers every request with the encrypted record,
    // so getNotationResults runs with no network and no Keeper account.
    private fun keyRecordOptions(loggingEnabled: Boolean = false): SecretsManagerOptions {
        val transmissionKey = ByteArray(32) { it.toByte() }
        TestStubs.transmissionKeyStub = { transmissionKey }
        val appKey = getRandomBytes(32)
        val recordKey = getRandomBytes(32)
        val response = buildJsonObject {
            put("encryptedAppKey", JsonNull)
            put("folders", JsonNull)
            putJsonArray("records") {
                addJsonObject {
                    put("recordUid", keyRecordUid)
                    put("recordKey", bytesToBase64(encrypt(recordKey, appKey)))
                    put("data", bytesToBase64(encrypt(stringToBytes(keyRecordJson.toString()), recordKey)))
                    put("revision", 1)
                    put("isEditable", true)
                    put("files", JsonNull)
                    put("innerFolderUid", JsonNull)
                }
            }
        }
        val encryptedResponse = encrypt(stringToBytes(response.toString()), transmissionKey)
        val storage = InMemoryStorage()
        initializeStorage(storage, "US:FAKE_CLIENT_KEY")
        storage.saveBytes(KEY_APP_KEY, appKey)
        return SecretsManagerOptions(
            storage,
            queryFunction = { _, _, _ -> KeeperHttpResponse(200, encryptedResponse) },
            loggingEnabled = loggingEnabled
        )
    }

    private fun parseJson(values: List<String>): List<JsonElement> = values.map { Json.parseToJsonElement(it) }

    // The SDK writes notation warnings to standard output and errors to standard error
    private fun captureOutput(block: () -> Unit): String {
        val buffer = ByteArrayOutputStream()
        val stream = PrintStream(buffer, true, "UTF-8")
        val originalOut = System.out
        val originalErr = System.err
        System.setOut(stream)
        System.setErr(stream)
        try {
            block()
        } finally {
            System.setOut(originalOut)
            System.setErr(originalErr)
        }
        return buffer.toString("UTF-8")
    }

    private fun assertNoKeyText(text: String?) {
        for (marker in keyMarkers)
            assertFalse((text ?: "").contains(marker), "Diagnostic text must not contain key material")
    }

    @Test
    fun keyPairPropertiesWithGetValue() {
        val secrets = getSecrets(keyRecordOptions())
        val uid = keyRecordUid

        assertEquals(publicKey1, getValue(secrets, "keeper://$uid/field/keyPair[0][publicKey]"))
        assertEquals(privateKey1, getValue(secrets, "keeper://$uid/field/keyPair[0][privateKey]"))
        assertEquals(publicKey2, getValue(secrets, "keeper://$uid/field/keyPair[1][publicKey]"))
        assertEquals(privateKey2, getValue(secrets, "keeper://$uid/field/keyPair[1][privateKey]"))
        // getValue returns the first result of a projection over all values
        assertEquals(privateKey1, getValue(secrets, "keeper://$uid/field/keyPair[][privateKey]"))
        assertEquals(publicKey1, getValue(secrets, "keeper://$uid/field/keyPair[][publicKey]"))
        // The legacy form with one property index reads the first value
        assertEquals(privateKey1, getValue(secrets, "keeper://$uid/field/keyPair[privateKey]"))
        assertEquals(publicKey1, getValue(secrets, "keeper://$uid/field/keyPair[publicKey]"))
        assertEquals(privateKey2, getValue(secrets, "keeper://SSH Test/field/keyPair[1][privateKey]"))

        // Custom field found by label, with one value and a stored empty public key
        assertEquals(privateKey3, getValue(secrets, "keeper://$uid/custom_field/Deploy Key[0][privateKey]"))
        assertEquals(privateKey3, getValue(secrets, "keeper://$uid/custom_field/Deploy Key[privateKey]"))
        assertEquals("", getValue(secrets, "keeper://$uid/custom_field/Deploy Key[0][publicKey]"))
    }

    @Test
    fun keyPairPropertiesWithGetNotationResults() {
        val options = keyRecordOptions()
        val uid = keyRecordUid

        assertEquals(listOf(publicKey1), getNotationResults(options, "keeper://$uid/field/keyPair[0][publicKey]"))
        assertEquals(listOf(privateKey1), getNotationResults(options, "keeper://$uid/field/keyPair[0][privateKey]"))
        assertEquals(listOf(publicKey2), getNotationResults(options, "keeper://$uid/field/keyPair[1][publicKey]"))
        assertEquals(listOf(privateKey2), getNotationResults(options, "keeper://$uid/field/keyPair[1][privateKey]"))
        assertEquals(listOf(publicKey1, publicKey2), getNotationResults(options, "keeper://$uid/field/keyPair[][publicKey]"))
        assertEquals(listOf(privateKey1, privateKey2), getNotationResults(options, "keeper://$uid/field/keyPair[][privateKey]"))
        assertEquals(listOf(privateKey2), getNotationResults(options, "keeper://SSH Test/field/keyPair[1][privateKey]"))

        assertEquals(listOf(privateKey3), getNotationResults(options, "keeper://$uid/custom_field/Deploy Key[0][privateKey]"))
        // A stored empty key is one value, not a missing result
        assertEquals(listOf(""), getNotationResults(options, "keeper://$uid/custom_field/Deploy Key[][publicKey]"))

        // This API needs a numeric or empty first index before a property index
        assertFailsWith<SecretsManagerException> {
            getNotationResults(options, "keeper://$uid/field/keyPair[privateKey]")
        }
    }

    @Test
    fun keyPairWholeValuesAreJson() {
        val options = keyRecordOptions()
        val secrets = getSecrets(options)
        val uid = keyRecordUid

        // getValue returns one JSON object, or a JSON array for an empty first index
        assertEquals(pair1, Json.parseToJsonElement(getValue(secrets, "keeper://$uid/field/keyPair")))
        assertEquals(pair1, Json.parseToJsonElement(getValue(secrets, "keeper://$uid/field/keyPair[0]")))
        assertEquals(pair2, Json.parseToJsonElement(getValue(secrets, "keeper://$uid/field/keyPair[1]")))
        assertEquals(JsonArray(listOf(pair1, pair2)), Json.parseToJsonElement(getValue(secrets, "keeper://$uid/field/keyPair[]")))
        assertEquals(keyPairJson("", privateKey3),
            Json.parseToJsonElement(getValue(secrets, "keeper://$uid/custom_field/Deploy Key[0]")))

        // getNotationResults returns one JSON object for each selected value
        assertEquals(listOf<JsonElement>(pair1, pair2), parseJson(getNotationResults(options, "keeper://$uid/field/keyPair")))
        assertEquals(listOf<JsonElement>(pair1, pair2), parseJson(getNotationResults(options, "keeper://$uid/field/keyPair[]")))
        assertEquals(listOf<JsonElement>(pair2), parseJson(getNotationResults(options, "keeper://$uid/field/keyPair[1]")))

        // JSON parsing gives back the exact key text
        val parsed = Json.parseToJsonElement(getValue(secrets, "keeper://$uid/field/keyPair[0]")).jsonObject
        assertEquals(privateKey1, parsed["privateKey"]!!.jsonPrimitive.content)
        assertEquals(publicKey1, parsed["publicKey"]!!.jsonPrimitive.content)
    }

    @Test
    fun keyPairEdgeCasesDoNotExposeKeyText() {
        val options = keyRecordOptions(loggingEnabled = true)
        val secrets = getSecrets(options)
        val uid = keyRecordUid

        val output = captureOutput {
            // An empty value list gives empty results, not an error
            assertEquals("", getValue(secrets, "keeper://$uid/custom_field/Empty Pair"))
            assertEquals("[]", getValue(secrets, "keeper://$uid/custom_field/Empty Pair[]"))
            assertEquals("", getValue(secrets, "keeper://$uid/custom_field/Empty Pair[privateKey]"))
            assertEquals(emptyList<String>(), getNotationResults(options, "keeper://$uid/custom_field/Empty Pair"))
            assertEquals(emptyList<String>(), getNotationResults(options, "keeper://$uid/custom_field/Empty Pair[][privateKey]"))

            // An index out of range or an unknown property fails, and the message has no key text.
            // An unknown property fails in the same way as for the other object fields.
            val failures = listOf(
                assertFailsWith<SecretsManagerException> { getValue(secrets, "keeper://$uid/field/keyPair[2][privateKey]") },
                assertFailsWith<SecretsManagerException> { getNotationResults(options, "keeper://$uid/field/keyPair[2][privateKey]") },
                assertFailsWith<SecretsManagerException> { getValue(secrets, "keeper://$uid/custom_field/Empty Pair[0][privateKey]") },
                assertFailsWith<NoSuchElementException> { getValue(secrets, "keeper://$uid/field/keyPair[0][comment]") },
                assertFailsWith<NoSuchElementException> { getNotationResults(options, "keeper://$uid/field/keyPair[][comment]") }
            )
            for (failure in failures)
                assertNoKeyText(failure.message)
            assertEquals(emptyList<String>(), tryGetNotationResults(options, "keeper://$uid/field/keyPair[0][comment]"))
        }
        assertNoKeyText(output)
    }

    @Test
    fun emptyPropertyIndexSelectsWholeValue() {
        val options = keyRecordOptions()
        val secrets = getSecrets(options)
        val uid = keyRecordUid
        val urls = buildJsonArray {
            add(url1)
            add(url2)
        }

        // Field with string values, getValue
        assertEquals(url1, getValue(secrets, "keeper://$uid/field/url"))
        assertEquals(url1, getValue(secrets, "keeper://$uid/field/url[0]"))
        assertEquals(url1, getValue(secrets, "keeper://$uid/field/url[0][]"))
        assertEquals(url2, getValue(secrets, "keeper://$uid/field/url[1][]"))
        assertEquals(urls, Json.parseToJsonElement(getValue(secrets, "keeper://$uid/field/url[]")))
        assertEquals(urls, Json.parseToJsonElement(getValue(secrets, "keeper://$uid/field/url[][]")))

        // Field with string values, getNotationResults
        assertEquals(listOf(url1, url2), getNotationResults(options, "keeper://$uid/field/url"))
        assertEquals(listOf(url1, url2), getNotationResults(options, "keeper://$uid/field/url[]"))
        assertEquals(listOf(url1, url2), getNotationResults(options, "keeper://$uid/field/url[][]"))
        assertEquals(listOf(url1), getNotationResults(options, "keeper://$uid/field/url[0]"))
        assertEquals(listOf(url1), getNotationResults(options, "keeper://$uid/field/url[0][]"))

        // A space inside the second index is a property name, not an empty index
        assertEquals("", getValue(secrets, "keeper://$uid/field/url[0][ ]"))
        assertEquals(emptyList<String>(), getNotationResults(options, "keeper://$uid/field/url[0][ ]"))

        // Fields with object values, getValue
        assertEquals(phone1, Json.parseToJsonElement(getValue(secrets, "keeper://$uid/custom_field/Phone")))
        assertEquals(phone1, Json.parseToJsonElement(getValue(secrets, "keeper://$uid/custom_field/Phone[0]")))
        assertEquals(JsonArray(listOf(phone1, phone2)), Json.parseToJsonElement(getValue(secrets, "keeper://$uid/custom_field/Phone[]")))
        assertEquals(phone1, Json.parseToJsonElement(getValue(secrets, "keeper://$uid/custom_field/Phone[0][]")))
        assertEquals(phone2, Json.parseToJsonElement(getValue(secrets, "keeper://$uid/custom_field/Phone[1][]")))
        assertEquals(JsonArray(listOf(phone1, phone2)), Json.parseToJsonElement(getValue(secrets, "keeper://$uid/custom_field/Phone[][]")))
        assertEquals(pair1, Json.parseToJsonElement(getValue(secrets, "keeper://$uid/field/keyPair[0][]")))
        assertEquals(JsonArray(listOf(pair1, pair2)), Json.parseToJsonElement(getValue(secrets, "keeper://$uid/field/keyPair[][]")))
        assertEquals(keyPairJson("", privateKey3), Json.parseToJsonElement(getValue(secrets, "keeper://$uid/custom_field/Deploy Key[0][]")))
        assertEquals("[]", getValue(secrets, "keeper://$uid/custom_field/Empty Pair[][]"))

        // Fields with object values, getNotationResults
        assertEquals(listOf<JsonElement>(phone1, phone2), parseJson(getNotationResults(options, "keeper://$uid/custom_field/Phone")))
        assertEquals(listOf<JsonElement>(phone1, phone2), parseJson(getNotationResults(options, "keeper://$uid/custom_field/Phone[]")))
        assertEquals(listOf<JsonElement>(phone1), parseJson(getNotationResults(options, "keeper://$uid/custom_field/Phone[0]")))
        assertEquals(listOf<JsonElement>(phone1, phone2), parseJson(getNotationResults(options, "keeper://$uid/custom_field/Phone[][]")))
        assertEquals(listOf<JsonElement>(phone1), parseJson(getNotationResults(options, "keeper://$uid/custom_field/Phone[0][]")))
        assertEquals(listOf<JsonElement>(pair1, pair2), parseJson(getNotationResults(options, "keeper://$uid/field/keyPair[][]")))
        assertEquals(listOf<JsonElement>(pair2), parseJson(getNotationResults(options, "keeper://$uid/field/keyPair[1][]")))
        assertEquals(listOf<JsonElement>(keyPairJson("", privateKey3)),
            parseJson(getNotationResults(options, "keeper://$uid/custom_field/Deploy Key[0][]")))
        assertEquals(emptyList<String>(), getNotationResults(options, "keeper://$uid/custom_field/Empty Pair[][]"))

        // A property index still selects one property
        assertEquals("777-7777777", getValue(secrets, "keeper://$uid/custom_field/Phone[1][number]"))
        assertEquals(listOf("555-5555555", "777-7777777"), getNotationResults(options, "keeper://$uid/custom_field/Phone[][number]"))
    }
}
