package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
//import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.FileReader
import java.security.Security
import kotlin.test.*

@ExperimentalSerializationApi
internal class SecretsManagerTest {

    @Serializable
    data class TestResponse(val transmissionKey: String, val data: String, val statusCode: Int)

    @ExperimentalSerializationApi
    @Test
    fun getSecretsE2E() {
        val file = File("../../fake_data.json")

        assertTrue(file.exists())

        val inputStream = BufferedReader(FileReader(file))
        val jsonString = inputStream.lines().reduce { x: String, y: String -> x + y }
        val testResponses = Json.decodeFromString<List<TestResponse>>(jsonString.get())
        var responseNo = 0
        TestStubs.transmissionKeyStub = { base64ToBytes(testResponses[responseNo].transmissionKey) }
        val testPostFunction: (
            url: String,
            transmissionKey: TransmissionKey,
            payload: EncryptedPayload,
        ) -> KeeperHttpResponse = { _, _, _ ->
            val response = testResponses[responseNo++]
            KeeperHttpResponse(response.statusCode, base64ToBytes(response.data))
        }
        val storage = LocalConfigStorage()

        val fakeOneTimeCode = "YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c"

        initializeStorage(storage, fakeOneTimeCode, "fake.keepersecurity.com")
        val options = SecretsManagerOptions(storage, testPostFunction)
        val secrets = getSecrets(options)
        assertTrue(secrets.records.size == 2)
        val record = secrets.getRecordByUid("Ue8h6JyWUs7Iu6eY_mha-w")
        assertNotNull(record)
        val password = record.getPassword()
        assertNotNull(password)
        assertEquals("EwFpmg);7KsO9+ln8g7", password)

        record.updatePassword("NewPassword1")
        val passwordNew1 = record.getPassword()
        assertNotNull(passwordNew1)
        assertEquals("NewPassword1", passwordNew1)

        // Removing password from the record
        (record.data.fields[2] as Password).value.clear()
        val passwordNull = record.getPassword()
        assertNull(passwordNull)

        record.updatePassword("NewPassword2")
        val passwordNew2 = record.getPassword()
        assertNotNull(passwordNew2)
        assertEquals("NewPassword2", passwordNew2)

        try {
            getSecrets(options)
            fail("Did not throw")
        } catch (e: Exception) {
            val message = Json.decodeFromString<JsonObject>(e.message!!)["message"]!!.jsonPrimitive
            assertEquals("Signature is invalid", message.content)
        }
    }

    @Test
    fun getSecretsE2EWithNoProvider() {
        getSecretsE2E()
    }

//    @Test
//    fun getSecretsE2EWithBC() {
//        Security.addProvider(BouncyCastleProvider())
//        getSecretsE2E()
//    }

    @Test
    fun getSecretsE2EWithBCFips() {
        Security.addProvider(BouncyCastleFipsProvider())
        getSecretsE2E()
    }

    @Test
    fun testStoragePrefixes() {
        var storage = InMemoryStorage()
        initializeStorage(storage, "US:ONE_TIME_TOKEN")
        assertEquals("keepersecurity.com", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "EU:ONE_TIME_TOKEN")
        assertEquals("keepersecurity.eu", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "AU:ONE_TIME_TOKEN")
        assertEquals("keepersecurity.com.au", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "eu:ONE_TIME_TOKEN")
        assertEquals("keepersecurity.eu", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "IL5:ONE_TIME_TOKEN")
        assertEquals("il5.keepersecurity.us", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "fake.keepersecurity.com:ONE_TIME_TOKEN")
        assertEquals("fake.keepersecurity.com", storage.getString("hostname"))
    }

    @Test
    fun testStorageBase64Config() {
        val fakeBase64Config: String = "eyJhcHBLZXkiOiAiRkFLRV9BUFBfS0VZIiwgICAgICJjbGllbnRJZCI6ICJGQUtFX0NMSUVOVF9LRVkiL" +
                "CAgICAgImhvc3RuYW1lIjogImZha2Uua2VlcGVyc2VjdXJpdHkuY29tIiwgICAgICJwcml2YXRlS2V5IjogIkZBS0VfUFJJVkFUR" +
                "V9LRVkiLCAgICAKInNlcnZlclB1YmxpY0tleUlkIjogIjEwIiB9"
        val storage = InMemoryStorage(fakeBase64Config)
        assertEquals("fake.keepersecurity.com", storage.getString("hostname"))
    }

    @Test
    fun testIL5OttFourSegmentParsing() {
        // KSM-902: 4-segment OTT IL5:clientKey:keyId:serverPublicKey stores key and ID in storage
        val fakeServerPublicKey = "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"
        val storage = InMemoryStorage()
        initializeStorage(storage, "IL5:FAKE_CLIENT_KEY:20:$fakeServerPublicKey")
        assertEquals("il5.keepersecurity.us", storage.getString(KEY_HOSTNAME))
        assertEquals("20", storage.getString(KEY_SERVER_PUBLIC_KEY_ID))
        assertEquals(fakeServerPublicKey, storage.getString(KEY_SERVER_PUBLIC_KEY))
    }

    @Test
    fun testExtendedOttRejectsThreeSegments() {
        // A 3-segment OTT was previously accepted and silently misparsed as a 2-segment token
        // with the third segment dropped; it must now be rejected loudly instead.
        val storage = InMemoryStorage()
        val ex = assertFailsWith<Exception> {
            initializeStorage(storage, "IL5:FAKE_CLIENT_KEY:20")
        }
        assertTrue(ex.message?.contains("segment count") == true, "Got: ${ex.message}")
    }

    @Test
    fun testIL5ConstructorParamPersistsToStorage() {
        // KSM-902: serverPublicKey constructor param is saved to storage so generateTransmissionKey can use it
        val fakeServerPublicKey = "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"
        val storage = InMemoryStorage()
        SecretsManagerOptions(storage, serverPublicKey = fakeServerPublicKey)
        assertEquals(fakeServerPublicKey, storage.getString(KEY_SERVER_PUBLIC_KEY))
    }

    @Test
    fun testIL5ConfigFieldOverridesEmbeddedTable() {
        // KSM-902: KEY_SERVER_PUBLIC_KEY in storage must be used instead of the embedded key table.
        // Key ID 999 is not in the embedded table. With a custom key in storage, generateTransmissionKey
        // must use the storage key. If it falls through to the table, it throws
        // "Key number 999 is not supported" and the post function is never called.
        val customKey = "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"
        val storage = InMemoryStorage()
        initializeStorage(storage, "IL5:FAKE_CLIENT_KEY:999:$customKey")
        assertEquals("999", storage.getString(KEY_SERVER_PUBLIC_KEY_ID))
        assertEquals(customKey, storage.getString(KEY_SERVER_PUBLIC_KEY))

        var capturedKeyId: Int? = null
        TestStubs.transmissionKeyStub = { ByteArray(32) }
        val testPostFunction: (String, TransmissionKey, EncryptedPayload) -> KeeperHttpResponse = { _, tk, _ ->
            capturedKeyId = tk.publicKeyId
            KeeperHttpResponse(400, """{"error":"generic","message":"intercepted"}""".toByteArray())
        }
        val options = SecretsManagerOptions(storage, testPostFunction)
        try { getSecrets(options) } catch (_: Exception) {}

        assertEquals(999, capturedKeyId, "generateTransmissionKey must use storage key (ID 999) not the embedded table")
    }

    @Test
    fun testRecordCreateEmptyCustomSerialized() {
        // KSM-823: RecordCreate with no custom fields must include "custom": [] in JSON payload
        val recordData = KeeperRecordData(
            title = "Test Record",
            type = "login",
            fields = mutableListOf()
        )
        val json = Json.encodeToString(recordData)
        assertTrue(json.contains("\"custom\":[]") || json.contains("\"custom\": []"),
            "Serialized payload must include custom:[] even when no custom fields are set. Got: $json")
    }

    @Test
    fun testKeeperFileDataMissingLastModified() {
        // GH-973 / KSM-854: lastModified entirely absent — must deserialize without throwing
        val json = """{"title":"test.txt","name":"test.txt","type":"text/plain","size":1024}"""
        val result = Json.decodeFromString<KeeperFileData>(json)
        assertEquals(0L, result.lastModified)
        assertEquals("test.txt", result.name)
    }

    @Test
    fun testKeeperFileDataIntegerLastModified() {
        // Regression guard: normal integer lastModified
        val json = """{"title":"test.txt","name":"test.txt","size":1024,"lastModified":1700000000000}"""
        val result = Json.decodeFromString<KeeperFileData>(json)
        assertEquals(1700000000000L, result.lastModified)
    }

    @Test
    fun testKeeperFileDataFractionalLastModified() {
        // Regression guard for KSM-673: fractional lastModified (iOS client format)
        val json = """{"title":"test.txt","name":"test.txt","size":1024,"lastModified":1760646182.790214}"""
        val result = Json.decodeFromString<KeeperFileData>(json)
        assertEquals(1760646182L, result.lastModified)
    }

    @Test
    fun testKeeperFileNullUrl() {
        // KSM-765: KeeperFile.url must be nullable; server may omit url for files without a download link
        val fileData = KeeperFileData("test.txt", "test.txt", "text/plain", 1024)
        val file = KeeperFile(ByteArray(32), "uid123", fileData, null, null)
        assertNull(file.url)
    }

    @Test
    fun testBase64EmptyStringThrowsTypedException() {
        // KSM-985: empty string must throw a typed Keeper exception, not an NPE from inside java.util.Base64
        val base64Ex = assertFailsWith<Exception> { base64ToBytes("") }
        assertTrue(base64Ex.message?.isNotEmpty() == true)
        val webSafe64Ex = assertFailsWith<Exception> { webSafe64ToBytes("") }
        assertTrue(webSafe64Ex.message?.isNotEmpty() == true)
    }

    @Test
    fun testSharedFolderFlatRecordUsesFolderKey() {
        // A flat records[] entry with innerFolderUid set has its recordKey encrypted with the
        // folder key, not the app key. Decrypting with the app key yields garbage and the record
        // is silently skipped, so all of its fields come back missing.
        val transmissionKey = ByteArray(32) { it.toByte() }
        TestStubs.transmissionKeyStub = { transmissionKey }

        val appKey = getRandomBytes(32)
        val folderKey = getRandomBytes(32)
        val recordKey = getRandomBytes(32)
        val folderUid = "testFolderUid001"
        val recordUid = "testRecordUid001"

        val encFolderKey = bytesToBase64(encrypt(folderKey, appKey))
        val encRecordKey = bytesToBase64(encrypt(recordKey, folderKey))
        val recordDataJson = """{"title":"Shared Record","type":"login","fields":[],"custom":[]}"""
        val encData = bytesToBase64(encrypt(stringToBytes(recordDataJson), recordKey))

        val responseJson = """{"encryptedAppKey":null,"folders":[{"folderUid":"$folderUid","folderKey":"$encFolderKey","data":null,"parent":null,"records":null}],"records":[{"recordUid":"$recordUid","recordKey":"$encRecordKey","data":"$encData","revision":1,"isEditable":true,"files":null,"innerFolderUid":"$folderUid"}]}"""
        val encryptedResponse = encrypt(stringToBytes(responseJson), transmissionKey)

        val storage = InMemoryStorage()
        initializeStorage(storage, "US:FAKE_CLIENT_KEY")
        storage.saveBytes(KEY_APP_KEY, appKey)

        val options = SecretsManagerOptions(storage, queryFunction = { _, _, _ -> KeeperHttpResponse(200, encryptedResponse) })
        val secrets = getSecrets(options)

        assertEquals(1, secrets.records.size)
        val record = secrets.records[0]
        assertEquals("Shared Record", record.data.title,
            "flat record with innerFolderUid must decrypt with the folder key, not the app key")
        assertEquals(folderUid, record.folderUid)
    }

//    @Test // uncomment to debug the integration test
    fun integrationTest() {
        val trustAllPostFunction: (
            url: String,
            transmissionKey: TransmissionKey,
            payload: EncryptedPayload,
        ) -> KeeperHttpResponse = { url, transmissionKey, payload -> postFunction(url, transmissionKey, payload, true) }
        val storage = LocalConfigStorage("config-dev.json")
//        initializeStorage(storage, "US:ONE_TIME_TOKEN")
        val options = SecretsManagerOptions(storage, trustAllPostFunction)
//        val options = SecretsManagerOptions(storage, ::cachingPostFunction)
        val secrets = getSecrets(options)
        val record = secrets.records[0]
        println(record.data.title)
        val password = record.getPassword()
        if (password != null) {
            println(password)
//            record.updatePassword("new password")
//            updateSecret(options, record)
        }

        val fis = FileInputStream("config-dev.json")
        val bytes = fis.readBytes()
        uploadFile(options, record, KeeperFileUpload("config-dev.json", "Sample File", "application/json", bytes))

//        if (record.folderUid != null) {
//            record.data.title = record.data.title + " Copy (Java)"
//            val recordUid = createSecret(options, record.folderUid!!, record.data, secrets)
//            println(recordUid)
//        }
//        val file = record.getFileByUid("XISgEFjKffxAsjzYCUJ6Bg")
//        if (file != null) {
//            val fileBytes = downloadFile(file)
//            val fos = FileOutputStream(file.data.name)
//            fos.write(fileBytes)
//            fos.close()
//        }
    }
}