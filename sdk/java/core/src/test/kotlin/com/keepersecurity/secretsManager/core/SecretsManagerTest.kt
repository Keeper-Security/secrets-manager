package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
//import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.security.Security
import kotlin.test.*

@ExperimentalSerializationApi
internal class SecretsManagerTest {

    init {
        Security.addProvider(BouncyCastleFipsProvider())
//        Security.addProvider(BouncyCastleProvider())
    }

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

        val fakeOneTimeCode = "VB3sGkzVyRB9Lup6WE7Rx-ETFZxyWR2zqY2b9f2zwBo"

        initializeStorage(storage, fakeOneTimeCode, "fake.keepersecurity.com")
        val options = SecretsManagerOptions(storage, testPostFunction)
        val secrets = getSecrets(options)
        assertTrue(secrets.records.size == 2)
        val record = secrets.getRecordByUid("i3v4ehaoB-Bwsb7bbbek2g")
        assertNotNull(record)
        val password = record.getPassword()
        assertNotNull(password)
        assertEquals("N\$B!lkoOrVL1RUNDBvn2", password)

        record.updatePassword("NewPassword1")
        val passwordNew1 = record.getPassword()
        assertNotNull(passwordNew1)
        assertEquals("NewPassword1", passwordNew1)

        // Removing password from the record
        (record.data.fields[1] as Password).value.clear()
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