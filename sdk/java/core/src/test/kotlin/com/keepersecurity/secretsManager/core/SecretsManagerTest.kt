package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import kotlin.test.*

@ExperimentalSerializationApi
internal class SecretsManagerTest {

    @Serializable
    data class TestResponse(val transmissionKey: String, val data: String, val statusCode: Int)

    @ExperimentalSerializationApi
    @Test
    fun getSecretsE2E() {
        val file = File("../../test_data.json")

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
        initializeStorage(storage, "VB3sGkzVyRB9Lup6WE7Rx-ETFZxyWR2zqY2b9f2zwBo", "local.keepersecurity.com")
        val options = SecretsManagerOptions(storage, testPostFunction)
        val secrets = getSecrets(options)
        assertTrue(secrets.size() == 2)
        val record = secrets.getRecordByUid("i3v4ehaoB-Bwsb7bbbek2g")
        assertNotNull(record)
        val password = record.getPassword()
        assertNotNull(password)
        assertEquals("N\$B!lkoOrVL1RUNDBvn2", password)
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
        initializeStorage(storage, "US:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw")
        assertEquals("keepersecurity.com", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "EU:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw")
        assertEquals("keepersecurity.eu", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "AU:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw")
        assertEquals("keepersecurity.com.au", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "eu:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw")
        assertEquals("keepersecurity.eu", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "local.keepersecurity.com:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw")
        assertEquals("local.keepersecurity.com", storage.getString("hostname"))
    }

    @Test
    fun testStorageBase64Config() {
        val base64Config: String = "eyAgICAgImFwcEtleSI6ICI4S3gyNVN2dGtSU3NFWUl1cjdtSEt0THFBTkZOQjdBWlJhOWNxaTJQU1FFPSIsICAgICAiY2x" +
                "pZW50SWQiOiAiNEgvVTVKNkRjZktMWUJJSUFWNVl3RUZHNG4zWGhpRHZOdG9Qa21TTUlUZVROWnNhL0VKMHpUYnBBQ1J0bU" +
                "5VQlJIK052UisyNHNRaFU5dUdqTFRaSHc9PSIsICAgICAiaG9zdG5hbWUiOiAia2VlcGVyc2VjdXJpdHkuY29tIiwgICAgI" +
                "CJwcml2YXRlS2V5IjogIk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ3VoekRJNGlW" +
                "UzVCdzlsNWNmZkZYcFArRmh1bE5INDFHRFdWY3NiZ1h5aU9oUkFOQ0FBVGsxZnpvTDgvVkxwdVl1dTEzd0VsUE5wM2FHMmd" +
                "sRmtFUHp4YWlNZ1ArdnRVZDRnWjIzVHBHdTFzMXRxS2FFZTloN1ZDVk1qd3ZEQTMxYW5mTWxZRjUiLCAgICAgInNlcnZlcl" +
                "B1YmxpY0tleUlkIjogIjEwIiB9"
        val storage = InMemoryStorage(base64Config)
        assertEquals("keepersecurity.com", storage.getString("hostname"))
    }

//    @Test // uncomment to debug the integration test
    fun integrationTest() {
        val trustAllPostFunction: (
            url: String,
            transmissionKey: TransmissionKey,
            payload: EncryptedPayload,
        ) -> KeeperHttpResponse = { url, transmissionKey, payload -> postFunction(url, transmissionKey, payload, true) }
        val storage = LocalConfigStorage("config-dev.json")
//        initializeStorage(storage, "dev.keepersecurity.com:3rUMHjPysRByQPIrwLCwTtKFIBnfxpZeA4UG32w0wuU")
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