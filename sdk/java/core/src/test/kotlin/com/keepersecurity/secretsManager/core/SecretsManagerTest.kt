package com.keepersecurity.secretsManager.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.fail

internal class SecretsManagerTest {

    @Serializable
    data class TestResponse(val transmissionKey: String, val data: String, val statusCode: Int)

    @Test
    fun getSecretsE2E() {
        val file = File("../../test_data.json")
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

//    @Test // uncomment to debug the integration test
    fun integrationTest() {
        val trustAllPostFunction: (
            url: String,
            transmissionKey: TransmissionKey,
            payload: EncryptedPayload,
        ) -> KeeperHttpResponse = { url, transmissionKey, payload -> postFunction(url, transmissionKey, payload, true) }
        val storage = LocalConfigStorage("config-prod-msp1.json")
        initializeStorage(storage, "BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw", "keepersecurity.com")
        val options = SecretsManagerOptions(storage, trustAllPostFunction)
//        val options = SecretsManagerOptions(storage, ::cachingPostFunction)
        val secrets = getSecrets(options)
        val record = secrets.records[0]
        val password = record.getPassword()
        if (password != null) {
            println(password)
//            record.updatePassword("new password")
//            updateSecret(options, record)
        }
//        val file = record.getFileByUid("XISgEFjKffxAsjzYCUJ6Bg")
//        if (file != null) {
//            val fileBytes = downloadFile(file)
//            val fos = FileOutputStream(file.data.name)
//            fos.write(fileBytes)
//            fos.close()
//        }
    }
}