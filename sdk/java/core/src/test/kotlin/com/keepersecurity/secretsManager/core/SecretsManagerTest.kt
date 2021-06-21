package com.keepersecurity.secretsManager.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import kotlin.test.Test
import kotlin.test.assertEquals
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
        TestStubs.queryStub = {
            val response = testResponses[responseNo++]
            Pair(base64ToBytes(response.data), response.statusCode)
        }
        TestStubs.transmissionKeyStub = { base64ToBytes(testResponses[responseNo].transmissionKey) }
        val storage = LocalConfigStorage(null)
        initializeStorage(storage, "VB3sGkzVyRB9Lup6WE7Rx-ETFZxyWR2zqY2b9f2zwBo", "local.keepersecurity.com")
        val secrets = getSecrets(storage)
        val password =
            (((secrets.records[1].data["fields"] as JsonArray)[1] as JsonObject)["value"] as JsonArray)[0].jsonPrimitive
        assertEquals("N\$B!lkoOrVL1RUNDBvn2", password.content)
        try {
            getSecrets(storage)
            fail("Did not throw")
        } catch (e: Exception) {
            val message = Json.decodeFromString<JsonObject>(e.message!!)["message"]!!.jsonPrimitive
            assertEquals("Signature is invalid", message.content)
        }
    }
}