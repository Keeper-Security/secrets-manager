package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * An application can log the exception that the InMemoryStorage constructor throws for a config
 * string it cannot parse. kotlinx-serialization puts the decoded config text in that message, so
 * these tests decode through the real parser and look for a canary in every message.
 */
@ExperimentalSerializationApi
internal class InMemoryStorageConfigErrorTest {

    private val canary = "S3cr3t-Pa55w0rd!"

    private fun messageChain(t: Throwable): String =
        generateSequence(t) { it.cause }.joinToString(" | ") { "${it.javaClass.simpleName}: ${it.message}" }

    private val badConfigs: Map<String, String> = run {
        val mistyped = """{"hostname":"fake","clientId":"c","privateKey":"$canary","appKey":12345}"""
        mapOf(
            "mistyped field, raw JSON" to mistyped,
            "mistyped field, base64" to bytesToBase64(mistyped.toByteArray()),
            "not a JSON object" to "$canary is not a config"
        )
    }

    @Test
    fun testInvalidConfigErrorNeverIncludesConfigText() {
        val leaking = mutableListOf<String>()
        for ((name, config) in badConfigs) {
            val thrown = try {
                InMemoryStorage(config)
                null
            } catch (e: Exception) {
                e
            }
            assertTrue(thrown != null, "[$name] an invalid config must throw")
            if (messageChain(thrown).contains(canary)) leaking.add(name)
        }
        assertTrue(leaking.isEmpty(), "these configs put config text in the exception chain: $leaking")
    }

    @Test
    fun testInvalidConfigThrowsSecretsManagerExceptionWithoutCause() {
        // A cause would add a "Caused by:" line that prints the original message.
        val thrown = try {
            InMemoryStorage(badConfigs.getValue("mistyped field, raw JSON"))
            null
        } catch (e: SecretsManagerException) {
            e
        }
        assertTrue(thrown != null, "the constructor must throw SecretsManagerException")
        assertNull(thrown.cause, "the original parser exception must not be kept as the cause")
    }

    @Test
    fun testValidConfigStillLoads() {
        val json = """{"hostname":"fake.example.com","clientId":"c","privateKey":"pk","appKey":"ak"}"""
        for (config in listOf(json, bytesToBase64(json.toByteArray()))) {
            val storage = InMemoryStorage(config)
            assertEquals("fake.example.com", storage.getString(KEY_HOSTNAME))
            assertEquals("ak", storage.getString(KEY_APP_KEY))
        }
    }
}
