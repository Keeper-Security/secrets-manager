package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import java.io.File
import kotlin.test.*

@ExperimentalSerializationApi
internal class IL5EdgeCaseTest {

    private val fakeServerPublicKey =
        "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"

    @BeforeTest
    fun setUp() {
        TestStubs.transmissionKeyStub = { ByteArray(32) }
    }

    @Test
    fun localConfigStoragePersistsServerPublicKey() {
        // Delete immediately — we only want the unique path, not an empty file that would fail JSON parse.
        val configFile = File.createTempFile("ksm-test-", ".json").also { it.delete() }
        try {
            initializeStorage(LocalConfigStorage(configFile.absolutePath), "IL5:FAKE_CLIENT_KEY:20:$fakeServerPublicKey")

            // Simulate a second run: fresh LocalConfigStorage loading from the same file.
            val storage2 = LocalConfigStorage(configFile.absolutePath)
            assertEquals(
                fakeServerPublicKey,
                storage2.getString(KEY_SERVER_PUBLIC_KEY),
                "serverPublicKey must survive a save/load round-trip through LocalConfigStorage"
            )
            assertEquals("20", storage2.getString(KEY_SERVER_PUBLIC_KEY_ID))
        } finally {
            configFile.delete()
        }
    }

    @Test
    fun customKeyRejection_surfacesActionableIl5Message() {
        val storage = InMemoryStorage()
        initializeStorage(storage, "IL5:FAKE_CLIENT_KEY:20:$fakeServerPublicKey")
        storage.saveBytes(KEY_APP_KEY, ByteArray(32))

        val mock: QueryFunction = { _, _, _ ->
            KeeperHttpResponse(400, """{"error":"key","key_id":21}""".toByteArray())
        }
        val options = SecretsManagerOptions(storage, mock)

        val ex = assertFailsWith<Exception> { getSecrets(options) }
        assertTrue(
            ex.message?.contains("Server rejected the custom server public key") == true,
            "Expected actionable IL5 message, got: ${ex.message}"
        )
        assertTrue(
            ex.message?.contains("21") == true,
            "Expected suggested key id 21 in message, got: ${ex.message}"
        )
    }
}
