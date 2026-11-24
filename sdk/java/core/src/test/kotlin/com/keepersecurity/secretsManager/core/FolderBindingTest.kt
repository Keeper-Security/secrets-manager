package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.IOException
import java.net.HttpURLConnection.HTTP_FORBIDDEN
import java.net.HttpURLConnection.HTTP_OK
import java.net.HttpURLConnection.HTTP_UNAVAILABLE
import kotlin.test.*

@OptIn(ExperimentalSerializationApi::class)
class FolderBindingTest {
    @get:Rule val temp = TemporaryFolder()

    private val appKey = getRandomBytes(32)
    private val ownerKey = extractPublicRaw(generateKeyPair().public)
    private val denied = KeeperHttpResponse(
        HTTP_FORBIDDEN,
        stringToBytes("""{"error":"access_denied","message":"Unable to validate Keeper application access"}""")
    )

    private fun newToken() = "US:${webSafe64FromBytes(getRandomBytes(32))}"

    private fun response(data: String, key: TransmissionKey) =
        KeeperHttpResponse(HTTP_OK, encrypt(stringToBytes(data), key.key))

    private fun bindingResponse(storage: KeyValueStorage) =
        """{"encryptedAppKey":"${bytesToBase64(encrypt(appKey, storage.getBytes(KEY_CLIENT_KEY)!!))}","appOwnerPublicKey":"${bytesToBase64(ownerKey)}"}"""

    @Test
    fun refusedFirstReadRemovesTheFileAndAllowsANewToken() {
        val config = temp.root.resolve("config.json")
        val storage = LocalConfigStorage(config.path)
        initializeStorage(storage, newToken())
        val refusedClientId = storage.getString(KEY_CLIENT_ID)
        var requests = 0
        val refused = SecretsManagerOptions(storage, queryFunction = { url, _, _ ->
            assertTrue(url.endsWith("/get_folders"))
            requests++
            denied
        })

        val failure = assertFailsWith<SecretsManagerException> { getFolders(refused) }

        assertTrue(failure.message!!.contains("Generate a new one-time token"))
        assertEquals(1, requests)
        assertFalse(config.exists())
        assertNull(storage.getString(KEY_CLIENT_ID))
        assertNull(storage.getBytes(KEY_CLIENT_KEY))
        assertNull(storage.getBytes(KEY_PRIVATE_KEY))
        assertNull(storage.getBytes(KEY_PUBLIC_KEY))

        initializeStorage(storage, newToken())
        assertNotEquals(refusedClientId, storage.getString(KEY_CLIENT_ID))
        val binding = bindingResponse(storage)
        val sentPublicKey = mutableListOf<Boolean>()
        val accepted = SecretsManagerOptions(storage, queryFunction = { url, key, payload ->
            val body = Json.parseToJsonElement(bytesToString(decrypt(payload.payload, key.key))).jsonObject
            sentPublicKey.add("publicKey" in body)
            when {
                url.endsWith("/get_secret") -> response("""{"encryptedAppKey":null,"folders":[],"records":[]}""", key)
                sentPublicKey.size == 1 -> response(binding, key)
                else -> response("""{"folders":[]}""", key)
            }
        })

        assertEquals(emptyList(), getFolders(accepted))
        assertEquals(emptyList(), getSecrets(accepted).records)
        assertEquals(listOf(true, false, false), sentPublicKey)
        val saved = LocalConfigStorage(config.path)
        assertContentEquals(appKey, saved.getBytes(KEY_APP_KEY))
        assertContentEquals(ownerKey, saved.getBytes(KEY_OWNER_PUBLIC_KEY))
        assertNull(saved.getBytes(KEY_CLIENT_KEY))
    }

    @Test
    fun refusedRefreshAndLaterReadsKeepTheBoundConfig() {
        val config = temp.root.resolve("config.json")
        val storage = LocalConfigStorage(config.path)
        initializeStorage(storage, newToken())
        val binding = bindingResponse(storage)
        var reads = 0
        val options = SecretsManagerOptions(storage, queryFunction = { _, key, _ ->
            if (reads++ == 0) response(binding, key) else denied
        })

        assertFailsWith<SecretsManagerException> { getFolders(options) }
        val savedConfig = config.readText()
        assertContentEquals(appKey, LocalConfigStorage(config.path).getBytes(KEY_APP_KEY))
        assertFailsWith<SecretsManagerException> { getFolders(options) }
        assertEquals(savedConfig, config.readText())
        assertEquals(3, reads)
    }

    @Test
    fun refusedFirstReadUsesTheStringErrorCode() {
        for (body in listOf(
            """{"result_code":"access_denied"}""",
            """{"result_code":null,"error":"access_denied"}"""
        )) {
            val config = temp.newFolder().resolve("config.json")
            val storage = LocalConfigStorage(config.path)
            initializeStorage(storage, newToken())
            val options = SecretsManagerOptions(storage, queryFunction = { _, _, _ ->
                KeeperHttpResponse(HTTP_FORBIDDEN, stringToBytes(body))
            })

            val failure = assertFailsWith<SecretsManagerException> { getFolders(options) }

            assertTrue(failure.message!!.contains("Generate a new one-time token"))
            assertFalse(config.exists())
        }
    }

    @Test
    fun transientFailuresKeepTheIncompleteConfig() {
        val config = temp.root.resolve("config.json")
        val storage = LocalConfigStorage(config.path)
        initializeStorage(storage, newToken())
        val saved = config.readText()
        val transportError = IOException("Test transport failure")
        val transportFailure = SecretsManagerOptions(storage, queryFunction = { _, _, _ -> throw transportError })
        val serverFailure = SecretsManagerOptions(storage, queryFunction = { _, _, _ ->
            KeeperHttpResponse(HTTP_UNAVAILABLE, ByteArray(0))
        })

        assertSame(transportError, assertFailsWith<IOException> { getFolders(transportFailure) })
        assertFailsWith<SecretsManagerException> { getFolders(serverFailure) }
        assertEquals(saved, config.readText())
    }

    @Test
    fun refusalKeepsInMemoryStorage() {
        for (storage in listOf(InMemoryStorage(), LocalConfigStorage())) {
            initializeStorage(storage, newToken())
            val clientId = storage.getString(KEY_CLIENT_ID)
            val options = SecretsManagerOptions(storage, queryFunction = { _, _, _ -> denied })

            assertFailsWith<SecretsManagerException> { getFolders(options) }
            assertEquals(clientId, storage.getString(KEY_CLIENT_ID))
        }
    }

    @Test
    fun refusalKeepsAConfigThatAnotherInstanceBound() {
        val config = temp.root.resolve("config.json")
        val storage = LocalConfigStorage(config.path)
        initializeStorage(storage, newToken())
        val options = SecretsManagerOptions(storage, queryFunction = { _, _, _ ->
            LocalConfigStorage(config.path).saveBytes(KEY_APP_KEY, appKey)
            denied
        })

        assertFailsWith<SecretsManagerException> { getFolders(options) }
        assertContentEquals(appKey, LocalConfigStorage(config.path).getBytes(KEY_APP_KEY))
    }

    @Test
    fun refusalKeepsAReplacementUnboundConfig() {
        for (reuseToken in listOf(false, true)) {
            val config = temp.newFolder().resolve("config.json")
            val storage = LocalConfigStorage(config.path)
            val token = newToken()
            initializeStorage(storage, token)
            val clientId = storage.getString(KEY_CLIENT_ID)
            val privateKey = storage.getBytes(KEY_PRIVATE_KEY)

            val replacement = temp.newFolder().resolve("config.json")
            val replacementStorage = LocalConfigStorage(replacement.path)
            initializeStorage(replacementStorage, if (reuseToken) token else newToken())
            val saved = replacement.readText()
            val options = SecretsManagerOptions(storage, queryFunction = { _, _, _ ->
                replacement.copyTo(config, overwrite = true)
                denied
            })

            val failure = assertFailsWith<SecretsManagerException> { getFolders(options) }

            assertTrue(failure.message!!.contains("access_denied"))
            assertEquals(saved, config.readText())
            assertEquals(clientId, storage.getString(KEY_CLIENT_ID))
            assertContentEquals(privateKey, storage.getBytes(KEY_PRIVATE_KEY))
        }
    }
}
