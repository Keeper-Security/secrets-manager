package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.Signature
import java.util.Base64
import kotlin.test.*

// Runs getSecrets through the real cachingPostFunction with a scripted post function and a cache file in a
// temp directory, so the binding, follow-up, restart and offline paths are covered without a network call.
@ExperimentalSerializationApi
internal class CachingPostFunctionTest {

    private val transmissionKey = ByteArray(32) { it.toByte() }
    private val dir = Files.createTempDirectory("ksm_cache_test_").toFile()
    private val cacheFile = File(dir, "cache.dat")
    private val configFile = File(dir, "config.json")

    private val keyPair = generateKeyPair()
    private val signer = RequestSigner { data ->
        Signature.getInstance("SHA256withECDSA").run { initSign(keyPair.private); update(data); sign() }
    }
    private val appKey = getRandomBytes(32)
    private var offline = false
    private var postCalls = 0

    @AfterTest
    fun cleanUp() {
        dir.deleteRecursively()
    }

    private fun bindResponse(storage: KeyValueStorage): String {
        val encrypted = bytesToBase64(encrypt(appKey, storage.getBytes(KEY_CLIENT_KEY)!!))
        return """{"encryptedAppKey":"$encrypted","folders":null,"records":[]}"""
    }

    private val boundResponse = """{"encryptedAppKey":null,"folders":null,"records":[]}"""

    private fun newStorage(storage: KeyValueStorage): KeyValueStorage {
        val clientKey = Base64.getUrlEncoder().withoutPadding().encodeToString(getRandomBytes(32))
        initializeStorage(storage, "US:$clientKey", null, extractPublicRaw(keyPair.public))
        return storage
    }

    // The first post is the binding request when the client is unbound, every later one is a bound request.
    // beforePost runs with the 0-based call index, so a test can look at the cache file at that moment.
    private fun options(
        storage: KeyValueStorage,
        protector: AppKeyProtector? = null,
        beforePost: (Int) -> Unit = {}
    ): SecretsManagerOptions {
        TestStubs.transmissionKeyStub = { transmissionKey }
        val post: (String, TransmissionKey, EncryptedPayload) -> KeeperHttpResponse = { _, tk, _ ->
            val index = postCalls++
            beforePost(index)
            if (offline) throw IOException("network unreachable")
            val body = if (storage.getBytes(KEY_APP_KEY) == null && storage.getBytes(KEY_APP_KEY_WRAPPED) == null) bindResponse(storage) else boundResponse
            KeeperHttpResponse(200, encrypt(stringToBytes(body), tk.key))
        }
        return SecretsManagerOptions(
            storage,
            queryFunction = { url, tk, payload -> cachingPostFunction(url, tk, payload, post, cacheFile) },
            signer = signer,
            appKeyProtector = protector
        )
    }

    private fun cachedResponseJson(): String {
        val cached = cacheFile.readBytes()
        return bytesToString(decrypt(cached.copyOfRange(32, cached.size), cached.copyOfRange(0, 32)))
    }

    @Test
    fun theBindingResponseIsNotCachedAndTheFollowUpIs() {
        val storage = newStorage(InMemoryStorage())
        val options = options(storage) { index ->
            // Call 0 is the binding request. Call 1 is the follow-up fetch, and by then the binding
            // response must not be on disk, because the client key in the config opens it.
            if (index == 1) assertFalse(cacheFile.exists(), "the binding response was cached")
        }

        getSecrets(options)

        assertEquals(2, postCalls, "one binding request and one follow-up")
        assertTrue(cacheFile.exists(), "the follow-up response must be cached")
        assertTrue(cachedResponseJson().contains("\"encryptedAppKey\":null"), "the cached response must not carry the app key")
    }

    @Test
    fun anOfflineRunServesTheCachedFollowUp() {
        val storage = newStorage(InMemoryStorage())
        getSecrets(options(storage))

        offline = true
        val secrets = getSecrets(options(storage))

        assertTrue(secrets.records.isEmpty())
        assertEquals(3, postCalls, "the offline run still tried the network first")
    }

    @Test
    fun aBindThatFailsToWrapLeavesNoCacheAndKeepsTheClientKey() {
        val storage = newStorage(InMemoryStorage())
        var wraps = 0
        val working = object : AppKeyProtector {
            val key = getRandomBytes(32)
            override fun wrap(appKey: ByteArray) = if (++wraps == 2) throw IllegalStateException("device removed") else encrypt(appKey, key)
            override fun unwrap(wrappedAppKey: ByteArray) = decrypt(wrappedAppKey, key)
        }

        assertFailsWith<SecretsManagerException> { getSecrets(options(storage, working)) }

        assertFalse(cacheFile.exists(), "a cache next to the config would open the app key through the client key")
        assertNotNull(storage.getBytes(KEY_CLIENT_KEY), "the client key must survive so the next run binds")
    }

    @Test
    fun anUnboundClientWithNoCacheFailsOfflineWithAClearMessage() {
        val storage = newStorage(InMemoryStorage())
        offline = true

        val e = assertFailsWith<SecretsManagerException> { getSecrets(options(storage)) }

        assertTrue(e.message!!.contains("no cached data is available"), e.message)
    }

    @Test
    fun aRestartWithTheSameConfigAndCacheWorksOffline() {
        getSecrets(options(newStorage(LocalConfigStorage(configFile.path))))

        offline = true
        val secrets = getSecrets(options(LocalConfigStorage(configFile.path)))

        assertTrue(secrets.records.isEmpty())
        assertTrue(cachedResponseJson().contains("\"encryptedAppKey\":null"))
    }
}
