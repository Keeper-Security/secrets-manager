package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.security.Signature
import java.util.Base64
import kotlin.test.*

@ExperimentalSerializationApi
internal class RequestSignerTest {

    @Test
    fun externalSignerSignsRequestsAndBindsPublicKey() {
        val transmissionKey = ByteArray(32) { it.toByte() }
        TestStubs.transmissionKeyStub = { transmissionKey }

        val keyPair = generateKeyPair()
        val publicKey = extractPublicRaw(keyPair.public)
        var signCalls = 0
        val signer = object : RequestSigner {
            override fun sign(data: ByteArray): ByteArray {
                signCalls++
                return Signature.getInstance("SHA256withECDSA").run {
                    initSign(keyPair.private)
                    update(data)
                    sign()
                }
            }

            override val keyLocation = "Test token, slot 1"
        }

        val clientKey = Base64.getUrlEncoder().withoutPadding().encodeToString(getRandomBytes(32))
        val storage = InMemoryStorage()
        initializeStorage(storage, "US:$clientKey", publicKey = publicKey)
        assertNull(storage.getString(KEY_PRIVATE_KEY), "no private key may be stored when the key is external")
        assertContentEquals(publicKey, storage.getBytes(KEY_PUBLIC_KEY))

        val appKey = getRandomBytes(32)
        val encryptedAppKey = bytesToBase64(encrypt(appKey, storage.getBytes(KEY_CLIENT_KEY)!!))
        val bindResponse = """{"encryptedAppKey":"$encryptedAppKey","folders":null,"records":[]}"""
        val boundResponse = """{"encryptedAppKey":null,"folders":null,"records":[]}"""

        // getSecrets re-fetches right after binding, so expect two signed requests
        val sentPublicKeys = mutableListOf<String?>()
        val options = SecretsManagerOptions(storage, queryFunction = { _, tk, payload ->
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(importPublicKey(publicKey))
            verifier.update(tk.encryptedKey + payload.payload)
            assertTrue(verifier.verify(payload.signature), "request signature must verify with the bound public key")
            val request = Json.parseToJsonElement(bytesToString(decrypt(payload.payload, transmissionKey))).jsonObject
            sentPublicKeys.add(request["publicKey"]?.jsonPrimitive?.content)
            val response = if (sentPublicKeys.size == 1) bindResponse else boundResponse
            KeeperHttpResponse(200, encrypt(stringToBytes(response), transmissionKey))
        }, signer = signer)

        getSecrets(options)

        assertEquals(2, signCalls)
        assertEquals(listOf(bytesToBase64(publicKey), null), sentPublicKeys)
        assertContentEquals(appKey, storage.getBytes(KEY_APP_KEY))
        assertContentEquals(publicKey, storage.getBytes(KEY_PUBLIC_KEY), "an external key keeps its public key once bound")
        assertEquals("Test token, slot 1", storage.getString(KEY_PRIVATE_KEY_LOCATION), "the SDK records where the key is")
    }

    // Wraps with AES-GCM under a key that never enters the storage
    private class TestProtector : AppKeyProtector {
        val key = getRandomBytes(32)
        var unwrapCalls = 0
        override fun wrap(appKey: ByteArray) = encrypt(appKey, key)
        override fun unwrap(wrappedAppKey: ByteArray): ByteArray {
            unwrapCalls++
            return decrypt(wrappedAppKey, key)
        }
    }

    private fun boundStorage(): Pair<InMemoryStorage, ByteArray> {
        val keyPair = generateKeyPair()
        val clientKey = Base64.getUrlEncoder().withoutPadding().encodeToString(getRandomBytes(32))
        val storage = InMemoryStorage()
        initializeStorage(storage, "US:$clientKey", publicKey = extractPublicRaw(keyPair.public))
        return storage to keyPair.private.encoded
    }

    @Test
    fun appKeyIsWrappedAtBindingAndSignerLearnsTheTitle() {
        val transmissionKey = ByteArray(32) { it.toByte() }
        TestStubs.transmissionKeyStub = { transmissionKey }
        val (storage, _) = boundStorage()
        val appKey = getRandomBytes(32)
        val encryptedAppKey = bytesToBase64(encrypt(appKey, storage.getBytes(KEY_CLIENT_KEY)!!))
        val appData = webSafe64FromBytes(encrypt(stringToBytes("""{"title":"Production App","type":"General"}"""), appKey))
        val responses = listOf(
            """{"encryptedAppKey":"$encryptedAppKey","appData":"$appData","folders":null,"records":[]}""",
            """{"encryptedAppKey":null,"appData":"$appData","folders":null,"records":[]}"""
        )
        val bound = mutableListOf<String>()
        val signer = object : RequestSigner {
            override fun sign(data: ByteArray) = ByteArray(64)
            override fun onBound(appData: AppData) { bound.add(appData.title) }
        }
        val protector = TestProtector()
        var call = 0
        val options = SecretsManagerOptions(storage, queryFunction = { _, _, _ ->
            KeeperHttpResponse(200, encrypt(stringToBytes(responses[minOf(call++, 1)]), transmissionKey))
        }, signer = signer, appKeyProtector = protector)

        assertEquals("Production App", getSecrets(options).appData.title)
        assertEquals(1, protector.unwrapCalls, "the refetch after binding unwraps the app key")
        assertNull(storage.getString(KEY_APP_KEY), "the plain app key must not be stored")
        assertContentEquals(appKey, protector.unwrap(storage.getBytes(KEY_APP_KEY_WRAPPED)!!))
        assertEquals(listOf("Production App"), bound, "onBound runs once, at binding")

        getSecrets(options)
        assertEquals(listOf("Production App"), bound)
    }

    @Test
    fun failedWrappingKeepsThePlainAppKey() {
        val transmissionKey = ByteArray(32) { it.toByte() }
        TestStubs.transmissionKeyStub = { transmissionKey }
        val (storage, _) = boundStorage()
        val appKey = getRandomBytes(32)
        val encryptedAppKey = bytesToBase64(encrypt(appKey, storage.getBytes(KEY_CLIENT_KEY)!!))
        val responses = listOf(
            """{"encryptedAppKey":"$encryptedAppKey","folders":null,"records":[]}""",
            """{"encryptedAppKey":null,"folders":null,"records":[]}"""
        )
        val failing = object : AppKeyProtector {
            override fun wrap(appKey: ByteArray): ByteArray = throw IllegalStateException("no wrapping key")
            override fun unwrap(wrappedAppKey: ByteArray): ByteArray = throw IllegalStateException("unexpected")
        }
        var call = 0
        getSecrets(SecretsManagerOptions(storage, queryFunction = { _, _, _ ->
            KeeperHttpResponse(200, encrypt(stringToBytes(responses[minOf(call++, 1)]), transmissionKey))
        }, signer = { ByteArray(64) }, appKeyProtector = failing))

        assertContentEquals(appKey, storage.getBytes(KEY_APP_KEY), "binding must not lose the app key")
        assertNull(storage.getString(KEY_APP_KEY_WRAPPED))
    }

    @Test
    fun wrappedAppKeyNeedsTheProtector() {
        val transmissionKey = ByteArray(32) { it.toByte() }
        TestStubs.transmissionKeyStub = { transmissionKey }
        val (storage, privateKey) = boundStorage()
        storage.saveBytes(KEY_PRIVATE_KEY, privateKey)
        storage.saveBytes(KEY_APP_KEY_WRAPPED, TestProtector().wrap(getRandomBytes(32)))
        val response = encrypt(stringToBytes("""{"encryptedAppKey":null,"folders":null,"records":[]}"""), transmissionKey)
        val ex = assertFailsWith<SecretsManagerException> {
            getSecrets(SecretsManagerOptions(storage, queryFunction = { _, _, _ -> KeeperHttpResponse(200, response) }))
        }
        assertTrue(ex.message!!.contains("AppKeyProtector"), ex.message)
    }

    @Test
    fun initializeStorageRejectsMalformedPublicKey() {
        val ex = assertFailsWith<SecretsManagerException> {
            initializeStorage(InMemoryStorage(), "US:FAKE_CLIENT_KEY", publicKey = ByteArray(64))
        }
        assertTrue(ex.message!!.contains("65 byte"))
    }

    @Test
    fun publicKeySurvivesConfigReload() {
        val file = File.createTempFile("ksm_signer_", ".json")
        file.delete()
        try {
            val publicKey = extractPublicRaw(generateKeyPair().public)
            val storage = LocalConfigStorage(file.path)
            initializeStorage(storage, "US:FAKE_CLIENT_KEY", publicKey = publicKey)
            storage.saveString(KEY_PRIVATE_KEY_LOCATION, "YubiKey serial 1, PIV slot 82")  // as getSecrets would with a signer
            storage.saveString(KEY_PRIVATE_KEY_PIN, "123456")  // as YubiKeySigner.savePin would

            val reloaded = LocalConfigStorage(file.path)
            assertContentEquals(publicKey, reloaded.getBytes(KEY_PUBLIC_KEY))
            assertEquals("YubiKey serial 1, PIV slot 82", reloaded.getString(KEY_PRIVATE_KEY_LOCATION))
            assertEquals("123456", reloaded.getString(KEY_PRIVATE_KEY_PIN))
            assertEquals("123456", InMemoryStorage(file.readText()).getString(KEY_PRIVATE_KEY_PIN))
            assertNull(reloaded.getString(KEY_PRIVATE_KEY))

            reloaded.delete(KEY_PRIVATE_KEY_PIN)
            assertFalse(file.readText().contains("privateKeyPin"), "removing the PIN removes it from the file")
        } finally {
            file.delete()
        }
    }
}
