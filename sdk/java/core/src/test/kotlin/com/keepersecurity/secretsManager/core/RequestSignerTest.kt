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

    private val transmissionKey = ByteArray(32) { it.toByte() }

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

    private class Device {
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
    }

    // Storage initialized with an external public key, plus the app key the server will hand out at binding
    private class Setup(val device: Device = Device()) {
        val storage = InMemoryStorage()
        val appKey = getRandomBytes(32)

        init {
            val clientKey = Base64.getUrlEncoder().withoutPadding().encodeToString(getRandomBytes(32))
            initializeStorage(storage, "US:$clientKey", null, device.publicKey)
        }

        private val encryptedAppKey = bytesToBase64(encrypt(appKey, storage.getBytes(KEY_CLIENT_KEY)!!))
        val bindResponse = """{"encryptedAppKey":"$encryptedAppKey","folders":null,"records":[]}"""
        val boundResponse = """{"encryptedAppKey":null,"folders":null,"records":[]}"""
    }

    // Answers the first request with the bind response and every later one with the bound response
    private fun options(setup: Setup, protector: AppKeyProtector? = null, onRequest: (Int) -> Unit = {}): SecretsManagerOptions {
        TestStubs.transmissionKeyStub = { transmissionKey }
        var call = 0
        return SecretsManagerOptions(setup.storage, queryFunction = { _, _, _ ->
            onRequest(call)
            val response = if (call++ == 0) setup.bindResponse else setup.boundResponse
            KeeperHttpResponse(200, encrypt(stringToBytes(response), transmissionKey))
        }, signer = setup.device.signer, appKeyProtector = protector)
    }

    @Test
    fun externalSignerSignsRequestsAndKeepsItsPublicKey() {
        val setup = Setup()
        assertNull(setup.storage.getString(KEY_PRIVATE_KEY), "no private key may be stored when the key is external")
        val sentPublicKeys = mutableListOf<String?>()
        TestStubs.transmissionKeyStub = { transmissionKey }
        var call = 0
        val options = SecretsManagerOptions(setup.storage, queryFunction = { _, tk, payload ->
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(importPublicKey(setup.device.publicKey))
            verifier.update(tk.encryptedKey + payload.payload)
            assertTrue(verifier.verify(payload.signature), "request signature must verify with the bound public key")
            val request = Json.parseToJsonElement(bytesToString(decrypt(payload.payload, transmissionKey))).jsonObject
            sentPublicKeys.add(request["publicKey"]?.jsonPrimitive?.content)
            val response = if (call++ == 0) setup.bindResponse else setup.boundResponse
            KeeperHttpResponse(200, encrypt(stringToBytes(response), transmissionKey))
        }, signer = setup.device.signer)

        getSecrets(options)

        assertEquals(listOf(bytesToBase64(setup.device.publicKey), null), sentPublicKeys, "the public key is sent only until bound")
        assertContentEquals(setup.device.publicKey, setup.storage.getBytes(KEY_PUBLIC_KEY), "an external key keeps its public key once bound")
        assertContentEquals(setup.appKey, setup.storage.getBytes(KEY_APP_KEY))
        assertEquals("Test token, slot 1", setup.storage.getString(KEY_PRIVATE_KEY_LOCATION))
    }

    @Test
    fun appKeyIsStoredOnlyWrappedAndSignerLearnsTheTitleOnce() {
        val setup = Setup()
        val appData = webSafe64FromBytes(encrypt(stringToBytes("""{"title":"Production App","type":"General"}"""), setup.appKey))
        val responses = listOf(
            """{"encryptedAppKey":"${bytesToBase64(encrypt(setup.appKey, setup.storage.getBytes(KEY_CLIENT_KEY)!!))}","appData":"$appData","folders":null,"records":[]}""",
            """{"encryptedAppKey":null,"appData":"$appData","folders":null,"records":[]}"""
        )
        val bound = mutableListOf<String>()
        val signer = object : RequestSigner {
            override fun sign(data: ByteArray) = ByteArray(64)
            override fun onBound(appData: AppData) { bound.add(appData.title) }
        }
        val protector = TestProtector()
        TestStubs.transmissionKeyStub = { transmissionKey }
        var call = 0
        val options = SecretsManagerOptions(setup.storage, queryFunction = { _, _, _ ->
            KeeperHttpResponse(200, encrypt(stringToBytes(responses[minOf(call++, 1)]), transmissionKey))
        }, signer = signer, appKeyProtector = protector)

        assertEquals("Production App", getSecrets(options).appData.title)
        assertNull(setup.storage.getString(KEY_APP_KEY), "the plain app key must not be stored")
        assertContentEquals(setup.appKey, protector.unwrap(setup.storage.getBytes(KEY_APP_KEY_WRAPPED)!!))
        getSecrets(options)
        assertEquals(listOf("Production App"), bound, "onBound runs once, at binding")
    }

    @Test
    fun wrapFailureAtBindingStoresNothingAndTheNextRunBinds() {
        val setup = Setup()
        val working = TestProtector()
        // The preflight wrap (call 1) succeeds. The wrap at binding (call 2) fails, as if the device was unplugged.
        var wraps = 0
        val flaky = object : AppKeyProtector {
            override fun wrap(appKey: ByteArray) = if (++wraps == 2) throw IllegalStateException("device removed") else working.wrap(appKey)
            override fun unwrap(wrappedAppKey: ByteArray) = working.unwrap(wrappedAppKey)
        }

        val ex = assertFailsWith<SecretsManagerException> { getSecrets(options(setup, flaky)) }
        assertTrue(ex.message!!.contains("Nothing was stored, so run the command again"), ex.message)
        assertNull(setup.storage.getString(KEY_APP_KEY), "a failed wrap must not fall back to the plain app key")
        assertNull(setup.storage.getString(KEY_APP_KEY_WRAPPED))
        assertNotNull(setup.storage.getString(KEY_CLIENT_KEY), "the client key must survive so the next run can bind")

        getSecrets(options(setup, working))
        assertContentEquals(setup.appKey, working.unwrap(setup.storage.getBytes(KEY_APP_KEY_WRAPPED)!!))
    }

    @Test
    fun protectorThatCannotWrapFailsBeforeAnyRequest() {
        val setup = Setup()
        var requests = 0
        val broken = object : AppKeyProtector {
            override fun wrap(appKey: ByteArray): ByteArray = throw SecretsManagerException("This device has no wrapping key")
            override fun unwrap(wrappedAppKey: ByteArray): ByteArray = throw IllegalStateException("unexpected")
        }

        val ex = assertFailsWith<SecretsManagerException> { getSecrets(options(setup, broken) { requests++ }) }

        assertEquals(0, requests, "nothing may reach the server")
        assertTrue(ex.message!!.contains("This device has no wrapping key"), "a Keeper exception message is shown: ${ex.message}")
        assertTrue(ex.message!!.contains("Nothing was sent to Keeper"), ex.message)
    }

    @Test
    fun foreignProtectorMessagesAreNotEchoed() {
        val setup = Setup()
        val leaky = object : AppKeyProtector {
            override fun wrap(appKey: ByteArray): ByteArray = throw RuntimeException("pin=123456")
            override fun unwrap(wrappedAppKey: ByteArray): ByteArray = throw IllegalStateException("unexpected")
        }
        val ex = assertFailsWith<SecretsManagerException> { getSecrets(options(setup, leaky)) }
        assertFalse(ex.message!!.contains("123456"), "only the class name of a foreign exception may appear")
        assertTrue(ex.message!!.contains("RuntimeException"), ex.message)
        assertEquals("pin=123456", ex.cause!!.message, "the full cause stays attached")
    }

    @Test
    fun wrappedAndPlainKeysAreHandledStrictly() {
        val protector = TestProtector()
        fun load(withPlain: Boolean, withWrapped: Boolean, useProtector: Boolean): String? {
            val setup = Setup()
            if (withPlain) setup.storage.saveBytes(KEY_APP_KEY, setup.appKey)
            if (withWrapped) setup.storage.saveBytes(KEY_APP_KEY_WRAPPED, protector.wrap(setup.appKey))
            return try {
                getSecrets(options(setup, if (useProtector) protector else null).copy(queryFunction = { _, _, _ ->
                    KeeperHttpResponse(200, encrypt(stringToBytes(setup.boundResponse), transmissionKey))
                }))
                null
            } catch (e: SecretsManagerException) {
                e.message
            }
        }
        assertNull(load(withPlain = false, withWrapped = true, useProtector = true))
        assertNull(load(withPlain = true, withWrapped = false, useProtector = false), "a plain key without a protector keeps working")
        assertTrue(load(withPlain = false, withWrapped = true, useProtector = false)!!.contains("Pass the app key protector"))
        assertTrue(load(withPlain = true, withWrapped = false, useProtector = true)!!.contains("migrateAppKeyToProtector"))
        assertTrue(load(withPlain = true, withWrapped = true, useProtector = true)!!.contains("both a plain and a wrapped"))
    }

    @Test
    fun migrateWrapsChecksAndDeletesThePlainKey() {
        val setup = Setup()
        val protector = TestProtector()
        setup.storage.saveBytes(KEY_APP_KEY, setup.appKey)
        val options = SecretsManagerOptions(setup.storage, appKeyProtector = protector)

        migrateAppKeyToProtector(options)
        assertNull(setup.storage.getString(KEY_APP_KEY))
        assertContentEquals(setup.appKey, protector.unwrap(setup.storage.getBytes(KEY_APP_KEY_WRAPPED)!!))

        // An interrupted run leaves both keys. Running again finishes the job.
        setup.storage.saveBytes(KEY_APP_KEY, setup.appKey)
        migrateAppKeyToProtector(options)
        assertNull(setup.storage.getString(KEY_APP_KEY))
    }

    @Test
    fun migrateChangesNothingWhenTheWrappedKeyDoesNotUnwrap() {
        val setup = Setup()
        setup.storage.saveBytes(KEY_APP_KEY, setup.appKey)
        val corrupting = object : AppKeyProtector {
            override fun wrap(appKey: ByteArray) = appKey.copyOf()
            override fun unwrap(wrappedAppKey: ByteArray) = ByteArray(32)
        }
        val ex = assertFailsWith<SecretsManagerException> {
            migrateAppKeyToProtector(SecretsManagerOptions(setup.storage, appKeyProtector = corrupting))
        }
        assertTrue(ex.message!!.contains("The config was not changed"), ex.message)
        assertContentEquals(setup.appKey, setup.storage.getBytes(KEY_APP_KEY))
        assertNull(setup.storage.getString(KEY_APP_KEY_WRAPPED))
    }

    @Test
    fun failureToRecordTheKeyLocationDoesNotFailTheRequest() {
        val setup = Setup()
        val readOnly = object : KeyValueStorage by setup.storage {
            override fun saveString(key: String, value: String) {
                if (key == KEY_PRIVATE_KEY_LOCATION) throw java.io.IOException("read-only file system")
                setup.storage.saveString(key, value)
            }
        }
        val opts = options(setup).copy(storage = readOnly)
        getSecrets(opts)
        assertContentEquals(setup.appKey, setup.storage.getBytes(KEY_APP_KEY))
    }

    @Test
    fun optionsToStringShowsOnlyClassNames() {
        val secretSigner = object : RequestSigner {
            override fun sign(data: ByteArray) = ByteArray(0)
            override fun toString() = "pin=123456"
        }
        val text = SecretsManagerOptions(InMemoryStorage(), signer = secretSigner).toString()
        assertFalse(text.contains("123456"))
    }

    @Test
    fun initializeStorageRejectsMalformedPublicKey() {
        val ex = assertFailsWith<SecretsManagerException> {
            initializeStorage(InMemoryStorage(), "US:FAKE_CLIENT_KEY", null, ByteArray(64))
        }
        assertTrue(ex.message!!.contains("65 byte"))
    }

    @Test
    fun publicKeyAndLocationSurviveConfigReload() {
        val file = File.createTempFile("ksm_signer_", ".json")
        file.delete()
        try {
            val publicKey = extractPublicRaw(generateKeyPair().public)
            val storage = LocalConfigStorage(file.path)
            initializeStorage(storage, "US:FAKE_CLIENT_KEY", null, publicKey)
            storage.saveString(KEY_PRIVATE_KEY_LOCATION, "Test token, slot 1")

            val reloaded = LocalConfigStorage(file.path)
            assertContentEquals(publicKey, reloaded.getBytes(KEY_PUBLIC_KEY))
            assertEquals("Test token, slot 1", reloaded.getString(KEY_PRIVATE_KEY_LOCATION))
            assertNull(reloaded.getString(KEY_PRIVATE_KEY))
        } finally {
            file.delete()
        }
    }
}
