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

    private val marker = "SYNTHPIN987654"

    // Authenticated encryption that decrypts inside the buffer it is given, which Java's overlapping
    // AES-GCM call allows, and clears its input when it wraps, as a protector that scrubs key material
    // would. The SDK has to hand such a protector copies and keep its own buffers.
    private class MutatingProtector : AppKeyProtector {
        private val key = javax.crypto.spec.SecretKeySpec(getRandomBytes(32), "AES")

        override fun wrap(appKey: ByteArray): ByteArray {
            val iv = getRandomBytes(12)
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, javax.crypto.spec.GCMParameterSpec(128, iv))
            val wrapped = iv + cipher.doFinal(appKey)
            appKey.fill(0)
            return wrapped
        }

        override fun unwrap(wrappedAppKey: ByteArray): ByteArray {
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, javax.crypto.spec.GCMParameterSpec(128, wrappedAppKey.copyOfRange(0, 12)))
            val written = cipher.doFinal(wrappedAppKey, 12, wrappedAppKey.size - 12, wrappedAppKey, 0)
            return wrappedAppKey.copyOf(written)
        }
    }

    // Hands out the arrays it holds instead of copies, as a storage backed by a shared buffer would.
    private class BufferStorage : KeyValueStorage {
        private val strings = HashMap<String, String>()
        private val buffers = HashMap<String, ByteArray>()
        override fun saveString(key: String, value: String) { strings[key] = value }
        override fun getString(key: String) = strings[key]
        override fun saveBytes(key: String, value: ByteArray) { buffers[key] = value }
        override fun getBytes(key: String) = buffers[key]
        override fun delete(key: String) { strings.remove(key); buffers.remove(key) }
    }

    // Keeps string and byte values apart, as a storage may when it has no single representation.
    private class SplitStorage : KeyValueStorage {
        private val strings = HashMap<String, String>()
        private val buffers = HashMap<String, ByteArray>()
        override fun saveString(key: String, value: String) { strings[key] = value }
        override fun getString(key: String) = strings[key]
        override fun saveBytes(key: String, value: ByteArray) { buffers[key] = value.copyOf() }
        override fun getBytes(key: String) = buffers[key]?.copyOf()
        override fun delete(key: String) { strings.remove(key); buffers.remove(key) }
    }

    // Fails the chosen call with the chosen throwable and otherwise wraps like TestProtector.
    private class FailingProtector(val failure: (op: String, call: Int) -> Throwable?) : AppKeyProtector {
        val working = TestProtector()
        private var wraps = 0
        private var unwraps = 0
        override fun wrap(appKey: ByteArray): ByteArray {
            failure("wrap", ++wraps)?.let { throw it }
            return working.wrap(appKey)
        }
        override fun unwrap(wrappedAppKey: ByteArray): ByteArray {
            failure("unwrap", ++unwraps)?.let { throw it }
            return working.unwrap(wrappedAppKey)
        }
    }

    private fun captureConsole(block: () -> Unit): String {
        val out = System.out
        val err = System.err
        val buffer = java.io.ByteArrayOutputStream()
        val stream = java.io.PrintStream(buffer, true)
        System.setOut(stream)
        System.setErr(stream)
        try {
            block()
        } finally {
            System.setOut(out)
            System.setErr(err)
        }
        return buffer.toString()
    }

    // Storage initialized with an external public key, plus the app key the server will hand out at binding
    private class Setup(val device: Device = Device(), val storage: KeyValueStorage = InMemoryStorage()) {
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
        assertTrue(ex.message!!.contains("SecretsManagerException"), "the failure class is named: ${ex.message}")
        assertFalse(ex.message!!.contains("no wrapping key"), "the protector's own text is not shown: ${ex.message}")
        assertTrue(ex.message!!.contains("Nothing was sent to Keeper"), ex.message)
    }

    @Test
    fun protectorFailuresCarryNoTextFromTheProtectorInAnyPath() {
        // Every path that calls the protector, with a failure that carries the marker in its message, its
        // cause and a suppressed exception, and with the public Keeper exception type. The whole rendered
        // throwable is checked, since a stack trace prints every cause.
        fun leaky(kind: String): Throwable = if (kind == "foreign") {
            IllegalStateException("pin=$marker", RuntimeException("inner $marker").also { it.addSuppressed(RuntimeException("suppressed $marker")) })
        } else {
            SecretsManagerException("pin=$marker", RuntimeException("inner $marker"))
        }
        val paths = mapOf<String, (Throwable) -> Throwable>(
            "preflight wrap" to { error ->
                assertFailsWith<SecretsManagerException> { getSecrets(options(Setup(), FailingProtector { op, call -> if (op == "wrap" && call == 1) error else null })) }
            },
            "wrap at binding" to { error ->
                assertFailsWith<SecretsManagerException> { getSecrets(options(Setup(), FailingProtector { op, call -> if (op == "wrap" && call == 2) error else null })) }
            },
            "unwrap when loading" to { error ->
                val setup = Setup()
                val protector = FailingProtector { op, _ -> if (op == "unwrap") error else null }
                setup.storage.saveBytes(KEY_APP_KEY_WRAPPED, protector.working.wrap(setup.appKey))
                assertFailsWith<SecretsManagerException> {
                    getSecrets(options(setup, protector).copy(queryFunction = { _, _, _ ->
                        KeeperHttpResponse(200, encrypt(stringToBytes(setup.boundResponse), transmissionKey))
                    }))
                }
            },
            "migration" to { error ->
                val setup = Setup()
                setup.storage.saveBytes(KEY_APP_KEY, setup.appKey)
                assertFailsWith<SecretsManagerException> {
                    migrateAppKeyToProtector(SecretsManagerOptions(setup.storage, appKeyProtector = FailingProtector { op, _ -> if (op == "wrap") error else null }))
                }
            }
        )
        for (kind in listOf("foreign", "keeper")) {
            for ((path, run) in paths) {
                val rendered = run(leaky(kind)).stackTraceToString()
                assertFalse(rendered.contains(marker), "$kind failure leaked into the $path throwable: $rendered")
                assertTrue(rendered.contains(if (kind == "foreign") "IllegalStateException" else "SecretsManagerException"), "$path must keep the failure class")
            }
        }
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

    @Test
    fun migrationKeepsTheEnvelopeWhenTheProtectorMutatesItsBuffers() {
        val setup = Setup()
        val protector = MutatingProtector()
        setup.storage.saveBytes(KEY_APP_KEY, setup.appKey)

        migrateAppKeyToProtector(SecretsManagerOptions(setup.storage, appKeyProtector = protector))

        val saved = setup.storage.getBytes(KEY_APP_KEY_WRAPPED)!!
        assertFalse(saved.copyOf(32).contentEquals(setup.appKey), "the saved envelope starts with the plain app key")
        assertContentEquals(setup.appKey, protector.unwrap(saved.copyOf()), "the saved envelope no longer unwraps")
        assertNull(setup.storage.getString(KEY_APP_KEY))
    }

    @Test
    fun bindingKeepsUsingTheAppKeyAfterAProtectorScrubsItsInput() {
        val setup = Setup()
        val appData = webSafe64FromBytes(encrypt(stringToBytes("""{"title":"Production App","type":"General"}"""), setup.appKey))
        val responses = listOf(
            """{"encryptedAppKey":"${bytesToBase64(encrypt(setup.appKey, setup.storage.getBytes(KEY_CLIENT_KEY)!!))}","appData":"$appData","folders":null,"records":[]}""",
            """{"encryptedAppKey":null,"appData":"$appData","folders":null,"records":[]}"""
        )
        TestStubs.transmissionKeyStub = { transmissionKey }
        var call = 0
        val options = SecretsManagerOptions(setup.storage, queryFunction = { _, _, _ ->
            KeeperHttpResponse(200, encrypt(stringToBytes(responses[minOf(call++, 1)]), transmissionKey))
        }, signer = setup.device.signer, appKeyProtector = MutatingProtector())

        assertEquals("Production App", getSecrets(options).appData.title)
    }

    @Test
    fun loadingDoesNotLetAnInPlaceUnwrapCorruptTheStoredEnvelope() {
        val setup = Setup(storage = BufferStorage())
        val options = options(setup, MutatingProtector())

        getSecrets(options)
        getSecrets(options)
        getSecrets(options)
    }

    @Test
    fun bindingResponseIsNeverCachedAndOrdinaryResponsesStillAre() {
        val setup = Setup()
        val key = TransmissionKey(1, transmissionKey, ByteArray(0))
        val saved = mutableListOf<ByteArray>()
        fun cache(data: ByteArray) = cacheResponse(key, KeeperHttpResponse(200, data)) { saved.add(it) }

        // The binding response carries the encrypted app key, and the client key that stays in the
        // config opens it. A cache next to a config must not be able to recover the app key.
        cache(encrypt(stringToBytes(setup.bindResponse), transmissionKey))
        assertTrue(saved.isEmpty(), "the binding response was cached")
        cache(getRandomBytes(40))
        assertTrue(saved.isEmpty(), "a response that cannot be read must not be cached")

        cache(encrypt(stringToBytes(setup.boundResponse), transmissionKey))
        assertEquals(1, saved.size, "an ordinary response is cached")
    }

    @Test
    fun signerFailureTextNeverReachesTheLogOrTheException() {
        // Binding succeeds. The signer then fails on the fetch that follows binding, where the SDK logs the failure.
        val setup = Setup()
        var signs = 0
        val failsAfterBinding = object : RequestSigner {
            override fun sign(data: ByteArray): ByteArray {
                if (++signs > 1) throw IllegalStateException("token error pin=$marker")
                return setup.device.signer.sign(data)
            }
        }
        val console = captureConsole { getSecrets(options(setup).copy(signer = failsAfterBinding)) }
        assertFalse(console.contains(marker), "the SDK log echoed the signer failure: $console")

        // The first request fails: the thrown exception is the only place the text could appear.
        val failsAtOnce = object : RequestSigner {
            override fun sign(data: ByteArray): ByteArray =
                throw IllegalStateException("token error pin=$marker", RuntimeException("inner $marker"))
        }
        val e = assertFailsWith<SecretsManagerException> { getSecrets(options(Setup()).copy(signer = failsAtOnce)) }
        val rendered = e.stackTraceToString()
        assertFalse(rendered.contains(marker), "the throwable echoed the signer failure: $rendered")
        assertTrue(rendered.contains("IllegalStateException"), "the failure class must be kept")
    }

    @Test
    fun boundClientsOnAStorageThatSeparatesBytesFromStringsNeverAskForAPublicKey() {
        // A bound client holds its app key as bytes only. Checking for it through getString would read
        // it as unbound and demand a public key that a bound client no longer has.
        val device = Device()
        val protector = TestProtector()
        for (wrapped in listOf(false, true)) {
            val setup = Setup(device, SplitStorage())
            setup.storage.delete(KEY_PUBLIC_KEY)
            setup.storage.delete(KEY_CLIENT_KEY)
            if (wrapped) setup.storage.saveBytes(KEY_APP_KEY_WRAPPED, protector.wrap(setup.appKey))
            else setup.storage.saveBytes(KEY_APP_KEY, setup.appKey)
            var requests = 0
            var wraps = 0
            val counting = object : AppKeyProtector {
                override fun wrap(appKey: ByteArray): ByteArray { wraps++; return protector.wrap(appKey) }
                override fun unwrap(wrappedAppKey: ByteArray) = protector.unwrap(wrappedAppKey)
            }
            TestStubs.transmissionKeyStub = { transmissionKey }

            getSecrets(SecretsManagerOptions(setup.storage, queryFunction = { _, _, _ ->
                requests++
                KeeperHttpResponse(200, encrypt(stringToBytes(setup.boundResponse), transmissionKey))
            }, signer = device.signer, appKeyProtector = if (wrapped) counting else null))

            assertEquals(1, requests, "wrapped=$wrapped must send one request")
            assertEquals(0, wraps, "wrapped=$wrapped must not run the binding preflight again")
        }
    }

    @Test
    fun bindingOnAStorageThatSeparatesBytesFromStringsDeletesTheClientPublicKey() {
        // A client with its own private key (no external signer) deletes its public key once bound.
        // The private key lives as bytes only here, so a string lookup would miss it and keep the public key.
        val storage = SplitStorage()
        val clientKey = Base64.getUrlEncoder().withoutPadding().encodeToString(getRandomBytes(32))
        initializeStorage(storage, "US:$clientKey", null)
        assertNotNull(storage.getBytes(KEY_PRIVATE_KEY))
        val bind = """{"encryptedAppKey":"${bytesToBase64(encrypt(getRandomBytes(32), storage.getBytes(KEY_CLIENT_KEY)!!))}","folders":null,"records":[]}"""
        TestStubs.transmissionKeyStub = { transmissionKey }

        getSecrets(SecretsManagerOptions(storage, queryFunction = { _, _, _ ->
            KeeperHttpResponse(200, encrypt(stringToBytes(bind), transmissionKey))
        }))

        assertNull(storage.getBytes(KEY_PUBLIC_KEY), "a bound client must not keep its one-time public key")
    }
}
