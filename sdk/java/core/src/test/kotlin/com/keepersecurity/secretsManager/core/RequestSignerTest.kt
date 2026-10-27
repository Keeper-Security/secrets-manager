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

    // Fails the first delete or save of the chosen key with an IO error and then behaves normally, as a full
    // disk or a read-only mount would for one write.
    private class FailingStorage(
        private val delegate: KeyValueStorage,
        private val failDelete: String? = null,
        private val failSave: String? = null
    ) : KeyValueStorage by delegate {
        var failed = false
        override fun delete(key: String) {
            if (!failed && key == failDelete) { failed = true; throw java.io.IOException("disk error") }
            delegate.delete(key)
        }
        override fun saveBytes(key: String, value: ByteArray) {
            if (!failed && key == failSave) { failed = true; throw java.io.IOException("disk error") }
            delegate.saveBytes(key, value)
        }
    }

    // A software-key config as it looks when a bind was interrupted: it still holds the one-time bootstrap
    // keys (client key, and the public key that goes with the private key) next to the app key.
    private fun interruptedSoftwareKeyConfig(storage: KeyValueStorage, appKey: ByteArray): KeyValueStorage {
        val clientKey = Base64.getUrlEncoder().withoutPadding().encodeToString(getRandomBytes(32))
        initializeStorage(storage, "US:$clientKey", null)
        storage.saveBytes(KEY_APP_KEY, appKey)
        return storage
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
        // The mutating protector scrubs its input, so binding must keep using its own copy of the app key.
        for (protector in listOf(TestProtector(), MutatingProtector())) {
            val name = protector.javaClass.simpleName
            val setup = Setup()
            val bound = mutableListOf<String>()
            val signer = object : RequestSigner {
                override fun sign(data: ByteArray) = ByteArray(64)
                override fun onBound(appData: AppData) { bound.add(appData.title) }
            }
            val options = titledBindingOptions(setup, protector, signer)

            assertEquals("Production App", getSecrets(options).appData.title, name)
            assertNull(setup.storage.getString(KEY_APP_KEY), "$name: the plain app key must not be stored")
            assertContentEquals(setup.appKey, protector.unwrap(setup.storage.getBytes(KEY_APP_KEY_WRAPPED)!!.copyOf()), "$name: the wrapped key must unwrap")
            getSecrets(options)
            assertEquals(listOf("Production App"), bound, "$name: onBound runs once, at binding")
        }
    }

    // Binding response first, then bound responses, all carrying the app title
    private fun titledBindingOptions(setup: Setup, protector: AppKeyProtector, signer: RequestSigner): SecretsManagerOptions {
        val appData = webSafe64FromBytes(encrypt(stringToBytes("""{"title":"Production App","type":"General"}"""), setup.appKey))
        val responses = listOf(
            """{"encryptedAppKey":"${bytesToBase64(encrypt(setup.appKey, setup.storage.getBytes(KEY_CLIENT_KEY)!!))}","appData":"$appData","folders":null,"records":[]}""",
            """{"encryptedAppKey":null,"appData":"$appData","folders":null,"records":[]}"""
        )
        TestStubs.transmissionKeyStub = { transmissionKey }
        var call = 0
        return SecretsManagerOptions(setup.storage, queryFunction = { _, _, _ ->
            KeeperHttpResponse(200, encrypt(stringToBytes(responses[minOf(call++, 1)]), transmissionKey))
        }, signer = signer, appKeyProtector = protector)
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

    // Every path that calls the protector. Each entry makes the protector fail with the given throwable and returns
    // what the SDK threw.
    private fun protectorFailurePaths() = mapOf<String, (Throwable) -> Throwable>(
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
        val paths = protectorFailurePaths()
        for (kind in listOf("foreign", "keeper")) {
            for ((path, run) in paths) {
                val rendered = run(leaky(kind)).stackTraceToString()
                assertFalse(rendered.contains(marker), "$kind failure leaked into the $path throwable: $rendered")
                val kept = if (kind == "foreign") listOf("java.lang.IllegalStateException", "java.lang.RuntimeException") else listOf("java.lang.RuntimeException")
                for (name in kept) {
                    assertTrue(rendered.contains(name), "$kind failure in the $path throwable lost the original class $name: $rendered")
                }
            }
        }
    }

    // Named, because the error text uses the simple class name, which is empty for anonymous and local classes.
    private class DeviceMessageException(message: String, cause: Throwable? = null) : SafeMessageException(message, cause)

    @Test
    fun aSafeMessageFromTheSignerIsShownWithoutItsCauses() {
        val signer = RequestSigner { throw DeviceMessageException("Wrong PIN, 2 retries left", RuntimeException("inner $marker")) }
        val e = assertFailsWith<SecretsManagerException> { getSecrets(options(Setup()).copy(signer = signer)) }
        assertEquals("The request signer failed (DeviceMessageException: Wrong PIN, 2 retries left). This request was not sent.", e.message)
        val rendered = e.stackTraceToString()
        assertFalse(rendered.contains(marker), "the text of a cause reached the throwable: $rendered")
        assertTrue(rendered.contains("java.lang.RuntimeException"), "the class of the cause must be kept: $rendered")
    }

    @Test
    fun aSafeMessageFromTheProtectorIsShownInEveryPath() {
        for ((path, run) in protectorFailurePaths()) {
            val e = run(DeviceMessageException("This device has no wrapping key", RuntimeException("inner $marker")))
            assertTrue(e.message!!.contains("(DeviceMessageException: This device has no wrapping key)"), "$path: ${e.message}")
            assertFalse(e.stackTraceToString().contains(marker), "$path: the text of a cause reached the throwable")
        }
    }

    @Test
    fun onlyTheTopExceptionCanMarkItsTextAsSafe() {
        // A safe exception lower in the chain must not show the text of the exception that wraps it, or its own text
        val signer = RequestSigner { throw IllegalStateException("token error pin=$marker", DeviceMessageException("safe text")) }
        val e = assertFailsWith<SecretsManagerException> { getSecrets(options(Setup()).copy(signer = signer)) }
        assertEquals("The request signer failed (IllegalStateException). This request was not sent.", e.message)
        val rendered = e.stackTraceToString()
        assertFalse(rendered.contains(marker) || rendered.contains("safe text"), "hidden text reached the throwable: $rendered")
    }

    @Test
    fun aSafeMessageIsCleanedAndCut() {
        // A line break, a terminal escape and a right-to-left override, then more text than the SDK shows
        val signer = RequestSigner { throw DeviceMessageException("Reader\nbusy\u001B[2J\u202Eend " + "x".repeat(2000)) }
        val message = assertFailsWith<SecretsManagerException> { getSecrets(options(Setup()).copy(signer = signer)) }.message!!
        assertTrue(message.startsWith("The request signer failed (DeviceMessageException: Reader busy [2J end xxx"), message)
        assertFalse(message.any { Character.isISOControl(it) || Character.getType(it) == Character.FORMAT.toInt() }, "a control or format character was shown: $message")
        val shown = message.substringAfter("DeviceMessageException: ").substringBefore("). This request was not sent.")
        assertEquals(503, shown.length, "the text is cut after 500 characters and marked: $shown")
        assertTrue(shown.endsWith("x..."), shown)
    }

    @Test
    fun aSafeMessageIsCutWithoutSplittingACharacter() {
        // The 500th character is the first half of a surrogate pair, so the cut moves before it
        val signer = RequestSigner { throw DeviceMessageException("a".repeat(499) + "\uD83D\uDD11" + "b".repeat(10)) }
        val message = assertFailsWith<SecretsManagerException> { getSecrets(options(Setup()).copy(signer = signer)) }.message!!
        val shown = message.substringAfter("DeviceMessageException: ").substringBefore("). This request was not sent.")
        assertEquals("a".repeat(499) + "...", shown)
    }

    @Test
    fun aSafeMessageWithNoTextShowsTheClassNameOnly() {
        val signer = RequestSigner { throw DeviceMessageException(" \n\t ") }
        val e = assertFailsWith<SecretsManagerException> { getSecrets(options(Setup()).copy(signer = signer)) }
        assertEquals("The request signer failed (DeviceMessageException). This request was not sent.", e.message)
    }

    @Test
    fun aSafeMessageFromOnBoundOrTheKeyLocationReachesTheLog() {
        val setup = Setup()
        val signer = object : RequestSigner {
            override fun sign(data: ByteArray) = setup.device.signer.sign(data)
            override val keyLocation: String?
                get() = throw DeviceMessageException("Reader busy")
            override fun onBound(appData: AppData) {
                throw DeviceMessageException("Could not name the key")
            }
        }
        val console = captureConsole { getSecrets(options(setup).copy(signer = signer)) }
        assertTrue(console.contains("Signer failed to process the binding: DeviceMessageException: Could not name the key"), console)
        assertTrue(console.contains("Could not record where the private key is kept (DeviceMessageException: Reader busy)"), console)
    }

    @Test
    fun wrappedAndPlainKeysAreHandledStrictly() {
        val protector = TestProtector()
        // label, plain key stored, wrapped key stored, protector set, expected message substring (null: loads fine)
        val rows = listOf(
            listOf("wrapped key with a protector", false, true, true, null),
            listOf("wrapped key without a protector", false, true, false, "Pass the app key protector"),
            listOf("plain key with a protector", true, false, true, "migrateAppKeyToProtector"),
            listOf("plain and wrapped keys with a protector", true, true, true, "both a plain and a wrapped")
        )
        for (row in rows) {
            val label = row[0] as String
            val setup = Setup()
            if (row[1] as Boolean) setup.storage.saveBytes(KEY_APP_KEY, setup.appKey)
            if (row[2] as Boolean) setup.storage.saveBytes(KEY_APP_KEY_WRAPPED, protector.wrap(setup.appKey))
            val message = try {
                getSecrets(options(setup, if (row[3] as Boolean) protector else null).copy(queryFunction = { _, _, _ ->
                    KeeperHttpResponse(200, encrypt(stringToBytes(setup.boundResponse), transmissionKey))
                }))
                null
            } catch (e: SecretsManagerException) {
                e.message ?: "(no message)"
            }
            val expected = row[4] as String?
            if (expected == null) {
                assertNull(message, "$label: must load, got: $message")
            } else {
                assertTrue(message?.contains(expected) == true, "$label: expected a message containing '$expected', got: $message")
            }
        }
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
        assertContentEquals(setup.appKey, protector.unwrap(setup.storage.getBytes(KEY_APP_KEY_WRAPPED)!!), "the wrapped key no longer unwraps after the rerun")
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

    // Nested and named: the options text uses the simple class name, which is empty for anonymous and local classes.
    private class PinSigner : RequestSigner {
        override fun sign(data: ByteArray) = ByteArray(0)
        override fun toString() = "pin=123456"
    }

    @Test
    fun optionsToStringShowsOnlyClassNames() {
        val secretSigner = PinSigner()
        val text = SecretsManagerOptions(InMemoryStorage(), signer = secretSigner).toString()
        assertFalse(text.contains("123456"))
        assertTrue(text.contains("signer=PinSigner"), "the signer class name is shown: $text")
    }

    @Test
    fun initializeStorageRejectsMalformedPublicKey() {
        val notUncompressed = ByteArray(65).also { it[0] = 0x05 }
        for ((label, badKey) in listOf("64 bytes" to ByteArray(64), "65 bytes without the 0x04 prefix" to notUncompressed)) {
            val storage = InMemoryStorage()
            val ex = assertFailsWith<SecretsManagerException>(label) {
                initializeStorage(storage, "US:FAKE_CLIENT_KEY", null, badKey)
            }
            assertTrue(ex.message?.contains("65 byte") == true, "$label: ${ex.message}")
            assertNull(storage.getString(KEY_HOSTNAME), "$label: nothing may be stored")
        }
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
    fun loadingDoesNotLetAnInPlaceUnwrapCorruptTheStoredEnvelope() {
        val setup = Setup(storage = BufferStorage())

        // The first call binds, the next two load the stored envelope, where an in-place unwrap would corrupt it.
        // Checked after each call, since a corrupted envelope fails the next load with an exception instead.
        val protector = MutatingProtector()
        val options = options(setup, protector)
        for (call in 1..3) {
            getSecrets(options)
            val unwrapped = runCatching { protector.unwrap(setup.storage.getBytes(KEY_APP_KEY_WRAPPED)!!.copyOf()) }.getOrNull()
            assertTrue(unwrapped?.contentEquals(setup.appKey) == true, "after call $call the stored envelope no longer unwraps to the app key")
        }
    }

    @Test
    fun bindingResponseIsNeverCachedAndOrdinaryResponsesStillAre() {
        val setup = Setup()
        val key = TransmissionKey(1, transmissionKey, ByteArray(0))
        val saved = mutableListOf<ByteArray>()
        // Covers cacheResponse, not the one-line call in cachingPostFunction, which would need a network call.
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

    @Test
    fun migrationFinishesAnInterruptedBindAndKeepsWhatABoundConfigNeeds() {
        val protector = TestProtector()
        for (external in listOf(true, false)) {
            val label = if (external) "external key" else "software key"
            val appKey = getRandomBytes(32)
            val storage: KeyValueStorage = if (external) Setup().storage else {
                interruptedSoftwareKeyConfig(InMemoryStorage(), appKey).also { it.delete(KEY_APP_KEY) }
            }
            // The wrap succeeded and was saved, then the run stopped before the bootstrap keys were removed.
            storage.saveBytes(KEY_APP_KEY_WRAPPED, protector.wrap(appKey))

            migrateAppKeyToProtector(SecretsManagerOptions(storage, appKeyProtector = protector))

            assertNull(storage.getBytes(KEY_CLIENT_KEY), "$label: the client key is a leftover")
            assertNull(storage.getBytes(KEY_APP_KEY), "$label: no plain key")
            assertContentEquals(appKey, protector.unwrap(storage.getBytes(KEY_APP_KEY_WRAPPED)!!.copyOf()), "$label: the wrapped key must still unwrap")
            if (external) {
                assertNotNull(storage.getBytes(KEY_PUBLIC_KEY), "$label: the signer finds its key through the public key")
            } else {
                assertNull(storage.getBytes(KEY_PUBLIC_KEY), "$label: the one-time public key is a leftover")
                assertNotNull(storage.getBytes(KEY_PRIVATE_KEY), "$label: the private key stays")
            }
        }
    }

    @Test
    fun migrationRemovesTheBootstrapKeysThatSitNextToAPlainKey() {
        val protector = TestProtector()
        val appKey = getRandomBytes(32)
        val storage = interruptedSoftwareKeyConfig(InMemoryStorage(), appKey)

        migrateAppKeyToProtector(SecretsManagerOptions(storage, appKeyProtector = protector))

        assertNull(storage.getBytes(KEY_APP_KEY))
        assertNull(storage.getBytes(KEY_CLIENT_KEY))
        assertNull(storage.getBytes(KEY_PUBLIC_KEY))
        assertContentEquals(appKey, protector.unwrap(storage.getBytes(KEY_APP_KEY_WRAPPED)!!.copyOf()))
    }

    @Test
    fun migrationOfAnAlreadyCleanWrappedConfigStillSaysThereIsNothingToDo() {
        val setup = Setup()
        val protector = TestProtector()
        setup.storage.delete(KEY_CLIENT_KEY)
        setup.storage.saveBytes(KEY_APP_KEY_WRAPPED, protector.wrap(setup.appKey))

        val e = assertFailsWith<SecretsManagerException> {
            migrateAppKeyToProtector(SecretsManagerOptions(setup.storage, appKeyProtector = protector))
        }

        assertTrue(e.message!!.contains("nothing to migrate"), e.message)
    }

    @Test
    fun aFailedWriteAtAnyStepLeavesAKeyThatCanBeReadAndARetryFinishes() {
        val protector = TestProtector()
        // Each case fails one write. The app key must stay readable (plain or wrapped) after the failure.
        val cases = listOf("save wrapped" to (null to KEY_APP_KEY_WRAPPED), "delete plain" to (KEY_APP_KEY to null),
            "delete client key" to (KEY_CLIENT_KEY to null), "delete public key" to (KEY_PUBLIC_KEY to null))
        for ((label, keys) in cases) {
            val appKey = getRandomBytes(32)
            val base = interruptedSoftwareKeyConfig(InMemoryStorage(), appKey)
            val storage = FailingStorage(base, failDelete = keys.first, failSave = keys.second)
            val options = SecretsManagerOptions(storage, appKeyProtector = protector)

            val e = assertFailsWith<SecretsManagerException>("$label: the failed write must be reported") { migrateAppKeyToProtector(options) }
            assertTrue(e.message!!.contains("Run it again"), "$label: the message must say how to recover: ${e.message}")

            val plain = base.getBytes(KEY_APP_KEY)
            val wrapped = base.getBytes(KEY_APP_KEY_WRAPPED)?.let { protector.unwrap(it.copyOf()) }
            assertContentEquals(appKey, plain ?: wrapped, "$label: the app key must stay readable after the failure")

            migrateAppKeyToProtector(options)

            assertNull(base.getBytes(KEY_APP_KEY), "$label: retry removes the plain key")
            assertNull(base.getBytes(KEY_CLIENT_KEY), "$label: retry removes the client key")
            assertNull(base.getBytes(KEY_PUBLIC_KEY), "$label: retry removes the one-time public key")
            assertContentEquals(appKey, protector.unwrap(base.getBytes(KEY_APP_KEY_WRAPPED)!!.copyOf()), "$label: retry leaves a wrapped key that unwraps")
        }
    }

    @Test
    fun aMigrationInterruptedBeforeTheBootstrapKeysWereRemovedFinishesAfterAReload() {
        val file = File.createTempFile("ksm_migrate_", ".json")
        file.delete()
        try {
            val protector = TestProtector()
            val appKey = getRandomBytes(32)
            interruptedSoftwareKeyConfig(LocalConfigStorage(file.path), appKey)

            val failing = FailingStorage(LocalConfigStorage(file.path), failDelete = KEY_CLIENT_KEY)
            assertFailsWith<SecretsManagerException> {
                migrateAppKeyToProtector(SecretsManagerOptions(failing, appKeyProtector = protector))
            }

            // A new process reads what reached the disk.
            val reloaded = LocalConfigStorage(file.path)
            assertNull(reloaded.getBytes(KEY_APP_KEY), "the plain key is gone from the file")
            assertNotNull(reloaded.getBytes(KEY_CLIENT_KEY), "the interrupted run left the client key")
            migrateAppKeyToProtector(SecretsManagerOptions(reloaded, appKeyProtector = protector))

            val final = LocalConfigStorage(file.path)
            assertNull(final.getBytes(KEY_CLIENT_KEY))
            assertNull(final.getBytes(KEY_PUBLIC_KEY))
            assertNotNull(final.getBytes(KEY_PRIVATE_KEY))
            assertContentEquals(appKey, protector.unwrap(final.getBytes(KEY_APP_KEY_WRAPPED)!!.copyOf()))
        } finally {
            file.delete()
        }
    }

    @Test
    fun migrationKeepsTheLeftoversWhenTheWrappedKeyCannotBeUnwrapped() {
        val appKey = getRandomBytes(32)
        val storage = interruptedSoftwareKeyConfig(InMemoryStorage(), appKey).also { it.delete(KEY_APP_KEY) }
        storage.saveBytes(KEY_APP_KEY_WRAPPED, TestProtector().wrap(appKey))
        val wrongDevice = TestProtector()

        val e = assertFailsWith<SecretsManagerException> {
            migrateAppKeyToProtector(SecretsManagerOptions(storage, appKeyProtector = wrongDevice))
        }

        assertTrue(e.message!!.contains("The config was not changed"), e.message)
        assertNotNull(storage.getBytes(KEY_CLIENT_KEY), "nothing may be deleted when the wrapped key does not check out")
        assertNotNull(storage.getBytes(KEY_PUBLIC_KEY))
    }
}
