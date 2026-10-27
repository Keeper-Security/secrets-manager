package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import java.io.PrintStream
import java.security.Signature
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

// How the SDK treats the hooks a caller supplies (signer, key location, onBound, app key protector) when a
// thread interrupt or a hostile failure reaches them, and who owns the buffers that cross the protector boundary.
@ExperimentalSerializationApi
internal class HookInterruptTest {

    private val transmissionKey = ByteArray(32) { it.toByte() }
    private val marker = "SYNTHPIN987654"

    // Wraps with AES-GCM under a key that never enters the storage
    private class TestProtector : AppKeyProtector {
        val key = getRandomBytes(32)
        override fun wrap(appKey: ByteArray) = encrypt(appKey, key)
        override fun unwrap(wrappedAppKey: ByteArray) = decrypt(wrappedAppKey, key)
    }

    private class Device {
        val keyPair = generateKeyPair()
        val publicKey = extractPublicRaw(keyPair.public)
        val signer = object : RequestSigner {
            override fun sign(data: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
                initSign(keyPair.private)
                update(data)
                sign()
            }

            override val keyLocation = "Test token, slot 1"
        }
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

    // Fails the first delete of the chosen key with an IO error and then behaves normally.
    private class FailingStorage(private val delegate: KeyValueStorage, private val failDelete: String) : KeyValueStorage by delegate {
        override fun delete(key: String) {
            if (key == failDelete) throw java.io.IOException("disk error")
            delegate.delete(key)
        }
    }

    // Returns the same two arrays on every call, as a protector with fixed output buffers would.
    private class ReusingProtector : AppKeyProtector {
        private val key = javax.crypto.spec.SecretKeySpec(getRandomBytes(32), "AES")
        val wrapOut = ByteArray(60)
        val unwrapOut = ByteArray(32)
        override fun wrap(appKey: ByteArray): ByteArray {
            val iv = getRandomBytes(12)
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, javax.crypto.spec.GCMParameterSpec(128, iv))
            (iv + cipher.doFinal(appKey)).copyInto(wrapOut)
            return wrapOut
        }

        override fun unwrap(wrappedAppKey: ByteArray): ByteArray {
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, javax.crypto.spec.GCMParameterSpec(128, wrappedAppKey.copyOfRange(0, 12)))
            cipher.doFinal(wrappedAppKey, 12, wrappedAppKey.size - 12).copyInto(unwrapOut)
            return unwrapOut
        }
    }

    // Answers the first request with the bind response and every later one with the bound response
    private fun options(setup: Setup, protector: AppKeyProtector? = null): SecretsManagerOptions {
        TestStubs.transmissionKeyStub = { transmissionKey }
        var call = 0
        return SecretsManagerOptions(setup.storage, queryFunction = { _, _, _ ->
            val response = if (call++ == 0) setup.bindResponse else setup.boundResponse
            KeeperHttpResponse(200, encrypt(stringToBytes(response), transmissionKey))
        }, signer = setup.device.signer, appKeyProtector = protector)
    }

    private fun <T> captured(block: () -> T): Pair<T, String> {
        val out = System.out
        val err = System.err
        val buffer = java.io.ByteArrayOutputStream()
        val stream = PrintStream(buffer, true)
        System.setOut(stream)
        System.setErr(stream)
        try {
            return block() to buffer.toString()
        } finally {
            System.setOut(out)
            System.setErr(err)
        }
    }

    private val storageKeys = listOf(KEY_HOSTNAME, KEY_SERVER_PUBLIC_KEY_ID, KEY_SERVER_PUBLIC_KEY, KEY_CLIENT_ID, KEY_CLIENT_KEY, KEY_APP_KEY,
        KEY_OWNER_PUBLIC_KEY, KEY_PRIVATE_KEY, KEY_PUBLIC_KEY, KEY_APP_KEY_WRAPPED, KEY_PRIVATE_KEY_LOCATION)

    // Strings and bytes both, since a storage may keep them apart. Reading a text value as bytes can fail, which is not a change.
    private fun snapshot(storage: KeyValueStorage) = storageKeys.associateWith { key ->
        storage.getString(key) to runCatching { storage.getBytes(key)?.toList() }.getOrNull()
    }

    // One place in the SDK where a caller supplied hook runs, each reached by a different public call.
    private enum class Site {
        KEY_LOCATION_ON_GET, KEY_LOCATION_ON_DELETE, KEY_LOCATION_ON_UPDATE, SIGN, PREFLIGHT_WRAP, BIND_WRAP,
        LOAD_UNWRAP, MIGRATE_WRAP, MIGRATE_UNWRAP, ON_BOUND
    }

    private class Scenario(val setup: Setup, val requests: AtomicInteger, val options: SecretsManagerOptions, val call: () -> Unit)

    // Builds the config and the call that reaches [site]. [hook] runs once, when the SDK first reaches that site.
    private fun scenario(site: Site, nullKeyLocation: Boolean = false, secrets2: Boolean = false, hook: () -> Unit): Scenario {
        val setup = Setup()
        val requests = AtomicInteger()
        val fired = AtomicBoolean()
        fun fire() { if (fired.compareAndSet(false, true)) hook() }

        val working = TestProtector()
        var wraps = 0
        val protector = object : AppKeyProtector {
            override fun wrap(appKey: ByteArray): ByteArray {
                wraps++
                // Call 1 is the check before the first request, call 2 is the wrap at binding.
                if ((site == Site.PREFLIGHT_WRAP && wraps == 1) || (site == Site.BIND_WRAP && wraps == 2) || site == Site.MIGRATE_WRAP) fire()
                return working.wrap(appKey)
            }

            override fun unwrap(wrappedAppKey: ByteArray): ByteArray {
                if (site == Site.LOAD_UNWRAP || site == Site.MIGRATE_UNWRAP) fire()
                return working.unwrap(wrappedAppKey)
            }
        }
        val signer = object : RequestSigner {
            override fun sign(data: ByteArray): ByteArray {
                if (site == Site.SIGN) fire()
                return setup.device.signer.sign(data)
            }

            override val keyLocation: String?
                get() {
                    if (site == Site.KEY_LOCATION_ON_GET || site == Site.KEY_LOCATION_ON_DELETE || site == Site.KEY_LOCATION_ON_UPDATE) fire()
                    return if (nullKeyLocation) null else setup.device.signer.keyLocation
                }

            override fun onBound(appData: AppData) {
                if (site == Site.ON_BOUND) fire()
            }
        }

        val migrating = site == Site.MIGRATE_WRAP || site == Site.MIGRATE_UNWRAP
        val bound = site == Site.KEY_LOCATION_ON_DELETE || site == Site.KEY_LOCATION_ON_UPDATE || site == Site.LOAD_UNWRAP
        when {
            site == Site.LOAD_UNWRAP -> setup.storage.saveBytes(KEY_APP_KEY_WRAPPED, working.wrap(setup.appKey))
            bound || migrating -> setup.storage.saveBytes(KEY_APP_KEY, setup.appKey)
        }
        val usesProtector = migrating || site == Site.LOAD_UNWRAP || site == Site.PREFLIGHT_WRAP || site == Site.BIND_WRAP

        TestStubs.transmissionKeyStub = { transmissionKey }
        var call = 0
        val options = SecretsManagerOptions(setup.storage, queryFunction = { _, _, _ ->
            requests.incrementAndGet()
            val response = if (!bound && call++ == 0) setup.bindResponse else setup.boundResponse
            KeeperHttpResponse(200, encrypt(stringToBytes(response), transmissionKey))
        }, signer = signer, appKeyProtector = if (usesProtector) protector else null)

        val uid = "AAAAAAAAAAAAAAAAAAAAAA"
        val run: () -> Unit = when (site) {
            Site.KEY_LOCATION_ON_DELETE -> { { deleteSecret(options, listOf(uid)) } }
            Site.KEY_LOCATION_ON_UPDATE -> { { updateSecret(options, KeeperRecord(getRandomBytes(32), uid, data = KeeperRecordData("t", "login", mutableListOf()), revision = 1)) } }
            Site.MIGRATE_WRAP, Site.MIGRATE_UNWRAP -> { { migrateAppKeyToProtector(options.copy(signer = null)) } }
            else -> { { if (secrets2) getSecrets2(options) else getSecrets(options) } }
        }
        return Scenario(setup, requests, options, run)
    }

    private fun failureOf(scenario: Scenario): Throwable? = try { scenario.call(); null } catch (t: Throwable) { t }

    // How a hook reports that its thread was interrupted. Hooks wrap the interrupt in all three ways.
    private enum class Report { OWN_EXCEPTION, CAUSE_IN_CHAIN, FLAG_RESTORED }

    // A hook that really blocks, so the test can interrupt the thread that is inside it.
    private class Blocker(private val report: Report, private val marker: String) {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        lateinit var scenario: Scenario
        @Volatile var requestsAtEntry = -1
        @Volatile var storageAtEntry: Map<String, Pair<String?, List<Byte>?>>? = null
        @Volatile var failure: Throwable? = null

        fun block(snapshot: (KeyValueStorage) -> Map<String, Pair<String?, List<Byte>?>>) {
            requestsAtEntry = scenario.requests.get()
            storageAtEntry = snapshot(scenario.setup.storage)
            entered.countDown()
            try {
                release.await()
            } catch (interrupted: InterruptedException) {
                val thrown: Throwable = when (report) {
                    Report.OWN_EXCEPTION -> InterruptedException("pin=$marker")
                    Report.CAUSE_IN_CHAIN -> RuntimeException("pin=$marker", InterruptedException("inner $marker"))
                    Report.FLAG_RESTORED -> { Thread.currentThread().interrupt(); IllegalStateException("pin=$marker") }
                }
                failure = thrown
                throw thrown
            }
        }
    }

    private class Outcome(val failure: Throwable?, val flagAfter: Boolean)

    // Runs the call on its own thread, waits until the hook is blocked, interrupts that thread and waits for the
    // call to end. Every wait has a timeout, and the hook is always released, so a regression cannot hang the build.
    private fun interruptInsideHook(blocker: Blocker): Outcome {
        var outcome: Outcome? = null
        val worker = Thread {
            val failure = failureOf(blocker.scenario)
            outcome = Outcome(failure, Thread.currentThread().isInterrupted)
        }
        worker.isDaemon = true
        worker.start()
        try {
            val reached = blocker.entered.await(10, TimeUnit.SECONDS)
            assertTrue(reached, "the hook was never reached, the call ended with ${outcome?.failure}")
            worker.interrupt()
            worker.join(10_000)
            assertFalse(worker.isAlive, "the SDK call is still running 10 seconds after the interrupt")
        } finally {
            blocker.release.countDown()
            worker.join(5_000)
        }
        return outcome!!
    }

    private fun chainOf(e: Throwable) = generateSequence(e) { it.cause }.take(10).toList()

    @Test
    fun aHookInterruptedBeforeASideEffectStopsTheCallWithAnInterruptedExceptionOfTheSdk() {
        val problems = mutableListOf<String>()
        for (site in Site.values().filter { it != Site.ON_BOUND }) {
            for (report in Report.values()) {
                val label = "$site/$report"
                val blocker = Blocker(report, marker)
                blocker.scenario = scenario(site) { blocker.block(::snapshot) }
                val (outcome, console) = captured { interruptInsideHook(blocker) }
                val failure = outcome.failure
                if (failure == null) {
                    problems += "$label: the call returned normally instead of throwing InterruptedException"
                } else {
                    if (failure.javaClass != InterruptedException::class.java) problems += "$label: threw ${failure.javaClass.name}, expected InterruptedException"
                    val rendered = failure.stackTraceToString()
                    if (rendered.contains(marker)) problems += "$label: the hook text reached the exception: ${rendered.lines().first()}"
                    if (chainOf(failure).any { it === blocker.failure }) problems += "$label: the hook's own exception object was passed on"
                    val hookClass = blocker.failure!!.javaClass.name
                    if (!rendered.contains(hookClass)) problems += "$label: the cause chain lost the hook failure class $hookClass"
                }
                if (console.contains(marker)) problems += "$label: the hook text reached the log: ${console.trim().lines().first()}"
                if (outcome.flagAfter) problems += "$label: the interrupt flag is still set"
                if (blocker.scenario.requests.get() != blocker.requestsAtEntry) problems += "$label: ${blocker.scenario.requests.get() - blocker.requestsAtEntry} request(s) were sent after the interrupted hook"
                if (snapshot(blocker.scenario.setup.storage) != blocker.storageAtEntry) problems += "$label: the storage changed after the interrupted hook"
            }
        }
        assertTrue(problems.isEmpty(), problems.joinToString("\n", prefix = "\n"))
    }

    @Test
    fun aBindingThatFinishedKeepsItsResultWhenOnBoundIsInterrupted() {
        // The app key is already stored when onBound runs, so the call has nothing left to undo. It must hand
        // the interrupt back to the caller and still return.
        val problems = mutableListOf<String>()
        for (secrets2 in listOf(false, true)) for (report in Report.values()) {
            val blocker = Blocker(report, marker)
            blocker.scenario = scenario(Site.ON_BOUND, secrets2 = secrets2) { blocker.block(::snapshot) }
            val (outcome, console) = captured { interruptInsideHook(blocker) }
            val label = "${if (secrets2) "getSecrets2" else "getSecrets"}/$report"
            if (blocker.scenario.requests.get() != 1) problems += "$label: ${blocker.scenario.requests.get()} requests were sent, the extra fetch after an interrupted onBound must be skipped"
            outcome.failure?.let { problems += "$label: threw ${it.javaClass.name} instead of returning" }
            if (!outcome.flagAfter) problems += "$label: the interrupt flag was not restored"
            if (console.contains(marker)) problems += "$label: the hook text reached the log: ${console.trim().lines().first()}"
            val hookClass = blocker.failure!!.javaClass.simpleName
            if (!console.contains(hookClass)) problems += "$label: the log does not name $hookClass: ${console.trim().lines().firstOrNull()}"
            if (blocker.scenario.setup.storage.getBytes(KEY_APP_KEY)?.contentEquals(blocker.scenario.setup.appKey) != true) problems += "$label: the app key was not stored"
        }
        assertTrue(problems.isEmpty(), problems.joinToString("\n", prefix = "\n"))
    }

    @Test
    fun aHookThatReturnsNormallyWithTheInterruptFlagSetStopsTheCallBeforeAnyRequest() {
        // A hook can finish its work after the thread was interrupted, for example a blocking call in native code that
        // ignores the interrupt. The catch blocks never see that, so the SDK checks the flag before it builds and
        // before it sends a request.
        val problems = mutableListOf<String>()
        val cases = listOf(
            Triple("keyLocation/get", Site.KEY_LOCATION_ON_GET, false),
            Triple("keyLocation/null result", Site.KEY_LOCATION_ON_GET, true),
            Triple("keyLocation/delete", Site.KEY_LOCATION_ON_DELETE, false),
            Triple("keyLocation/update", Site.KEY_LOCATION_ON_UPDATE, false),
            Triple("sign", Site.SIGN, false),
            Triple("preflight wrap", Site.PREFLIGHT_WRAP, false)
        )
        for ((label, site, nullKeyLocation) in cases) {
            val sc = scenario(site, nullKeyLocation = nullKeyLocation) { Thread.currentThread().interrupt() }
            val requestsBefore = sc.requests.get()
            val failure = try { failureOf(sc) } finally { Thread.interrupted() }
            if (failure == null) {
                problems += "$label: the call returned normally"
            } else if (failure.javaClass != InterruptedException::class.java) {
                problems += "$label: threw ${failure.javaClass.name}, expected InterruptedException"
            }
            if (sc.requests.get() != requestsBefore) problems += "$label: ${sc.requests.get() - requestsBefore} request(s) were sent after the hook returned"
        }
        assertTrue(problems.isEmpty(), problems.joinToString("\n", prefix = "\n"))
    }

    @Test
    fun aWrapThatReturnsNormallyAtBindingWithTheInterruptFlagSetStillLeavesABoundConfig() {
        // The server has already bound the client when wrap runs. Stopping here would drop the app key it just sent,
        // so the SDK stores the wrapped key, returns the result, and leaves the flag set for the caller.
        val sc = scenario(Site.BIND_WRAP) { Thread.currentThread().interrupt() }
        val failure = failureOf(sc)
        val flagAfter = Thread.interrupted()

        assertNull(failure, "the binding must finish and return, but the call threw $failure")
        assertTrue(flagAfter, "the interrupt flag was cleared, the caller can no longer see the cancellation")
        assertNotNull(sc.setup.storage.getBytes(KEY_APP_KEY_WRAPPED), "the wrapped app key was not stored")
        assertNull(sc.setup.storage.getBytes(KEY_CLIENT_KEY), "the client key was left in the config")
        assertEquals(1, sc.requests.get(), "the extra fetch after binding must be skipped while the flag is set")
    }

    @Test
    fun tryGetNotationResultsKeepsTheInterruptStatusOfTheCallItCouldNotFinish() {
        // The function never throws, so the interrupt that ended the call must stay visible through the flag.
        val sc = scenario(Site.SIGN) { throw InterruptedException("interrupted in sign") }
        val result = try {
            tryGetNotationResults(sc.options, "keeper://AAAAAAAAAAAAAAAAAAAAAA/field/login")
        } finally {
            assertTrue(Thread.interrupted(), "the interrupt flag was cleared")
        }
        assertEquals(emptyList(), result)
    }

    // A custom Error type, since the SDK must not special-case the JDK ones.
    private class SyntheticError(message: String, cause: Throwable?) : Error(message, cause)

    private fun leakyError(kind: Int): Throwable {
        val inner = Error("inner $marker").also { it.addSuppressed(Error("suppressed $marker")) }
        return if (kind == 0) AssertionError("pin=$marker", inner) else SyntheticError("pin=$marker", inner)
    }

    @Test
    fun anErrorFromAHookNeverLeaksItsTextThroughTheExceptionOrTheLog() {
        // Sites that fail the call report a redacted exception. Sites that only log (key location, onBound)
        // let the call finish. This is what an Exception gets today.
        val logsOnly = setOf(Site.KEY_LOCATION_ON_GET, Site.KEY_LOCATION_ON_DELETE, Site.KEY_LOCATION_ON_UPDATE, Site.ON_BOUND)
        val problems = mutableListOf<String>()
        for (site in Site.values()) {
            for (kind in 0..1) {
                val error = leakyError(kind)
                val label = "$site/${error.javaClass.simpleName}"
                val sc = scenario(site) { throw error }
                val (failure, console) = captured { failureOf(sc) }
                if (console.contains(marker)) problems += "$label: the Error text reached the log: ${console.trim().lines().first()}"
                if (failure == null) {
                    if (site !in logsOnly) problems += "$label: the call returned normally"
                    continue
                }
                if (site in logsOnly) problems += "$label: the Error escaped a site that only logs: ${failure.javaClass.name}"
                if (failure === error) problems += "$label: the Error was passed on unchanged"
                val rendered = failure.stackTraceToString()
                if (rendered.contains(marker)) problems += "$label: the Error text reached the exception: ${rendered.lines().first()}"
                if (site !in logsOnly && !rendered.contains(error.javaClass.name)) problems += "$label: the exception lost the Error class name"
            }
        }
        assertTrue(problems.isEmpty(), problems.joinToString("\n", prefix = "\n"))
    }

    @Test
    fun aProtectorThatReusesItsWrapBufferCannotCorruptAnotherConfigsStoredKey() {
        // The wrapped key must be copied as soon as wrap returns. The same protector, with its one output buffer,
        // serves a second config, and a storage that keeps array references would see the first key overwritten.
        val protector = ReusingProtector()
        val first = Setup(storage = BufferStorage())
        val second = Setup(storage = BufferStorage())

        getSecrets(options(first, protector))
        getSecrets(options(second, protector))

        val stored = first.storage.getBytes(KEY_APP_KEY_WRAPPED)!!
        val unwrapped = runCatching { protector.unwrap(stored.copyOf()).copyOf() }.getOrNull()
        assertTrue(unwrapped?.contentEquals(first.appKey) == true, "the first config's stored envelope no longer unwraps after the second config was bound with the same protector")
    }

    // Clears the buffer it last returned from wrap when unwrap finishes, as a protector with one shared work buffer
    // would. The unwrap result itself is correct.
    private class ScrubbingProtector : AppKeyProtector {
        val inner = TestProtector()
        private var lastWrapped: ByteArray? = null
        override fun wrap(appKey: ByteArray) = inner.wrap(appKey).also { lastWrapped = it }
        override fun unwrap(wrappedAppKey: ByteArray): ByteArray = inner.unwrap(wrappedAppKey).also { lastWrapped?.fill(0) }
    }

    @Test
    fun migrationSavesTheBytesItCheckedEvenWhenTheProtectorReusesTheBufferItReturned() {
        // The check unwraps a copy and then the protector clears the original. Saving the original would store
        // zeros, delete the plain key, and lose the app key although the check passed.
        val setup = Setup()
        val protector = ScrubbingProtector()
        setup.storage.saveBytes(KEY_APP_KEY, setup.appKey)

        runCatching { migrateAppKeyToProtector(SecretsManagerOptions(setup.storage, appKeyProtector = protector)) }

        val plain = setup.storage.getBytes(KEY_APP_KEY)
        val wrapped = setup.storage.getBytes(KEY_APP_KEY_WRAPPED)?.let { runCatching { protector.inner.unwrap(it.copyOf()) }.getOrNull() }
        assertContentEquals(setup.appKey, plain ?: wrapped, "the app key can no longer be recovered from the storage after the migration")
    }

    @Test
    fun theAppKeyTheSdkHoldsSurvivesAnotherCallThatMakesTheProtectorReuseItsUnwrapBuffer() {
        // The SDK owns the array unwrap returned, so a later unwrap by the same protector must not change it.
        // Single threaded and without timing: the SDK's own log line for a record it skips is the point where it
        // still holds the app key, and a second config is read from inside that line.
        val protector = ReusingProtector()
        val first = Setup()
        val second = Setup()
        getSecrets(options(first, protector))
        getSecrets(options(second, protector))

        val recordKey = getRandomBytes(32)
        fun record(uid: String, key: ByteArray, data: ByteArray) =
            """{"recordUid":"$uid","recordKey":"${bytesToBase64(key)}","data":"${bytesToBase64(data)}","revision":1,"isEditable":false,"files":null,"innerFolderUid":null}"""
        val undecryptable = record("UNDECRYPTABLE0000000AA", getRandomBytes(48), getRandomBytes(48))
        val readable = record("READABLE00000000000AA", encrypt(recordKey, first.appKey), encrypt(stringToBytes("""{"title":"kept","type":"login","fields":[]}"""), recordKey))
        fun bound(setup: Setup, records: String, logging: Boolean): SecretsManagerOptions {
            val body = """{"encryptedAppKey":null,"folders":null,"records":[$records]}"""
            return options(setup, protector).copy(loggingEnabled = logging, queryFunction = { _, _, _ ->
                KeeperHttpResponse(200, encrypt(stringToBytes(body), transmissionKey))
            })
        }
        val secondOptions = bound(second, "", logging = false)
        var secondRead = false
        val err = System.err
        System.setErr(object : PrintStream(java.io.ByteArrayOutputStream()) {
            override fun println(x: String?) {
                if (!secondRead) {
                    secondRead = true
                    getSecrets(secondOptions)
                }
            }
        })
        val secrets = try {
            getSecrets(bound(first, "$undecryptable,$readable", logging = true))
        } finally {
            System.setErr(err)
        }

        assertTrue(secondRead, "the SDK did not log the skipped record, so the second config was never read")
        assertEquals(listOf("kept"), secrets.records.map { it.data.title }, "the record after the skipped one could not be read with the app key")
    }

    @Test
    fun aBindingWhoseCleanupFailsLeavesAnAppKeyThatTheNextRunReads() {
        // The wrapped key is saved before the client key is deleted, so a failed delete must not cost the app key.
        val setup = Setup()
        val protector = TestProtector()

        runCatching { getSecrets(options(setup, protector).copy(storage = FailingStorage(setup.storage, KEY_CLIENT_KEY))) }

        assertNull(setup.storage.getBytes(KEY_APP_KEY), "the plain app key must not be stored")
        val wrapped = setup.storage.getBytes(KEY_APP_KEY_WRAPPED)
        assertNotNull(wrapped, "the wrapped app key was not stored, so the failed cleanup cost the app key")
        assertContentEquals(setup.appKey, protector.unwrap(wrapped.copyOf()))
        val next = options(setup, protector).copy(queryFunction = { _, _, _ ->
            KeeperHttpResponse(200, encrypt(stringToBytes(setup.boundResponse), transmissionKey))
        })
        getSecrets(next)
    }
}
