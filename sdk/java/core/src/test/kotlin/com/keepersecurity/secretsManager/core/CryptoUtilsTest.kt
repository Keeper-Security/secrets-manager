package com.keepersecurity.secretsManager.core

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
//import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.*

@kotlinx.serialization.ExperimentalSerializationApi
internal class CryptoUtilsTest {

    init {
        Security.addProvider(BouncyCastleFipsProvider())
//        Security.addProvider(BouncyCastleProvider())
    }

    @Test
    fun privateKeyIsCompatible() {
        val keyPair = generateKeyPair()
        val data = getRandomBytes(32)
        val publicKey = extractPublicRaw(keyPair.public)
        val ciphertext = publicEncrypt(data, publicKey)
        val plaintext = privateDecrypt(ciphertext, keyPair.private.encoded)
        assertContentEquals(data, plaintext)
    }

    @Test
    fun cryptoEnginesAreNotSharedBetweenAccesses() {
        // The stress test below only fails reliably for a shared digest. A shared KeyPairGenerator or
        // KeyFactory still round-trips, so the per-call contract is checked directly.
        assertEquals(emptyList(), CryptoInteropChecks.sharedEngines())
    }

    @Test(timeout = 60_000)
    fun publicEncryptProducesDecryptableKeysUnderConcurrentCalls() {
        // Provider here depends on which test initialized KeeperCryptoParameters first.
        // CryptoProviderIsolationTest pins each provider explicitly.
        val stress = runPublicEncryptStress()
        assertEquals(0, stress.thrown.size, "publicEncrypt threw ${stress.thrown.size} times under concurrent calls")
        assertEquals(stress.expected, stress.completed, "only ${stress.completed} of ${stress.expected} calls finished")
        assertEquals(0, stress.undecryptable, "${stress.undecryptable} of ${stress.completed} ciphertexts did not decrypt to the original data")
    }

    // Runs [workload] on a helper thread and waits until it reports its first encrypt. The helper thread is
    // always interrupted and joined, also when the wait fails or the waiting test thread is itself interrupted.
    // The interrupt is the expected way for the workload to end. Any other failure on the helper thread, and
    // any cleanup problem attached to the interrupt, is rethrown here so it cannot pass unnoticed.
    private fun <T> whileWorkloadRuns(
        startupSeconds: Long,
        workload: (onFirstEncrypt: () -> Unit) -> Unit,
        body: (caller: Thread) -> T
    ): Pair<T?, Thread> {
        val started = CountDownLatch(1)
        val workloadFailure = AtomicReference<Throwable>()
        val caller = thread(isDaemon = true) {
            try {
                workload(started::countDown)
            } catch (e: InterruptedException) {
                if (e.suppressed.isNotEmpty()) workloadFailure.set(e)
            } catch (e: Throwable) {
                workloadFailure.set(e)
            }
        }
        var pending: Throwable? = null
        try {
            assertTrue(started.await(startupSeconds, TimeUnit.SECONDS), "workers never completed an encrypt")
            return body(caller) to caller
        } catch (e: Throwable) {
            pending = e
            throw e
        } finally {
            caller.interrupt()
            val interrupted = joinAll(listOf(caller), System.nanoTime() + TimeUnit.SECONDS.toNanos(30))
            val problem = workloadFailure.get() ?: if (caller.isAlive) AssertionError("the helper thread did not stop within 30s") else null
            if (interrupted) Thread.currentThread().interrupt()
            if (problem != null) {
                if (pending == null) throw problem else pending.addSuppressed(problem)
            }
        }
    }

    @Test(timeout = 60_000)
    fun stressWorkersStopWhenTheCallerIsInterrupted() {
        // JUnit's timeout interrupts the test thread only. Without cleanup in the workload helper,
        // its eight workers keep encrypting in the background after the test has already failed.
        val before = Thread.getAllStackTraces().keys.toSet()
        val workers = ConcurrentLinkedQueue<Thread>()
        val (_, caller) = whileWorkloadRuns(30, { first -> runPublicEncryptStress(bursts = 1_000_000, onFirstEncrypt = first, workers = workers) }) { }
        assertFalse(caller.isAlive, "workload did not return after the caller was interrupted")
        // The tracked list proves the workload registered its workers. The scan by name does not depend on that registry.
        assertTrue(workers.isNotEmpty(), "the workload registered no worker threads")
        val leaked = Thread.getAllStackTraces().keys.filter { it !in before && it.isAlive && it.name.startsWith(STRESS_THREAD_PREFIX) }
        assertEquals(emptyList(), leaked, "stress workers still running after interrupt")
    }

    @Test(timeout = 60_000)
    fun cleanupWaitsForWorkersThatExitAfterTheExecutorHasTerminated() {
        // A pool can report termination while a worker Thread is still winding down (seen on JDK 17), so
        // an executor-only wait lets that thread outlive the call. The hold below forces that gap on any JVM.
        val workers = ConcurrentLinkedQueue<Thread>()
        val hold = { sleepIgnoringInterrupts(300) }
        val (_, caller) = whileWorkloadRuns(30, { first ->
            runPublicEncryptStress(bursts = 1_000_000, onFirstEncrypt = first, workers = workers, afterWorkerTask = hold)
        }) { }
        assertFalse(caller.isAlive, "workload did not return after the caller was interrupted")
        assertTrue(workers.isNotEmpty(), "the workload registered no worker threads")
        assertEquals(emptyList(), workers.filter { it.isAlive }, "cleanup returned while workers were still alive")
    }

    @Test(timeout = 60_000)
    fun aWorkerThatNeverStopsIsReportedByCleanup() {
        val release = CountDownLatch(1)
        val workers = ConcurrentLinkedQueue<Thread>()
        try {
            val failure = assertFailsWith<InterruptedException> {
                whileWorkloadRuns(30, { first ->
                    runPublicEncryptStress(
                        bursts = 1_000_000, onFirstEncrypt = first, workers = workers, cleanupMillis = 500,
                        afterWorkerTask = { while (release.count > 0) runCatching { release.await() } },
                    )
                }) { }
            }
            val cleanup = failure.suppressed.singleOrNull()
            assertTrue(cleanup is IllegalStateException, "cleanup failure was not attached to the interrupt: ${failure.suppressed.toList()}")
            assertTrue(
                cleanup.message.orEmpty().contains("${workers.size} of ${workers.size} worker thread(s) still alive"),
                "cleanup failure does not name the stuck workers: ${cleanup.message}"
            )
        } finally {
            release.countDown()
            joinAll(workers, System.nanoTime() + TimeUnit.SECONDS.toNanos(10))
        }
        assertEquals(emptyList(), workers.filter { it.isAlive }, "the stuck workers did not exit after release")
    }

    @Test(timeout = 60_000)
    fun aWorkloadFailureIsRethrownOnTheTestThread() {
        // Control for the helper thread: a failure that is not the expected interrupt must reach the test.
        val failure = assertFailsWith<IllegalStateException> {
            whileWorkloadRuns(30, { first -> first(); throw IllegalStateException("workload broke") }) { }
        }
        assertEquals("workload broke", failure.message)
    }

    private fun sleepIgnoringInterrupts(millis: Long) {
        // shutdownNow interrupts every worker, and a plain sleep would end at once instead of holding the thread.
        val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis)
        while (end - System.nanoTime() > 0) {
            try { TimeUnit.NANOSECONDS.sleep(end - System.nanoTime()) } catch (e: InterruptedException) { }
        }
    }

    @Test(timeout = 60_000)
    fun theHelperThreadIsStoppedWhenTheWorkloadNeverStarts() {
        // Control for a startup that fails: the wait times out, and the helper thread must still be interrupted and joined.
        var helper: Thread? = null
        val neverStarts: (() -> Unit) -> Unit = { _ -> helper = Thread.currentThread(); Thread.sleep(Long.MAX_VALUE) }

        assertFailsWith<AssertionError> { whileWorkloadRuns(1, neverStarts) { } }

        assertNotNull(helper, "the workload never ran")
        assertFalse(helper!!.isAlive, "the helper thread was left running after the startup wait failed")
    }

    @Test(timeout = 60_000)
    fun theHelperThreadIsStoppedWhenTheWaitingTestThreadIsInterrupted() {
        // Control for an interrupted test: JUnit's timeout interrupts the test thread while it waits for startup.
        var helper: Thread? = null
        val neverStarts: (() -> Unit) -> Unit = { _ -> helper = Thread.currentThread(); Thread.sleep(Long.MAX_VALUE) }
        Thread.currentThread().interrupt()
        try {
            assertFailsWith<InterruptedException> { whileWorkloadRuns(30, neverStarts) { } }
        } finally {
            Thread.interrupted()
        }

        assertNotNull(helper, "the workload never ran")
        assertFalse(helper!!.isAlive, "the helper thread was left running after the test thread was interrupted")
    }

    @Test
    fun theSdkAgreesWithAnIndependentImplementationOfSha256EciesAndEcdsa() {
        // Under whichever provider the SDK captured in this JVM. CryptoProviderIsolationTest runs the same checks per provider.
        assertEquals(emptyList(), CryptoInteropChecks.run())
    }

    @Test
    fun testTotp() {
        // test default algorithm
        // {Algorithm: "", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        var url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=&digits=8&period=30"
        var totp = getTotpCode(url, 20000000000)
        assertEquals("65353130", totp?.code) // using default algorithm SHA1

        // test default digits
        // { Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 0}, Output: "353130"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=0&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("353130", totp?.code) // using default digits = 6

        // test default period
        // {Algorithm: "SHA1", Period: 0, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=0"
        totp = getTotpCode(url, 20000000000)
        assertEquals("65353130", totp?.code) // using default period = 30

        // test empty secret
        // {Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "", Digits: 8}, Output: "no secret key provided"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url)
        assertNull(totp, "Empty secret shouldn't produce valid TOTP")

        // test invalid algorithm
        // { Algorithm: "SHA1024", Period: 30, UnixTime: 0, Secret: "12345678901234567890", Digits: 8}, Output: "invalid algorithm - use one of SHA1/SHA256/SHA512"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1024&digits=8&period=30"
        totp = getTotpCode(url)
        assertNull(totp, "SHA1024 is unsupported algorithm for TOTP")

        // test invalid secret
        // { Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "1NVAL1D", Digits: 8}, Output: "bad secret key"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=1NVAL1D&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url)
        assertNull(totp, "Invalid secret shouldn't produce valid TOTP")

        // Check seconds passed
        // {Algorithm: "SHA1", Period: 30, UnixTime: 59, Secret: "12345678901234567890", Digits: 8}, Output: "94287082"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 59)
        assertEquals("94287082", totp?.code)
        assertEquals(1, totp?.timeLeft)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 59, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "46119246"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 59)
        assertEquals("46119246", totp?.code)
        assertEquals(1, totp?.timeLeft)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 59, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "90693936"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 59)
        assertEquals("90693936", totp?.code)
        assertEquals(1, totp?.timeLeft)

        // Check different periods - 1 sec. before split
        // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890", Digits: 8}, Output: "07081804"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 1111111109)
        assertEquals("07081804", totp?.code)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "68084774"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 1111111109)
        assertEquals("68084774", totp?.code)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111109, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "25091201"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 1111111109)
        assertEquals("25091201", totp?.code)

        // Check different periods - 1 sec. after split
        // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890", Digits: 8}, Output: "14050471"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 1111111111)
        assertEquals("14050471", totp?.code)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "67062674"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 1111111111)
        assertEquals("67062674", totp?.code)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111111, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "99943326"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 1111111111)
        assertEquals("99943326", totp?.code)

        // Check different time periods
        // {Algorithm: "SHA1", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890", Digits: 8}, Output: "89005924"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 1234567890)
        assertEquals("89005924", totp?.code)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "91819424"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 1234567890)
        assertEquals("91819424", totp?.code)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 1234567890, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "93441116"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 1234567890)
        assertEquals("93441116", totp?.code)

        // {Algorithm: "SHA1", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890", Digits: 8}, Output: "69279037"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 2000000000)
        assertEquals("69279037", totp?.code)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "90698825"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 2000000000)
        assertEquals("90698825", totp?.code)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 2000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "38618901"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 2000000000)
        assertEquals("38618901", totp?.code)

        // {Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("65353130", totp?.code)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "77737706"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("77737706", totp?.code)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 20000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "47863826"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("47863826", totp?.code)
    }

    @Test
    fun testGeneratePassword() {
        var password = generatePassword()
        assertEquals(32, password.length)

        password = generatePassword(32, 32)
        assertTrue { "^[a-z]{32}$".toRegex().matches(password) }

        password = generatePassword(32, 0, 32)
        assertTrue { "^[A-Z]{32}$".toRegex().matches(password) }

        password = generatePassword(32, 0, 0, 32)
        assertTrue { "^[0-9]{32}$".toRegex().matches(password) }

        password = generatePassword(32, 0, 0, 0, 32)
        assertTrue { password.length == 32 }
        assertTrue { password.filter { "\"!@#$%()+;<>=?[\\]{}^.,".contains(it) }.length == password.length }
    }

    @Test
    fun testGeneratePasswordMixedCategoriesAreShuffled() {
        // Every other testGeneratePassword case asks for a single category, so all 32 characters
        // come from one charset and the final shuffle cannot be observed. randomSample() emits
        // characters grouped by category, so a mixed request is the only way to tell a real
        // shuffle from no shuffle at all: without one, position 0 is always lowercase.
        //
        // Scope: this pins down that the shuffle happens and that it preserves the requested
        // count per category. It cannot distinguish a CSPRNG from a weak PRNG, since both
        // produce a uniform permutation; that the shuffle draws from SecureRandom is enforced
        // by review of generatePassword, not by this test.
        val charsets = listOf(AsciiLowercase, AsciiUppercase, AsciiDigits, AsciiSpecialCharacters)
        val categoryOfFirstChar = mutableSetOf<Int>()
        repeat(200) {
            val password = generatePassword(32, 8, 8, 8, 8)
            assertEquals(32, password.length)
            // The shuffle must preserve the requested count for each category.
            charsets.forEachIndexed { category, charset ->
                assertEquals(
                    8, password.count { it in charset },
                    "category $category count changed. Password: $password"
                )
            }
            categoryOfFirstChar.add(charsets.indexOfFirst { password[0] in it })
        }
        assertTrue(
            categoryOfFirstChar.size > 1,
            "position 0 only ever held category $categoryOfFirstChar across 200 passwords, " +
                "so the characters are not being shuffled across categories"
        )
    }

    @Test
    fun testWebSafe64FromBytes() {
        val urlSafeRegex = "^[a-zA-Z0-9_-]*\$".toRegex()

        for (i in 1..3){
            val paddedStr = webSafe64FromBytes(getRandomBytes(i))
            assertTrue(urlSafeRegex.containsMatchIn(paddedStr))
        }

        assertEquals("YQ", webSafe64FromBytes("a".toByteArray()))
        assertEquals("YWE", webSafe64FromBytes("aa".toByteArray()))
        assertEquals("YWFh", webSafe64FromBytes("aaa".toByteArray()))
        assertEquals("YWFhYQ", webSafe64FromBytes("aaaa".toByteArray()))
        assertEquals("8J-Ygw", webSafe64FromBytes("\uD83D\uDE03".toByteArray())) // encoded 😃 and will produce padded string along with the hyphen =>  `8J-Ygw==`
    }
}
