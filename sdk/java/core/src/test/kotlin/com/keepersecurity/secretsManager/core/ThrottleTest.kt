package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import java.net.HttpURLConnection.HTTP_FORBIDDEN
import java.net.HttpURLConnection.HTTP_OK
import kotlin.test.*

// Throttle retry with exponential backoff (KSM-876 / KSM-878). Unit tests exercise the internal
// helpers; e2e tests drive getSecrets through postQuery with a mocked queryFunction returning
// HTTP 403 {"error":"throttled"} responses and a recording throttleSleepMillis so retries never
// actually wait.
@ExperimentalSerializationApi
internal class ThrottleTest {

    private val fakeToken = "YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c"

    @BeforeTest
    fun setUp() {
        // A deterministic, valid 32-byte transmission key. Also avoids leakage from getSecretsE2E,
        // whose stub closes over its own (by now out-of-range) response index.
        TestStubs.transmissionKeyStub = { ByteArray(32) }
    }

    private fun throttleBody(retryAfter: Double? = null): ByteArray {
        val json = if (retryAfter == null) {
            """{"error":"throttled","message":"throttled"}"""
        } else {
            """{"error":"throttled","message":"throttled","retry_after":$retryAfter}"""
        }
        return json.toByteArray()
    }

    // --- unit: throttleDelayMillis ---

    @Test
    fun throttleDelay_exponentialSequence_noJitter() {
        val expected = listOf(11000L, 22000L, 44000L, 88000L, 176000L)
        expected.forEachIndexed { attempt, want ->
            assertEquals(want, throttleDelayMillis(attempt, 0.0, 0.0))
        }
    }

    @Test
    fun throttleDelay_retryAfterPrecedence_andNonPositiveIgnored() {
        assertEquals(7000L, throttleDelayMillis(3, 7.0, 0.0))
        assertEquals(11000L, throttleDelayMillis(0, 0.0, 0.0))
        assertEquals(22000L, throttleDelayMillis(1, -5.0, 0.0))
    }

    @Test
    fun throttleDelay_jitterBounds() {
        assertEquals(8250L, throttleDelayMillis(0, 0.0, -0.25))
        assertEquals(13750L, throttleDelayMillis(0, 0.0, 0.25))
    }

    // --- unit: parseThrottle ---

    @Test
    fun parseThrottle_table() {
        assertEquals(0.0, parseThrottle("""{"error":"throttled"}"""))
        assertEquals(5.0, parseThrottle("""{"result_code":"throttled","retry_after":5}"""))
        assertEquals(3.0, parseThrottle("""{"error":"throttled","retry_after":"3"}"""))
        assertEquals(0.0, parseThrottle("""{"error":"throttled","retry_after":-2}"""))
        assertNull(parseThrottle("""{"error":"key"}"""))
        assertNull(parseThrottle("not json"))
        assertNull(parseThrottle(""))
    }

    // --- e2e via getSecrets ---

    private fun buildStorage(): KeyValueStorage {
        val storage = InMemoryStorage()
        initializeStorage(storage, fakeToken, "fake.keepersecurity.com")
        // Seed an app key so the (non-bound) empty success response decrypts without error; the
        // key itself is unused because the mocked responses carry no records.
        storage.saveBytes(KEY_APP_KEY, ByteArray(32))
        return storage
    }

    @Test
    fun retriesThenSucceeds() {
        var calls = 0
        val sleeps = mutableListOf<Long>()
        val mock: QueryFunction = { _, transmissionKey, _ ->
            calls++
            if (calls == 1) {
                KeeperHttpResponse(HTTP_FORBIDDEN, throttleBody())
            } else {
                val body = """{"records":[],"folders":[],"encryptedAppKey":null}""".toByteArray()
                KeeperHttpResponse(HTTP_OK, encrypt(body, transmissionKey.key))
            }
        }
        val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

        val secrets = getSecrets(options)
        assertTrue(secrets.records.isEmpty())
        assertEquals(1, sleeps.size)
        assertEquals(2, calls)
    }

    @Test
    fun exhaustionThrowsKeeperThrottleException() {
        var calls = 0
        val sleeps = mutableListOf<Long>()
        val mock: QueryFunction = { _, _, _ ->
            calls++
            KeeperHttpResponse(HTTP_FORBIDDEN, throttleBody())
        }
        val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

        assertFailsWith<KeeperThrottleException> { getSecrets(options) }
        assertEquals(5, sleeps.size) // five backoff sleeps before giving up
        assertEquals(6, calls) // 5 retries + the final throttled response
    }

    @Test
    fun retryAfterIsHonored() {
        var calls = 0
        val sleeps = mutableListOf<Long>()
        val mock: QueryFunction = { _, _, _ ->
            calls++
            if (calls == 1) KeeperHttpResponse(HTTP_FORBIDDEN, throttleBody(3.0))
            else KeeperHttpResponse(HTTP_FORBIDDEN, throttleBody())
        }
        val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

        assertFailsWith<KeeperThrottleException> { getSecrets(options) }
        // retry_after = 3s with +/-25% jitter -> [2250ms, 3750ms]
        assertTrue(sleeps[0] in 2250L..3750L, "first delay was ${sleeps[0]}ms")
    }

    @Test
    fun nonThrottle403NotRetried() {
        val sleeps = mutableListOf<Long>()
        val mock: QueryFunction = { _, _, _ ->
            KeeperHttpResponse(HTTP_FORBIDDEN, """{"error":"access_denied","message":"nope"}""".toByteArray())
        }
        val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

        val e = assertFailsWith<Exception> { getSecrets(options) }
        assertFalse(e is KeeperThrottleException, "a non-throttle 403 must not become a throttle error")
        assertEquals(0, sleeps.size)
    }

    @Test
    fun non403ThrottleBodyNotRetried() {
        // A 502 carrying a {"error":"throttled"} body must NOT be retried (403 gate).
        val sleeps = mutableListOf<Long>()
        val mock: QueryFunction = { _, _, _ ->
            KeeperHttpResponse(502, throttleBody())
        }
        val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

        assertFailsWith<Exception> { getSecrets(options) }
        assertEquals(0, sleeps.size)
    }

    // --- logging gate (PR #1043 review): the throttle warning must respect options.loggingEnabled ---

    // Runs one throttle-then-success getSecrets with the given flag, returning whatever the SDK
    // wrote to stderr. Tests run sequentially here (shared TestStubs, no parallel config), so
    // temporarily swapping System.err is safe.
    private fun captureThrottleStderr(loggingEnabled: Boolean): String {
        var calls = 0
        val mock: QueryFunction = { _, transmissionKey, _ ->
            calls++
            if (calls == 1) {
                KeeperHttpResponse(HTTP_FORBIDDEN, throttleBody())
            } else {
                val body = """{"records":[],"folders":[],"encryptedAppKey":null}""".toByteArray()
                KeeperHttpResponse(HTTP_OK, encrypt(body, transmissionKey.key))
            }
        }
        val options = SecretsManagerOptions(
            buildStorage(), mock, loggingEnabled = loggingEnabled, throttleSleepMillis = { }
        )
        val original = System.err
        val buf = java.io.ByteArrayOutputStream()
        System.setErr(java.io.PrintStream(buf, true))
        try {
            getSecrets(options)
        } finally {
            System.setErr(original)
        }
        return buf.toString()
    }

    @Test
    fun throttleWarning_suppressedWhenLoggingDisabled() {
        val err = captureThrottleStderr(loggingEnabled = false)
        assertFalse(
            err.contains("throttled", ignoreCase = true),
            "no throttle warning should reach stderr when loggingEnabled=false, got: $err"
        )
    }

    @Test
    fun throttleWarning_emittedWhenLoggingEnabled() {
        val err = captureThrottleStderr(loggingEnabled = true)
        assertTrue(err.contains("throttled", ignoreCase = true), "expected a throttle warning on stderr")
        assertTrue(
            Regex("attempt 1/$MAX_THROTTLE_RETRIES").containsMatchIn(err),
            "expected attempt counter in warning, got: $err"
        )
    }
}
