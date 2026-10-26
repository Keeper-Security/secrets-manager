package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import java.net.HttpURLConnection.HTTP_FORBIDDEN
import java.net.HttpURLConnection.HTTP_OK
import kotlin.test.*

private const val STATUS_TOO_MANY_REQUESTS = 429

// Throttle retry with exponential backoff. Unit tests exercise the internal
// helpers; e2e tests drive getSecrets through postQuery with a mocked queryFunction returning
// HTTP 403 or 429 {"error":"throttled"} responses and a recording throttleSleepMillis so retries
// never actually wait. The backend moved from 403 to 429 in June 2026; 403 stays accepted in case
// a second rate limiter still uses it.
@ExperimentalSerializationApi
internal class ThrottleTest {

    private val fakeToken = "YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c"

    private var previousKeyStub: (() -> ByteArray)? = null

    @BeforeTest
    fun setUp() {
        previousKeyStub = if (TestStubs.transmissionKeyStubReady()) TestStubs.transmissionKeyStub else null
        // A deterministic, valid 32-byte transmission key. Also avoids leakage from getSecretsE2E,
        // whose stub closes over its own (by now out-of-range) response index.
        TestStubs.transmissionKeyStub = { ByteArray(32) }
    }

    @AfterTest
    fun tearDown() {
        // A lateinit cannot be unset, so with no previous stub the deterministic one stays.
        previousKeyStub?.let { TestStubs.transmissionKeyStub = it }
    }

    private fun throttleBody(retryAfter: Double? = null): ByteArray {
        val json = if (retryAfter == null) {
            """{"error":"throttled","message":"throttled"}"""
        } else {
            """{"error":"throttled","message":"throttled","retry_after":$retryAfter}"""
        }
        return json.toByteArray()
    }

    // A regression that stops the retry loop from ending must fail the test, not hang the build.
    // The mocks that answer "throttled" forever call this on every request.
    private fun failIfRunaway(calls: Int) = check(calls <= 50) { "retry loop did not stop after $calls requests" }

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
        assertEquals(13750L, throttleDelayMillis(0, 0.0, 0.25))
        assertTrue(throttleDelayMillis(0, 0.0, 0.2499999) < 13750L, "jitter just below 0.25 must stay below the upper bound")
    }

    // --- unit: parseThrottle ---

    @Test
    fun parseThrottle_table() {
        assertEquals(0.0, parseThrottle("""{"error":"throttled"}"""), "error key, no retry_after")
        assertEquals(5.0, parseThrottle("""{"result_code":"throttled","retry_after":5}"""), "result_code key, numeric retry_after")
        assertEquals(3.0, parseThrottle("""{"error":"throttled","retry_after":"3"}"""), "string retry_after")
        assertEquals(0.0, parseThrottle("""{"error":"throttled","retry_after":-2}"""), "negative retry_after")
        assertEquals(176.0, parseThrottle("""{"error":"throttled","retry_after":300}"""), "retry_after above the cap")
        assertNull(parseThrottle("""{"error":"key"}"""), "non-throttle error")
        assertNull(parseThrottle("not json"), "not json")
        assertNull(parseThrottle(""), "empty body")
    }

    // --- e2e via getSecrets ---

    // The backend throttles with 429 today and answered 403 before June 2026. Each case below runs
    // against both statuses, so a change to the status gate cannot silently drop one of them.
    private val throttleStatuses = listOf(HTTP_FORBIDDEN, STATUS_TOO_MANY_REQUESTS)

    private fun buildStorage(): KeyValueStorage {
        val storage = InMemoryStorage()
        initializeStorage(storage, fakeToken, "fake.keepersecurity.com")
        // Seed an app key so the (non-bound) empty success response decrypts without error; the
        // key itself is unused because the mocked responses carry no records.
        storage.saveBytes(KEY_APP_KEY, ByteArray(32))
        return storage
    }

    private fun successResponse(transmissionKey: TransmissionKey): KeeperHttpResponse {
        val body = """{"records":[],"folders":[],"encryptedAppKey":null}""".toByteArray()
        return KeeperHttpResponse(HTTP_OK, encrypt(body, transmissionKey.key))
    }

    private fun keyRotationResponse() = KeeperHttpResponse(400, """{"error":"key","key_id":10}""".toByteArray())

    @Test
    fun retriesThenSucceeds() {
        for (status in throttleStatuses) {
            var calls = 0
            val sleeps = mutableListOf<Long>()
            val mock: QueryFunction = { _, transmissionKey, _ ->
                calls++
                failIfRunaway(calls)
                if (calls == 1) KeeperHttpResponse(status, throttleBody()) else successResponse(transmissionKey)
            }
            val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

            assertTrue(getSecrets(options).records.isEmpty(), "status $status")
            assertEquals(1, sleeps.size, "status $status")
            assertEquals(2, calls, "status $status")
        }
    }

    @Test
    fun exhaustionThrowsKeeperThrottleException() {
        for (status in throttleStatuses) {
            var calls = 0
            val sleeps = mutableListOf<Long>()
            val mock: QueryFunction = { _, _, _ ->
                calls++
                failIfRunaway(calls)
                KeeperHttpResponse(status, throttleBody())
            }
            val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

            assertFailsWith<KeeperThrottleException>("status $status") { getSecrets(options) }
            assertEquals(5, sleeps.size, "status $status") // five backoff sleeps before giving up
            assertEquals(6, calls, "status $status") // 5 retries + the final throttled response
        }
    }

    @Test
    fun retryAfterIsHonored() {
        for (status in throttleStatuses) {
            var calls = 0
            val sleeps = mutableListOf<Long>()
            val mock: QueryFunction = { _, _, _ ->
                calls++
                failIfRunaway(calls)
                KeeperHttpResponse(status, if (calls == 1) throttleBody(3.0) else throttleBody())
            }
            val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

            assertFailsWith<KeeperThrottleException>("status $status") { getSecrets(options) }
            // retry_after = 3s with one-sided [0, 0.25) jitter -> [3000ms, 3750ms]
            assertTrue(sleeps[0] in 3000L..3750L, "status $status: first delay was ${sleeps[0]}ms")
            // retry_after covers one retry only; the next sleep returns to the attempt 1 base (22s + <25%)
            assertTrue(sleeps[1] in 22000L..27500L, "status $status: second delay was ${sleeps[1]}ms")
        }
    }

    private fun assertBodiesNotRetried(bodies: List<String>) {
        for (status in throttleStatuses) {
            for (body in bodies) {
                var calls = 0
                val sleeps = mutableListOf<Long>()
                val mock: QueryFunction = { _, _, _ ->
                    calls++
                    failIfRunaway(calls)
                    KeeperHttpResponse(status, body.toByteArray())
                }
                val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

                val e = assertFailsWith<Exception>("status $status body '$body'") { getSecrets(options) }
                assertFalse(e is KeeperThrottleException, "status $status body '$body' must not become a throttle error")
                assertEquals(0, sleeps.size, "status $status body '$body'")
                assertEquals(1, calls, "status $status body '$body'")
            }
        }
    }

    @Test
    fun nonThrottleErrorsNotRetried() {
        assertBodiesNotRetried(listOf("""{"error":"access_denied","message":"nope"}"""))
    }

    @Test
    fun malformedBodiesAreNotReadAsAThrottle() {
        assertBodiesNotRetried(listOf("not json", "[]", "\"throttled\"", ""))
    }

    @Test
    fun nonThrottleStatusWithThrottleBodyNotRetried() {
        // A 502 carrying a throttle body must not be retried: only 403 and 429 are gated.
        val sleeps = mutableListOf<Long>()
        var calls = 0
        val mock: QueryFunction = { _, _, _ ->
            failIfRunaway(++calls)
            KeeperHttpResponse(502, throttleBody())
        }
        val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

        assertFailsWith<Exception> { getSecrets(options) }
        assertEquals(0, sleeps.size)
    }

    @Test
    fun mixedStatusesShareOneThrottleBudget() {
        var calls = 0
        val sleeps = mutableListOf<Long>()
        val mock: QueryFunction = { _, _, _ ->
            calls++
            failIfRunaway(calls)
            KeeperHttpResponse(if (calls % 2 == 1) HTTP_FORBIDDEN else STATUS_TOO_MANY_REQUESTS, throttleBody())
        }
        val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

        assertFailsWith<KeeperThrottleException> { getSecrets(options) }
        assertEquals(5, sleeps.size)
        assertEquals(6, calls)
    }

    @Test
    fun keyRotationDoesNotResetTheThrottleBudget() {
        // Calls 1-6 alternate throttle/rotation, then the server only throttles. Resetting the
        // throttle counter on a rotation would allow more than five throttle sleeps.
        var calls = 0
        val sleeps = mutableListOf<Long>()
        val mock: QueryFunction = { _, _, _ ->
            calls++
            failIfRunaway(calls)
            if (calls <= 6 && calls % 2 == 0) keyRotationResponse()
            else KeeperHttpResponse(STATUS_TOO_MANY_REQUESTS, throttleBody())
        }
        val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

        assertFailsWith<KeeperThrottleException> { getSecrets(options) }
        assertEquals(5, sleeps.size)
        assertEquals(9, calls) // 6 throttled responses + 3 rotations
    }

    @Test
    fun throttleDoesNotResetTheKeyRotationBudget() {
        // Rotation on odd calls, throttle on even calls. Resetting the rotation counter on a
        // throttle would let this run past MAX_KEY_ROTATION_RETRIES.
        var calls = 0
        val sleeps = mutableListOf<Long>()
        val mock: QueryFunction = { _, _, _ ->
            calls++
            failIfRunaway(calls)
            if (calls % 2 == 1) keyRotationResponse() else KeeperHttpResponse(STATUS_TOO_MANY_REQUESTS, throttleBody())
        }
        val options = SecretsManagerOptions(buildStorage(), mock, throttleSleepMillis = { sleeps.add(it) })

        val e = assertFailsWith<SecretsManagerException> { getSecrets(options) }
        assertTrue(e.message.orEmpty().contains("key rotation exhausted $MAX_KEY_ROTATION_RETRIES retries"), "got: ${e.message}")
        assertEquals(MAX_KEY_ROTATION_RETRIES, sleeps.size)
        assertEquals(2 * MAX_KEY_ROTATION_RETRIES + 1, calls)
    }

    // --- logging and diagnostics: the throttle warning must respect options.loggingEnabled ---

    // Runs [block] and returns whatever the SDK wrote to stderr. Tests run sequentially here
    // (shared TestStubs, no parallel config), so temporarily swapping System.err is safe.
    private fun captureStderr(block: () -> Unit): String {
        val original = System.err
        val buf = java.io.ByteArrayOutputStream()
        System.setErr(java.io.PrintStream(buf, true))
        try {
            block()
        } finally {
            System.setErr(original)
        }
        return buf.toString()
    }

    // One throttle-then-success getSecrets with the given status and flag.
    private fun captureThrottleStderr(status: Int, loggingEnabled: Boolean): String {
        var calls = 0
        val mock: QueryFunction = { _, transmissionKey, _ ->
            calls++
            failIfRunaway(calls)
            if (calls == 1) KeeperHttpResponse(status, throttleBody()) else successResponse(transmissionKey)
        }
        val options = SecretsManagerOptions(
            buildStorage(), mock, loggingEnabled = loggingEnabled, throttleSleepMillis = { }
        )
        return captureStderr { getSecrets(options) }
    }

    @Test
    fun throttleWarningFollowsLoggingEnabled() {
        for (status in throttleStatuses) {
            val on = captureThrottleStderr(status, loggingEnabled = true)
            assertTrue(on.contains("attempt 1/$MAX_THROTTLE_RETRIES"), "status $status: expected attempt counter in warning, got: $on")

            val off = captureThrottleStderr(status, loggingEnabled = false)
            assertFalse(
                off.contains("throttl", ignoreCase = true),
                "status $status: nothing about throttling should reach stderr when loggingEnabled=false, got: $off"
            )
        }
    }

    @Test
    fun throttleDiagnosticsOmitTheServerResponseBody() {
        val marker = "SERVER-SUPPLIED-MARKER"
        for (status in throttleStatuses) {
            var calls = 0
            val mock: QueryFunction = { _, _, _ ->
                failIfRunaway(++calls)
                KeeperHttpResponse(status, """{"error":"throttled","message":"$marker"}""".toByteArray())
            }
            val options = SecretsManagerOptions(buildStorage(), mock, loggingEnabled = true, throttleSleepMillis = { })

            var thrown: KeeperThrottleException? = null
            val err = captureStderr { thrown = assertFailsWith<KeeperThrottleException>("status $status") { getSecrets(options) } }
            assertFalse(err.contains(marker), "status $status: stderr echoed the server body: $err")
            assertFalse(thrown!!.stackTraceToString().contains(marker), "status $status: exception echoed the server body")
        }
    }
}
