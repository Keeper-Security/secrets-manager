package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.test.*

// Connect/read timeouts on the built-in HTTP transport. The behavioural test points
// postFunction at a socket that accepts the TCP connection and then goes silent, so the client
// blocks reading the ServerHello, which is exactly the stall readTimeout has to bound. The call
// runs under a watchdog on a daemon thread: without the timeout the read never returns, and a
// plain assertion would hang the Gradle test JVM instead of failing it.
@ExperimentalSerializationApi
internal class TimeoutTest {

    private val stubTransmissionKey = TransmissionKey(7, ByteArray(32), ByteArray(32))
    private val stubPayload = EncryptedPayload(ByteArray(8), ByteArray(8))

    // Generous relative to the 1s timeout under test: this is the "it hung" tripwire, not a
    // latency assertion, so a loaded CI runner must not trip it.
    private val watchdogSeconds = 20L
    private val probeReadTimeoutMillis = 1_000

    @Test
    fun timeoutDefaults_matchDocumentedValues() {
        val options = SecretsManagerOptions(InMemoryStorage())
        assertEquals(5_000, options.connectTimeoutMillis, "documented default connect timeout")
        assertEquals(30_000, options.readTimeoutMillis, "documented default read timeout")
    }

    @Test
    fun timeoutOptions_acceptCustomValues() {
        val options = SecretsManagerOptions(
            InMemoryStorage(),
            connectTimeoutMillis = 2_000,
            readTimeoutMillis = 10_000
        )
        assertEquals(2_000, options.connectTimeoutMillis)
        assertEquals(10_000, options.readTimeoutMillis)
    }

    @Test
    fun readTimeout_boundsAStalledServer() {
        ServerSocket(0).use { server ->
            val accepted = Thread { runCatching { server.accept() } }
            accepted.isDaemon = true
            accepted.start()

            val url = "https://127.0.0.1:${server.localPort}/"
            val elapsedMillis = withWatchdog {
                val start = System.nanoTime()
                assertFailsWith<SocketTimeoutException> {
                    postFunction(
                        url,
                        stubTransmissionKey,
                        stubPayload,
                        true,
                        readTimeoutMillis = probeReadTimeoutMillis
                    )
                }
                (System.nanoTime() - start) / 1_000_000
            }
            assertTrue(
                elapsedMillis >= probeReadTimeoutMillis / 2,
                "returned in ${elapsedMillis}ms, too fast to have been the read timeout"
            )
        }
    }

    // Runs [block] on a daemon thread, failing (rather than blocking) if it never returns.
    private fun <T> withWatchdog(block: () -> T): T {
        val executor = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "timeout-test").apply { isDaemon = true }
        }
        try {
            return executor.submit(block).get(watchdogSeconds, TimeUnit.SECONDS)
        } catch (_: TimeoutException) {
            fail("call did not return within ${watchdogSeconds}s; the timeout was never applied")
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        } finally {
            executor.shutdownNow()
        }
    }
}
