package com.keepersecurity.secretsManager.core

import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.ServerSocket
import java.net.SocketAddress
import java.net.URI
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess
import kotlin.test.*

// A CONNECT proxy on a loopback port that records every request it receives. With challengeFirst set it
// answers the first CONNECT with 407 and a Basic challenge, as an authenticating proxy does. Every other
// request gets 502, so the client's connect fails after the exchange and the test never needs a real target.
internal class ConnectFixture(private val challengeFirst: Boolean = false) : AutoCloseable {
    class Request(val line: String, val headers: Map<String, String>)

    private val server = ServerSocket(0, 20, InetAddress.getByName("127.0.0.1"))
    val port: Int get() = server.localPort
    val requests = CopyOnWriteArrayList<Request>()
    private var challenged = false

    init {
        Thread {
            while (!server.isClosed) {
                val socket = try { server.accept() } catch (_: IOException) { break }
                Thread { serve(socket) }.apply { isDaemon = true }.start()
            }
        }.apply { isDaemon = true }.start()
    }

    private fun serve(socket: java.net.Socket) {
        socket.use { s ->
            val reader = s.getInputStream().bufferedReader(Charsets.ISO_8859_1)
            val out = s.getOutputStream()
            while (true) {
                val line = reader.readLine() ?: return
                if (line.isEmpty()) continue
                val headers = HashMap<String, String>()
                while (true) {
                    val header = reader.readLine() ?: return
                    if (header.isEmpty()) break
                    headers[header.substringBefore(':').trim().lowercase()] = header.substringAfter(':').trim()
                }
                requests.add(Request(line, headers))
                val challenge = synchronized(this) { (challengeFirst && !challenged).also { if (it) challenged = true } }
                if (challenge) {
                    out.write(("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"ksm-test\"\r\n" +
                        "Content-Length: 0\r\nProxy-Connection: keep-alive\r\n\r\n").toByteArray(Charsets.ISO_8859_1))
                    out.flush()
                } else {
                    out.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
                    out.flush()
                    return
                }
            }
        }
    }

    override fun close() = server.close()
}

// Answers every lookup with the same proxy, or with a direct connection, and counts the lookups.
private class FixedSelector(private val proxy: Proxy) : ProxySelector() {
    val lookups = CopyOnWriteArrayList<URI>()
    override fun select(uri: URI): List<Proxy> = listOf(proxy).also { lookups.add(uri) }
    override fun connectFailed(uri: URI, sa: SocketAddress, ioe: IOException) {}
}

private class FakeEnvironment(
    private val env: Map<String, String> = emptyMap(),
    private val properties: Map<String, String> = emptyMap()
) : ProxyEnvironment {
    override fun env(name: String): String? = env[name]
    override fun property(name: String): String? = properties[name]
}

// These tests use the real default connection opener, so they check which proxy the production code hands
// to java.net.URL, not only which proxy it decided on (ProxyTest covers the decision with a recording opener).
// Creating an HttpsURLConnection opens no socket. What matters is that nothing connects, so the tests watch the
// fixture and the default ProxySelector instead of the connection object.
internal class ProxyConnectionTest {

    private val target = "https://ksm-target.test:8443/api"
    private val originalSelector: ProxySelector? = ProxySelector.getDefault()
    private val fixture = ConnectFixture()

    @AfterTest
    fun restore() {
        ProxySelector.setDefault(originalSelector)
        fixture.close()
    }

    private fun connectAndIgnoreFailure(url: String, env: ProxyEnvironment, explicitProxyUrl: String? = null) {
        val connection = openProxiedConnection(url, explicitProxyUrl, false, env)
        connection.connectTimeout = 3_000
        connection.readTimeout = 3_000
        runCatching { connection.connect() }
    }

    @Test
    fun theSelectedAmbientProxyReceivesTheConnect() {
        connectAndIgnoreFailure(target, FakeEnvironment(env = mapOf("HTTPS_PROXY" to "http://127.0.0.1:${fixture.port}")))

        assertEquals(listOf("CONNECT ksm-target.test:8443 HTTP/1.1"), fixture.requests.map { it.line })
    }

    @Test
    fun anExcludedHostBypassesAnActiveDefaultSelector() {
        // The selector answers with the fixture proxy, so an excluded host reaches the fixture unless the
        // connection is opened with Proxy.NO_PROXY. Only https lookups count: the JDK can also ask the selector
        // about socket:// addresses while it connects, and that is not a routing decision for the target.
        val selector = FixedSelector(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", fixture.port)))
        ProxySelector.setDefault(selector)
        val closed = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
        val env = FakeEnvironment(env = mapOf("HTTPS_PROXY" to "http://127.0.0.1:${fixture.port}", "NO_PROXY" to "127.0.0.1"))

        connectAndIgnoreFailure("https://127.0.0.1:$closed/api", env)

        assertTrue(selector.lookups.none { it.scheme == "https" }, "the selector was asked about an excluded host: ${selector.lookups}")
        assertTrue(fixture.requests.isEmpty(), "an excluded host went through the proxy: ${fixture.requests.map { it.line }}")
    }

    @Test
    fun whenNoProxyIsSelectedTheDefaultSelectorDecides() {
        // An https:// ambient value cannot be honored, so resolveProxy returns null and the host is not excluded.
        // The connection must then be opened without a proxy argument, so the JDK consults its default
        // selector. Forcing Proxy.NO_PROXY here would send the request direct past that selector.
        val selector = FixedSelector(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", fixture.port)))
        ProxySelector.setDefault(selector)

        connectAndIgnoreFailure(target, FakeEnvironment(env = mapOf("HTTPS_PROXY" to "https://127.0.0.1:1")))

        assertTrue(selector.lookups.isNotEmpty(), "the default selector was never consulted")
        assertEquals(listOf("CONNECT ksm-target.test:8443 HTTP/1.1"), fixture.requests.map { it.line })
    }

    @Test
    fun aMalformedSelectedAmbientValueMakesNoConnectionAttempt() {
        val selector = FixedSelector(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", fixture.port)))
        ProxySelector.setDefault(selector)
        val env = FakeEnvironment(env = mapOf("HTTPS_PROXY" to "http://usr:8080#pw@127.0.0.1:${fixture.port}"))

        assertFailsWith<SecretsManagerException> { openProxiedConnection(target, null, false, env) }

        assertTrue(selector.lookups.isEmpty(), "the default selector was consulted for a rejected value")
        assertTrue(fixture.requests.isEmpty(), "a rejected value still reached a proxy")
    }

    @Test
    fun reservedCharactersInAProxyPasswordAreDecodedWhenPercentEncoded() {
        // Each reserved character is the first one of a different URI part (fragment, path, query, userinfo
        // delimiter), so each must survive as a literal character in the decoded credential.
        val cases = mapOf("%40" to "@", "%23" to "#", "%2F" to "/", "%3F" to "?", "%3A" to ":")
        for ((encoded, literal) in cases) {
            val resolved = resolveProxy("http://us%40er:pa${encoded}ss@127.0.0.1:${fixture.port}", target, FakeEnvironment())
            assertEquals("us@er", resolved!!.username, "user name for $encoded")
            assertEquals("pa${literal}ss", resolved.password, "password for $encoded")
        }
    }

    @Test(timeout = 120_000)
    fun percentEncodedCredentialsReachTheProxyDecodedOnTheWire() {
        // The JDK reads jdk.http.auth.tunneling.disabledSchemes when the first HTTPS connection of a JVM is made,
        // so the exchange runs in a fresh JVM where the SDK can still clear it.
        val log = File.createTempFile("ksm-proxy-wire-", ".log", File(System.getProperty("java.io.tmpdir")))
        val process = ProcessBuilder(
            File(System.getProperty("java.home"), "bin/java").path, "-cp", System.getProperty("java.class.path"),
            ProxyWireMain::class.java.name
        ).redirectErrorStream(true).redirectOutput(log).start()
        try {
            assertTrue(process.waitFor(90, TimeUnit.SECONDS), "the child JVM did not finish in 90 seconds:\n${log.readText()}")
            assertEquals(0, process.exitValue(), "the proxy did not receive the decoded credentials:\n${log.readText()}")
        } finally {
            process.destroyForcibly()
            log.delete()
        }
    }
}

internal object ProxyWireMain {
    @JvmStatic
    fun main(args: Array<String>) {
        ConnectFixture(challengeFirst = true).use { fixture ->
            val proxyUrl = "http://us%40er:p%40ss%23w%2Frd%3F@127.0.0.1:${fixture.port}"
            val connection = openProxiedConnection("https://ksm-target.test:8443/api", proxyUrl, false, FakeEnvironment())
            connection.connectTimeout = 5_000
            connection.readTimeout = 5_000
            runCatching { connection.connect() }

            val expected = "Basic " + Base64.getEncoder().encodeToString("us@er:p@ss#w/rd?".toByteArray(Charsets.UTF_8))
            val sent = fixture.requests.map { it.headers["proxy-authorization"] }
            println("requests=${fixture.requests.size} authorization=${sent.map { if (it == null) "none" else if (it == expected) "decoded credentials" else "OTHER" }}")
            val ok = fixture.requests.size >= 2 && sent[0] == null && sent[1] == expected
            exitProcess(if (ok) 0 else 1)
        }
    }
}
