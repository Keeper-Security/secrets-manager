package com.keepersecurity.secretsManager.core

import java.net.Authenticator
import java.net.Proxy
import java.net.URL
import java.net.URLConnection
import kotlin.test.Test
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

internal class ProxyTest {

    private class FakeProxyEnvironment(
        private val envVars: Map<String, String> = emptyMap(),
        private val properties: Map<String, String> = emptyMap()
    ) : ProxyEnvironment {
        override fun env(name: String): String? = envVars[name]
        override fun property(name: String): String? = properties[name]
    }

    private val target = "https://vault.keepersecurity.com/api/rest/sm/v1/get_secret"

    // Records the routing openProxiedConnection chose instead of connecting anywhere.
    private class RecordingOpener : ConnectionOpener {
        val calls = mutableListOf<Pair<URL, Proxy?>>()
        override fun open(url: URL, proxy: Proxy?): URLConnection {
            // openConnection() only builds the connection object. It does not touch the network.
            calls.add(url to proxy)
            return url.openConnection()
        }
    }

    // These parse cleanly as host:port unless the whole URL is checked: java.net.URI reads the text
    // after '#', '/' or '?' as a fragment, path or query, and the proxy silently becomes the user name.
    private val numericPrefixShapes = listOf(
        "http://usr:8080#Zq9@proxy.corp:3128",
        "http://usr:8080/Zq9@proxy.corp:3128",
        "http://usr:8080?Zq9@proxy.corp:3128"
    )

    // Each shape carries the fake password Zq9, so a message that echoes the value fails the check.
    private val malformedAmbientShapes = listOf(
        "http://usr:Zq9#w@127.0.0.1:9",
        "http://usr:Zq9/w@127.0.0.1:9",
        "http://usr:Zq9@ss@127.0.0.1:9",
        "http://usr:Zq9 ss@127.0.0.1:9",
        "http://usr:Zq9%zz@127.0.0.1:9",
        "http://usr:Zq9@[::1:9",
        "http://usr:Zq9@127.0.0.1:99999",
        "http://usr:Zq9@:8080"
    ) + numericPrefixShapes

    // java.net.URI reports no host for these targets, but the URL class that opens the connection
    // does, so the proxy decision has to use the URL view. Maps each target to the host to exclude.
    private val targetsWithoutAUriHost = mapOf(
        "https://127.1:9/api" to "127.1",
        "https://my_host.localhost/api" to "my_host.localhost",
        "https://bücher.example/api" to "bücher.example"
    )

    private val tunnelingSchemesProperty = "jdk.http.auth.tunneling.disabledSchemes"
    private var tunnelingSchemesBefore: String? = null

    @BeforeTest
    fun captureTunnelingSchemes() {
        tunnelingSchemesBefore = System.getProperty(tunnelingSchemesProperty)
    }

    // Registering a proxy credential mutates three pieces of process-wide state: the default
    // Authenticator, the ProxyAuthenticator credential store, and the JDK's tunneling-schemes
    // property. Gradle runs the whole suite in one JVM, so all three have to be put back or they
    // stay visible to every test that follows, including the weakened tunneling default.
    @AfterTest
    fun restoreGlobalProxyState() {
        Authenticator.setDefault(null)
        ProxyAuthenticator.reset()
        val before = tunnelingSchemesBefore
        if (before == null) System.clearProperty(tunnelingSchemesProperty)
        else System.setProperty(tunnelingSchemesProperty, before)
    }

    @Test
    fun explicitProxyUrlWithCredentialsIsParsed() {
        val resolved = resolveProxy("http://user:pass@proxy.local:8080", target, FakeProxyEnvironment())
        assertEquals(Proxy.Type.HTTP, resolved!!.proxy.type())
        val address = resolved.proxy.address() as java.net.InetSocketAddress
        assertEquals("proxy.local", address.hostString)
        assertEquals(8080, address.port)
        assertEquals("user", resolved.username)
        assertEquals("pass", resolved.password)
    }

    @Test
    fun precedenceIsExplicitThenSystemPropsThenEnv() {
        val env = FakeProxyEnvironment(
            envVars = mapOf("HTTPS_PROXY" to "http://env.local:9999"),
            properties = mapOf("https.proxyHost" to "sys.local", "https.proxyPort" to "3128")
        )
        assertEquals("explicit.local", host(resolveProxy("http://explicit.local:1111", target, env)))
        assertEquals("sys.local", host(resolveProxy(null, target, env)))

        val envOnly = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to "http://env.local:9999"))
        assertEquals("env.local", host(resolveProxy(null, target, envOnly)))
    }

    @Test
    fun noProxyExclusionReturnsNull() {
        val exactMatch = FakeProxyEnvironment(
            envVars = mapOf("HTTPS_PROXY" to "http://proxy.local:8080", "NO_PROXY" to "vault.keepersecurity.com")
        )
        assertNull(resolveProxy(null, target, exactMatch))

        val suffixMatch = FakeProxyEnvironment(
            envVars = mapOf("HTTPS_PROXY" to "http://proxy.local:8080", "NO_PROXY" to ".keepersecurity.com")
        )
        assertNull(resolveProxy(null, "https://ksm.keepersecurity.com/path", suffixMatch))
    }

    @Test
    fun noProxyConfiguredReturnsNull() {
        assertNull(resolveProxy(null, target, FakeProxyEnvironment()))
    }

    @Test
    fun explicitProxyUrlIgnoresNoProxy() {
        // NO_PROXY must not override an explicit proxyUrl — the caller opted in deliberately.
        val env = FakeProxyEnvironment(
            envVars = mapOf(
                "NO_PROXY" to "vault.keepersecurity.com",
                "HTTPS_PROXY" to "http://ambient.example.com:9999"
            )
        )
        val resolved = resolveProxy("http://explicit.example.com:1234", target, env)
        assertEquals("explicit.example.com", host(resolved))
    }

    @Test
    fun unparsableExplicitProxyUrlFailsClosed() {
        // An explicit proxyUrl that cannot be parsed must throw rather than fall through to
        // a direct connection — the caller intended to use a proxy.
        assertFailsWith<SecretsManagerException> {
            resolveProxy(":::not-a-url:::", target, FakeProxyEnvironment())
        }
    }

    @Test
    fun unparsableExplicitProxyUrlRedactsCredentials() {
        // Reserved-char passwords (containing '@', spaces) prevent URI parsing, so redactProxyUrl
        // must strip credentials textually rather than relying on URI.getUserInfo().
        val e = assertFailsWith<SecretsManagerException> {
            resolveProxy("http://user:p@ssword@proxy.corp:8080", target, FakeProxyEnvironment())
        }
        assertFalse(e.message!!.contains("p@ssword"), "Password must be redacted in exception message")
        assertTrue(e.message!!.contains("user:***"), "Redacted form must appear in exception message")
    }

    @Test
    fun redactProxyUrlStripsCredentialsTextually() {
        assertEquals("http://user:***@proxy.corp:8080", redactProxyUrl("http://user:p@ssword@proxy.corp:8080"))
        assertEquals("http://user:***@proxy.corp:8080", redactProxyUrl("http://user:pass word@proxy.corp:8080"))
        assertEquals("http://user:***@proxy.corp:8080", redactProxyUrl("http://user:simplepass@proxy.corp:8080"))
        assertEquals("http://user:***@proxy.corp:8080", redactProxyUrl("http://user:a/b@proxy.corp:8080"))
        assertEquals("user:***@proxy.corp:8080", redactProxyUrl("user:pa ss/word@proxy.corp:8080"))
        assertEquals("http://proxy.corp:8080", redactProxyUrl("http://proxy.corp:8080"))
        assertEquals("notaurl", redactProxyUrl("notaurl"))
    }

    @Test
    fun explicitProxyIsMarkedAsExplicit() {
        val resolved = resolveProxy("http://proxy.example.com:8080", target, FakeProxyEnvironment())
        assertTrue(resolved!!.isExplicit)
    }

    @Test
    fun ambientProxyIsNotMarkedAsExplicit() {
        val env = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to "http://proxy.example.com:8080"))
        val resolved = resolveProxy(null, target, env)
        assertFalse(resolved!!.isExplicit)
    }

    @Test
    fun httpsSchemeProxyIsRejectedWhenExplicit() {
        assertFailsWith<SecretsManagerException> {
            resolveProxy("https://proxy.corp:443", target, FakeProxyEnvironment())
        }
    }

    @Test
    fun httpsSchemeAmbientProxyDegradesToNull() {
        // An https:// value in an ambient env var still degrades to null instead of throwing. Raising
        // here is deliberately left for the next major release: https:// is a form other tools accept,
        // so a deployment that sets it for them would start failing on a minor upgrade.
        val env = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to "https://proxy.corp:443"))
        assertNull(resolveProxy(null, target, env))
    }

    @Test
    fun schemeDefaultPortIsHttpElse80() {
        // http:// without a port should default to 80.
        val http = resolveProxy("http://proxy.corp", target, FakeProxyEnvironment())
        assertEquals(80, (http!!.proxy.address() as java.net.InetSocketAddress).port)
    }

    @Test
    fun outOfRangePortForExplicitProxyFailsClosed() {
        assertFailsWith<SecretsManagerException> {
            resolveProxy("http://proxy.corp:99999", target, FakeProxyEnvironment())
        }
    }

    @Test
    fun malformedAmbientProxyRaisesAndDoesNotEchoTheValue() {
        for (variable in listOf("HTTPS_PROXY", "https_proxy")) {
            for (value in malformedAmbientShapes) {
                val env = FakeProxyEnvironment(envVars = mapOf(variable to value))
                val e = assertFailsWith<SecretsManagerException>("expected $variable=$value to be rejected") {
                    resolveProxy(null, target, env)
                }
                // The whole throwable, not just the message: a parser exception attached as the cause
                // would print the value in any stack trace.
                val rendered = e.stackTraceToString()
                assertTrue(e.message.orEmpty().contains(variable), "message must name $variable: ${e.message}")
                assertFalse(rendered.contains("Zq9"), "throwable must not echo the password: $rendered")
                assertFalse(rendered.contains(value), "throwable must not echo the value: $rendered")
            }
        }
    }

    @Test
    fun malformedAmbientProxyFailsBeforeAConnectionIsOpened() {
        for (variable in listOf("HTTPS_PROXY", "https_proxy")) {
            for (value in malformedAmbientShapes) {
                val opener = RecordingOpener()
                val env = FakeProxyEnvironment(envVars = mapOf(variable to value))
                assertFailsWith<SecretsManagerException>("expected $variable=$value to be rejected") {
                    openProxiedConnection(target, null, false, env, opener)
                }
                assertTrue(opener.calls.isEmpty(), "$variable=$value opened a connection before it was rejected")
            }
        }
    }

    @Test
    fun explicitProxyUrlWithTrailingStructureFailsClosed() {
        for (url in numericPrefixShapes) {
            val e = assertFailsWith<SecretsManagerException>("expected $url to be rejected") {
                resolveProxy(url, target, FakeProxyEnvironment())
            }
            assertTrue(e.message.orEmpty().contains("could not be parsed"), "message must say the value could not be parsed: ${e.message}")
            assertFalse(e.stackTraceToString().contains("Zq9"), "throwable must not echo the password")
        }
    }

    @Test
    fun proxyUrlMayEndWithARootPath() {
        // A trailing slash is a common way to write a proxy URL. Only a real path, query or
        // fragment is rejected.
        for (value in listOf("http://proxy.corp:3128/", "http://user:pass@proxy.corp:3128/")) {
            assertEquals("proxy.corp", host(resolveProxy(null, target, FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to value)))), value)
        }
    }

    @Test
    fun targetsWithoutAUriHostFollowTheAmbientProxy() {
        val valid = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to "http://proxy.corp:3128"))
        val malformed = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to "http://usr:Zq9@127.0.0.1:99999"))
        for (url in targetsWithoutAUriHost.keys) {
            assertEquals("proxy.corp", host(resolveProxy(null, url, valid)), "valid proxy: target $url went direct")

            val opener = RecordingOpener()
            assertFailsWith<SecretsManagerException>("malformed value: target $url skipped proxy validation") {
                openProxiedConnection(url, null, false, malformed, opener)
            }
            assertTrue(opener.calls.isEmpty(), "malformed value: target $url opened a connection before it was rejected")
        }
    }

    @Test
    fun noProxyStillExcludesATargetWithoutAUriHost() {
        // Exclusions run before the proxy value is parsed, also when the host comes from the URL view.
        for ((url, excluded) in targetsWithoutAUriHost) {
            val env = FakeProxyEnvironment(
                envVars = mapOf("HTTPS_PROXY" to "http://usr:Zq9@127.0.0.1:99999", "NO_PROXY" to excluded)
            )
            assertNull(resolveProxy(null, url, env), "target $url ignored NO_PROXY=$excluded")
        }
    }

    @Test
    fun openedConnectionFollowsTheRoutingDecisionForATargetWithoutAUriHost() {
        // openProxiedConnection reads the target host a second time to decide Proxy.NO_PROXY, so it
        // needs the same URL view as resolveProxy. Otherwise an excluded host falls back to the
        // JDK's default selector, which can still send it through a proxy.
        for ((url, hostName) in targetsWithoutAUriHost) {
            val proxied = RecordingOpener()
            openProxiedConnection(url, null, false, FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to "http://proxy.corp:3128")), proxied)
            assertEquals("proxy.corp", (proxied.calls.single().second?.address() as? java.net.InetSocketAddress)?.hostString, "target $url was not proxied")

            val excluded = RecordingOpener()
            val env = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to "http://proxy.corp:3128", "NO_PROXY" to hostName))
            openProxiedConnection(url, null, false, env, excluded)
            assertEquals(Proxy.NO_PROXY, excluded.calls.single().second, "target $url is excluded and must connect direct")
        }
    }

    private val badAmbientValue = "http://usr:Zq9@127.0.0.1:99999"
    private val goodAmbientValue = "http://good.corp:3128"

    @Test
    fun explicitProxyUrlWinsOverAMalformedAmbientValue() {
        val env = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to badAmbientValue))
        assertEquals("explicit.corp", host(resolveProxy("http://explicit.corp:8080", target, env)), "explicit proxyUrl must be used")
    }

    @Test
    fun systemPropertyProxyWinsOverAMalformedAmbientValue() {
        val env = FakeProxyEnvironment(
            envVars = mapOf("HTTPS_PROXY" to badAmbientValue),
            properties = mapOf("https.proxyHost" to "sys.local", "https.proxyPort" to "3128")
        )
        assertEquals("sys.local", host(resolveProxy(null, target, env)), "https.proxyHost must be used")
    }

    @Test
    fun noProxyIsAppliedBeforeAMalformedAmbientValueIsParsed() {
        val env = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to badAmbientValue, "NO_PROXY" to "vault.keepersecurity.com"))
        assertNull(resolveProxy(null, target, env), "an excluded host must not trigger parsing of the proxy value")
    }

    @Test
    fun upperCaseVariableDecidesBeforeLowerCase() {
        val validFirst = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to goodAmbientValue, "https_proxy" to badAmbientValue))
        assertEquals("good.corp", host(resolveProxy(null, target, validFirst)), "valid HTTPS_PROXY must hide a malformed https_proxy")

        val malformedFirst = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to badAmbientValue, "https_proxy" to goodAmbientValue))
        assertFailsWith<SecretsManagerException>("malformed HTTPS_PROXY must raise even when https_proxy is valid") {
            resolveProxy(null, target, malformedFirst)
        }
    }

    @Test
    fun partialUserinfoExplicitProxyThrows() {
        // Every incomplete credential shape fails as a config error. The empty-password form is
        // the one a templated proxy URL produces when its password variable goes unset, and it
        // has to fail here rather than reaching the proxy and returning an opaque 407.
        for (url in listOf(
            "http://user@proxy.corp:8080",
            "http://:secret@proxy.corp:8080",
            "http://user:@proxy.corp:8080"
        )) {
            assertFailsWith<SecretsManagerException>("expected $url to be rejected") {
                resolveProxy(url, target, FakeProxyEnvironment())
            }
        }
    }

    @Test
    fun emptyPasswordAmbientProxyIsNotTreatedAsCredentials() {
        // Ambient config never throws, but an empty password must not count as a credential:
        // hasCredentials drives both the Authenticator registration and the 407 message branch.
        val env = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to "http://user:@proxy.corp:8080"))
        val resolved = resolveProxy(null, target, env)
        assertNotNull(resolved)
        assertEquals("proxy.corp", host(resolved))
        assertNull(resolved.password)
        assertFalse(resolved.hasCredentials)
    }

    @Test
    fun blankEnvVarDoesNotMaskLowerPriorityVar() {
        // A set-but-empty HTTPS_PROXY must not hide a valid https_proxy (case variant).
        val env = FakeProxyEnvironment(
            envVars = mapOf("HTTPS_PROXY" to "", "https_proxy" to "http://fallback.corp:3128")
        )
        assertEquals("fallback.corp", host(resolveProxy(null, target, env)))
    }

    @Test
    fun blankSystemPropertyHostDegradesToNull() {
        // An empty https.proxyHost must not produce an unparseable ":443" candidate.
        val env = FakeProxyEnvironment(
            properties = mapOf("https.proxyHost" to "")
        )
        assertNull(resolveProxy(null, target, env))
    }

    @Test
    fun httpProxyHostPropertyIsIgnoredForHttpsTraffic() {
        // The JDK's ProxySelector never applies http.proxyHost to HTTPS URLs.
        // KSM connects only to HTTPS endpoints, so http.proxyHost must have no effect.
        val env = FakeProxyEnvironment(
            properties = mapOf("http.proxyHost" to "legacyproxy.corp", "http.proxyPort" to "3128")
        )
        assertNull(resolveProxy(null, target, env))
    }

    @Test
    fun unparsableAmbientProxyDoesNotForceDirectConnection() {
        // A https.proxyHost the URI parser rejects (underscore host) is left to the JDK's selector.
        // Forcing Proxy.NO_PROXY here would send the request direct past a proxy the JDK may still apply.
        val env = FakeProxyEnvironment(
            properties = mapOf("https.proxyHost" to "my_proxy", "https.proxyPort" to "3128")
        )
        val opener = RecordingOpener()
        openProxiedConnection(target, null, false, env, opener)
        assertEquals(1, opener.calls.size, "exactly one connection must be opened")
        assertNull(opener.calls.single().second, "proxy must be null so the JDK selector stays in charge, not Proxy.NO_PROXY")
    }

    @Test
    fun isExcludedReturnsTrueForNoProxyMatch() {
        val env = FakeProxyEnvironment(
            envVars = mapOf("HTTPS_PROXY" to "http://proxy.local:8080", "NO_PROXY" to "vault.keepersecurity.com")
        )
        assertTrue(isExcluded("vault.keepersecurity.com", env))
    }

    @Test
    fun proxyAuthenticatorAnswersOnlyForRegisteredProxy() {
        ProxyAuthenticator.register("proxy.local", 8080, "u", "p")

        val proxyMatch = Authenticator.requestPasswordAuthentication(
            "proxy.local", null, 8080, "http", "", "basic", null, Authenticator.RequestorType.PROXY
        )
        assertEquals("u", proxyMatch?.userName)

        val serverChallenge = Authenticator.requestPasswordAuthentication(
            "proxy.local", null, 8080, "https", "", "basic", null, Authenticator.RequestorType.SERVER
        )
        assertNull(serverChallenge)

        val otherProxy = Authenticator.requestPasswordAuthentication(
            "other.local", null, 8080, "http", "", "basic", null, Authenticator.RequestorType.PROXY
        )
        assertNull(otherProxy)
    }

    @Test
    fun proxyAuthenticatorResetDropsRegisteredCredentials() {
        // Guards the teardown above: if reset() ever stops emptying the store, a registered
        // credential outlives its test and the leak this test exists to prevent comes back.
        ProxyAuthenticator.register("proxy.local", 8080, "u", "p")
        ProxyAuthenticator.reset()

        val afterReset = Authenticator.requestPasswordAuthentication(
            "proxy.local", null, 8080, "http", "", "basic", null, Authenticator.RequestorType.PROXY
        )
        assertNull(afterReset)
    }

    @Test
    fun proxyAuthFailureMessageBranchContentIsCorrect() {
        // The ambient-credentials branch must only fire when username is non-null.
        // An unauthenticated ambient proxy (no credentials in env var) must use the standard path.
        val standardMsg = proxyAuthFailureMessage("407", isAmbientCredentials = false)
        val ambientMsg = proxyAuthFailureMessage("407", isAmbientCredentials = true)
        assertTrue(standardMsg.contains("proxyUrl"), "Standard message must mention proxyUrl")
        assertTrue(ambientMsg.contains("SecretsManagerOptions"), "Ambient message must point to SecretsManagerOptions")
        assertFalse(ambientMsg.contains("downloadFile"), "Ambient message must not mention downloadFile as a proxyUrl carrier")
        assertTrue(ambientMsg.contains("proxyUrl field"), "Ambient message must mention proxyUrl field in options")
    }

    @Test
    fun redactProxyUrlHandlesSchemeLessUrl() {
        assertEquals("user:***@proxy.corp:8080", redactProxyUrl("user:p@ssword@proxy.corp:8080"))
    }

    @Test
    fun secretsManagerExceptionSerialVersionUidMatchesReleasedJars() {
        assertEquals(
            5401507264959279624L,
            java.io.ObjectStreamClass.lookup(SecretsManagerException::class.java).serialVersionUID
        )
    }

    private fun host(resolved: ResolvedProxy?): String =
        (resolved!!.proxy.address() as java.net.InetSocketAddress).hostString
}
