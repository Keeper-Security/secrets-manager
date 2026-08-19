package com.keepersecurity.secretsManager.core

import java.net.Authenticator
import java.net.Proxy
import kotlin.test.Test
import kotlin.test.AfterTest
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
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

    @AfterTest
    fun clearGlobalAuthenticator() {
        Authenticator.setDefault(null)
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
        // An https:// value in an ambient env var degrades gracefully instead of throwing.
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
    fun outOfRangePortForAmbientProxyDegradesToNull() {
        val env = FakeProxyEnvironment(envVars = mapOf("HTTPS_PROXY" to "http://proxy.corp:99999"))
        assertNull(resolveProxy(null, target, env))
    }

    @Test
    fun partialUserinfoExplicitProxyThrows() {
        assertFailsWith<SecretsManagerException> {
            resolveProxy("http://user@proxy.corp:8080", target, FakeProxyEnvironment())
        }
    }

    @Test
    fun blankEnvVarDoesNotMaskLowerPriorityVar() {
        // A set-but-empty HTTPS_PROXY must not hide a valid HTTP_PROXY.
        val env = FakeProxyEnvironment(
            envVars = mapOf("HTTPS_PROXY" to "", "HTTP_PROXY" to "http://fallback.corp:3128")
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
        // A proxy candidate that fails parseProxy (e.g. underscore hostname rejected by URI) must
        // fall through without forcing Proxy.NO_PROXY — isExcluded() is the only exclusion signal.
        // We verify this by checking that isExcluded returns false for a non-excluded host even
        // when systemPropertyProxy produces a candidate that is then rejected.
        val env = FakeProxyEnvironment(
            properties = mapOf("https.proxyHost" to "my_proxy", "https.proxyPort" to "3128")
        )
        // resolveProxy returns null when the ambient candidate can't be parsed AND the host is not
        // excluded — the caller (openProxiedConnection) must fall back to the system ProxySelector,
        // not force Proxy.NO_PROXY.
        val resolved = resolveProxy(null, target, env)
        assertNull(resolved)
        // The host is NOT excluded, so isExcluded must return false.
        assertFalse(isExcluded("vault.keepersecurity.com", env))
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
    fun proxyAuthFailureMessageAmbientBranchRequiresCredentials() {
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
