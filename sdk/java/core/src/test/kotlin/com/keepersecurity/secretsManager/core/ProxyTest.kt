package com.keepersecurity.secretsManager.core

import java.net.Authenticator
import java.net.Proxy
import kotlin.test.Test
import kotlin.test.AfterTest
import kotlin.test.assertEquals
import kotlin.test.assertNull

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

    private fun host(resolved: ResolvedProxy?): String =
        (resolved!!.proxy.address() as java.net.InetSocketAddress).hostString
}
