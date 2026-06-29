package com.keepersecurity.secretsManager.core

import java.net.Authenticator
import java.net.InetSocketAddress
import java.net.PasswordAuthentication
import java.net.Proxy
import java.net.URI
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.HttpsURLConnection

internal data class ResolvedProxy(val proxy: Proxy, val username: String?, val password: String?)

/**
 * Seam over the ambient environment so proxy resolution stays deterministic under test.
 * Production uses the real process environment and JVM system properties.
 */
internal interface ProxyEnvironment {
    fun env(name: String): String?
    fun property(name: String): String?
}

internal object SystemProxyEnvironment : ProxyEnvironment {
    override fun env(name: String): String? = System.getenv(name)
    override fun property(name: String): String? = System.getProperty(name)
}

/**
 * Resolves the proxy for a target URL, or null when no proxy applies (caller then opens a direct
 * connection). Precedence: explicit proxyUrl, then JVM system properties (https/http.proxyHost),
 * then HTTP(S)_PROXY environment variables. NO_PROXY / http.nonProxyHosts exclude the target.
 */
internal fun resolveProxy(
    explicitProxyUrl: String?,
    targetUrl: String,
    environment: ProxyEnvironment = SystemProxyEnvironment
): ResolvedProxy? {
    val targetHost = runCatching { URI(targetUrl).host }.getOrNull() ?: return null
    if (isExcluded(targetHost, environment)) return null

    val candidate = explicitProxyUrl?.takeIf { it.isNotBlank() }
        ?: systemPropertyProxy(environment)
        ?: environment.env("HTTPS_PROXY") ?: environment.env("https_proxy")
        ?: environment.env("HTTP_PROXY") ?: environment.env("http_proxy")
        ?: return null

    return parseProxy(candidate)
}

private fun systemPropertyProxy(environment: ProxyEnvironment): String? {
    val host = environment.property("https.proxyHost") ?: environment.property("http.proxyHost") ?: return null
    val isHttps = environment.property("https.proxyHost") != null
    val port = (if (isHttps) environment.property("https.proxyPort") else environment.property("http.proxyPort"))
        ?: if (isHttps) "443" else "80"
    return "$host:$port"
}

private fun parseProxy(raw: String): ResolvedProxy? {
    val normalized = if (raw.contains("://")) raw else "http://$raw"
    val uri = runCatching { URI(normalized) }.getOrNull() ?: return null
    val host = uri.host ?: return null
    val port = if (uri.port != -1) uri.port else 80
    val userInfo = uri.userInfo
    val username = userInfo?.substringBefore(':')?.takeIf { it.isNotEmpty() }
    val password = userInfo?.substringAfter(':', "")?.takeIf { userInfo.contains(':') }
    val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress(host, port))
    return ResolvedProxy(proxy, username, password)
}

private fun isExcluded(host: String, environment: ProxyEnvironment): Boolean {
    val noProxy = environment.env("NO_PROXY") ?: environment.env("no_proxy")
    val nonProxyHosts = environment.property("http.nonProxyHosts")
    val patterns = buildList {
        noProxy?.split(',')?.forEach { add(it.trim()) }
        nonProxyHosts?.split('|')?.forEach { add(it.trim()) }
    }.filter { it.isNotEmpty() }
    val lowerHost = host.lowercase(Locale.ROOT)
    return patterns.any { pattern ->
        val p = pattern.lowercase(Locale.ROOT).removePrefix("*").removePrefix(".")
        pattern == "*" || lowerHost == p || lowerHost.endsWith(".$p")
    }
}

/**
 * Opens an HTTPS connection through the resolved proxy (or directly when none applies), applying
 * the cert-verification bypass and registering proxy credentials when present.
 */
internal fun openProxiedConnection(
    targetUrl: String,
    explicitProxyUrl: String?,
    allowUnverifiedCertificate: Boolean,
    environment: ProxyEnvironment = SystemProxyEnvironment
): HttpsURLConnection {
    val resolved = resolveProxy(explicitProxyUrl, targetUrl, environment)
    val url = URI.create(targetUrl).toURL()
    val connection = (if (resolved != null) url.openConnection(resolved.proxy) else url.openConnection())
        as HttpsURLConnection
    if (allowUnverifiedCertificate) {
        connection.sslSocketFactory = trustAllSocketFactory()
    }
    if (resolved?.username != null && resolved.password != null) {
        val address = resolved.proxy.address() as InetSocketAddress
        ProxyAuthenticator.register(address.hostString, address.port, resolved.username, resolved.password)
    }
    return connection
}

/**
 * KSM endpoints are HTTPS, so authenticated proxies are reached via a CONNECT tunnel. On Java 8 the
 * only way to supply tunnel credentials is the process-global default Authenticator, so this is
 * installed lazily (only when an authenticated proxy is actually used) and answers solely for the
 * registered proxy host/port. Migrating to per-connection HttpURLConnection.setAuthenticator is a
 * Java 9+ change tracked for the next major.
 */
internal object ProxyAuthenticator : Authenticator() {
    private data class Credential(val username: String, val password: CharArray)

    private val credentials = ConcurrentHashMap<String, Credential>()

    @Volatile
    private var installed = false

    fun register(host: String, port: Int, username: String, password: String) {
        credentials[key(host, port)] = Credential(username, password.toCharArray())
        enableBasicProxyAuthOverTunnel()
        install()
    }

    @Synchronized
    private fun install() {
        if (!installed) {
            Authenticator.setDefault(this)
            installed = true
        }
    }

    override fun getPasswordAuthentication(): PasswordAuthentication? {
        if (requestorType != RequestorType.PROXY) return null
        val credential = credentials[key(requestingHost, requestingPort)] ?: return null
        return PasswordAuthentication(credential.username, credential.password.clone())
    }

    private fun key(host: String, port: Int) = "${host.lowercase(Locale.ROOT)}:$port"
}

/**
 * Basic auth on HTTPS CONNECT tunnels is disabled by default since 8u111. Clear it (best effort,
 * unless the host app set it explicitly) so authenticated proxies work. May still require the
 * -Djdk.http.auth.tunneling.disabledSchemes= JVM flag if a tunneled connection was opened earlier.
 */
private fun enableBasicProxyAuthOverTunnel() {
    val property = "jdk.http.auth.tunneling.disabledSchemes"
    if (System.getProperty(property) == null) {
        System.setProperty(property, "")
    }
}
