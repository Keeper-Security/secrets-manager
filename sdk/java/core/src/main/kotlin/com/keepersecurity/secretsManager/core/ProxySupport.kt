package com.keepersecurity.secretsManager.core

import java.io.IOException
import java.net.Authenticator
import java.net.HttpURLConnection.HTTP_PROXY_AUTH
import java.net.InetSocketAddress
import java.net.PasswordAuthentication
import java.net.Proxy
import java.net.URI
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.HttpsURLConnection

internal data class ResolvedProxy(val proxy: Proxy, val username: String?, val password: String?, val isExplicit: Boolean = false) {
    val hasCredentials: Boolean get() = username != null && password != null
    override fun toString(): String =
        "ResolvedProxy(proxy=$proxy, username=$username, " +
        "password=${if (password != null) "<redacted>" else null}, isExplicit=$isExplicit)"
}

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
    // Explicit proxyUrl is authoritative: NO_PROXY / http.nonProxyHosts do not override it,
    // and an unparseable value fails closed rather than falling through to a direct connection.
    // Checked before parsing targetUrl so that non-URI-parseable hosts (e.g. underscore names
    // that java.net.URI rejects but java.net.URL connects to) still honour an explicit proxy.
    if (!explicitProxyUrl.isNullOrBlank()) {
        return parseProxy(explicitProxyUrl, isExplicit = true)
            ?: throw SecretsManagerException("proxyUrl '${redactProxyUrl(explicitProxyUrl)}' could not be parsed as a valid proxy URL")
    }

    val targetHost = runCatching { URI(targetUrl).host }.getOrNull() ?: return null

    // Ambient proxy: apply exclusions before selecting a candidate.
    if (isExcluded(targetHost, environment)) return null
    // HTTP_PROXY / http_proxy are intentionally excluded: all KSM traffic is HTTPS, and routing
    // it through an http-scoped proxy setting would silently proxy traffic the operator may not
    // have intended (same reasoning as the http.proxyHost exclusion above).
    val candidate = systemPropertyProxy(environment)
        ?: environment.env("HTTPS_PROXY")?.takeIf { it.isNotBlank() }
        ?: environment.env("https_proxy")?.takeIf { it.isNotBlank() }
        ?: return null

    return parseProxy(candidate, isExplicit = false)
}

private fun systemPropertyProxy(environment: ProxyEnvironment): String? {
    // Only https.proxyHost is honored: all KSM traffic is HTTPS, and the JDK's own ProxySelector
    // never applies http.proxyHost to HTTPS URLs. Applying it here would silently proxy traffic
    // the operator may not have intended to route through that host.
    val host = environment.property("https.proxyHost")?.takeIf { it.isNotBlank() } ?: return null
    val port = environment.property("https.proxyPort")?.takeIf { it.isNotBlank() } ?: "443"
    return "$host:$port"
}

private fun parseProxy(raw: String, isExplicit: Boolean = false): ResolvedProxy? {
    val normalized = if (raw.contains("://")) raw else "http://$raw"
    val uri = runCatching { URI(normalized) }.getOrNull() ?: return null
    val host = uri.host ?: return null

    // The JDK's HttpURLConnection cannot speak TLS to a proxy. An https:// proxy URL misleads
    // callers into thinking TLS is used between the client and the proxy when it is not.
    if (uri.scheme?.equals("https", ignoreCase = true) == true) {
        if (isExplicit) throw SecretsManagerException(
            "Invalid proxy URL: HTTPS proxies are not supported by the JDK's HttpURLConnection. " +
            "Use an http:// proxy URL. The SDK still connects to KSM over HTTPS regardless of the proxy scheme."
        )
        return null
    }

    // https:// proxy URLs are rejected above; no need to handle the https scheme here.
    val port = if (uri.port != -1) uri.port else 80
    val userInfo = uri.userInfo
    val username = userInfo?.substringBefore(':')?.takeIf { it.isNotEmpty() }
    // An empty half is not a credential: it yields null here exactly as a missing half does, so
    // hasCredentials stays false and the check below sees both cases the same way.
    val password = userInfo?.substringAfter(':', "")?.takeIf { it.isNotEmpty() }

    // Credentials in explicit config must be complete. Rejecting an empty half alongside a missing
    // one turns http://user@host, http://:secret@host and http://user:@host into the same config
    // error, instead of letting the last one reach the proxy and come back as an opaque 407. A
    // templated URL whose password variable went unset (http://$USER:$PASS@host) is the usual way
    // that shape appears.
    if (isExplicit && userInfo != null && (username == null || password == null)) {
        throw SecretsManagerException("Invalid proxy URL: both username and password are required (format: http://user:pass@host:port)")
    }

    // Use createUnresolved to defer DNS to connection time, avoiding two round-trips per request
    // and preventing .local / mDNS lookups from blocking proxy-resolution in tests.
    val proxy = runCatching {
        Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved(host, port))
    }.getOrElse { e ->
        if (isExplicit) throw SecretsManagerException("Invalid proxy URL: port out of range (0-65535)", e)
        return null
    }
    return ResolvedProxy(proxy, username, password, isExplicit)
}

internal fun isExcluded(host: String, environment: ProxyEnvironment): Boolean {
    val noProxy = environment.env("NO_PROXY")?.takeIf { it.isNotBlank() }
        ?: environment.env("no_proxy")?.takeIf { it.isNotBlank() }
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
    val targetHost = runCatching { URI(targetUrl).host }.getOrNull()
    val resolved = resolveProxy(explicitProxyUrl, targetUrl, environment)

    // When the host is explicitly excluded by NO_PROXY/http.nonProxyHosts, force a direct
    // connection with Proxy.NO_PROXY so the JDK's default ProxySelector cannot re-introduce a
    // proxy that the operator has opted out of. An unparseable ambient proxy that falls through
    // resolveProxy as null is NOT treated as an exclusion — only isExcluded() determines that.
    val isExcluded = resolved == null && targetHost != null && isExcluded(targetHost, environment)

    // Only register the JVM-wide Authenticator when the proxy (and its credentials) came from the
    // caller's explicit proxyUrl option, not from ambient env variables. Ambient env credentials
    // are owned by the host application; overriding the default Authenticator from them would
    // silently interfere with other libraries that installed their own Authenticator.
    // Must run before openConnection(): the JDK reads jdk.http.auth.tunneling.disabledSchemes
    // into a static field the first time HttpURLConnection's class is loaded, so clearing it
    // afterward has no effect on this connection.
    if (resolved?.isExplicit == true && resolved.hasCredentials) {
        val address = resolved.proxy.address() as InetSocketAddress
        ProxyAuthenticator.register(address.hostString, address.port, resolved.username!!, resolved.password!!)
    }
    val url = URI.create(targetUrl).toURL()
    val proxy = when {
        resolved != null -> resolved.proxy
        isExcluded -> Proxy.NO_PROXY
        else -> null
    }
    val connection = (if (proxy != null) url.openConnection(proxy) else url.openConnection())
        as HttpsURLConnection
    if (allowUnverifiedCertificate) {
        connection.sslSocketFactory = trustAllSslSocketFactory()
    }
    return connection
}

/**
 * Reads the response code, turning an authenticated-proxy rejection (407) into a clear,
 * actionable [SecretsManagerException] instead of a bare status code or opaque IOException.
 *
 * A 407 here almost always means the JDK's own jdk.http.auth.tunneling.disabledSchemes guard
 * (see openProxiedConnection) was already locked to its default "Basic disabled" value by an
 * earlier HTTPS connection somewhere in this process, before this call had a chance to clear it.
 * That guard can only be cleared before the *first* HTTPS connection in the JVM, and no runtime
 * code can undo it retroactively.
 */
internal fun HttpsURLConnection.checkedResponseCode(
    explicitProxyUrl: String?,
    targetUrl: String,
    environment: ProxyEnvironment = SystemProxyEnvironment
): Int {
    val resolved = resolveProxy(explicitProxyUrl, targetUrl, environment)
    val requiresProxyAuth = resolved?.hasCredentials ?: false
    if (!requiresProxyAuth) {
        return responseCode
    }
    val isAmbientCredentials = !resolved!!.isExplicit
    return try {
        val code = responseCode
        if (code == HTTP_PROXY_AUTH) throw SecretsManagerException(proxyAuthFailureMessage(null, isAmbientCredentials)) else code
    } catch (e: IOException) {
        // The JDK surfaces "Unable to tunnel through proxy. Proxy returns 'HTTP/1.1 407 ...'" as
        // an IOException on the response-code read. Check for "407" specifically to avoid
        // misclassifying legitimate proxy 502/503/504 tunnel errors as auth failures.
        if (e.message?.contains("407") == true) {
            throw SecretsManagerException(proxyAuthFailureMessage(e.message, isAmbientCredentials), e)
        }
        throw e
    }
}

internal fun proxyAuthFailureMessage(cause: String?, isAmbientCredentials: Boolean = false): String {
    val baseMessage = "Authenticated proxy rejected the connection (407 Proxy Authentication Required)" +
        (cause?.let { ": $it" } ?: "")
    val guidance = if (isAmbientCredentials) {
        ". Credentials were detected in environment variables (HTTP_PROXY, HTTPS_PROXY, etc.) " +
        "but were not registered with the JVM Authenticator because no explicit proxyUrl was passed " +
        "to the SDK. Registering the global Authenticator from ambient environment variables risks " +
        "interfering with other libraries in the same process. To use the proxy credentials, set " +
        "the proxyUrl field in SecretsManagerOptions with the full authenticated proxy URL."
    } else {
        ". First, double-check the proxy username/password in proxyUrl. If those are correct, " +
        "the likely cause is that this JVM already made an HTTPS connection before this one: Java " +
        "disables Basic auth over HTTPS CONNECT tunnels by default (CVE-2016-5597 mitigation), and " +
        "that default locks in the first time any HTTPS connection is made in the process, so the " +
        "SDK's own attempt to clear it then comes too late, and Java won't have even attempted to " +
        "send credentials (a 407 looks the same either way). Set the JVM property " +
        "jdk.http.auth.tunneling.disabledSchemes to an empty value at process startup, before any " +
        "other HTTPS traffic: pass -Djdk.http.auth.tunneling.disabledSchemes= on the java command " +
        "line, or set it via the JDK_JAVA_OPTIONS environment variable (Java 9+) or " +
        "_JAVA_OPTIONS/JAVA_TOOL_OPTIONS (Java 8)."
    }
    return baseMessage + guidance
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

    fun register(host: String, port: Int, username: String, password: String) {
        credentials[key(host, port)] = Credential(username, password.toCharArray())
        enableBasicProxyAuthOverTunnel()
        // Re-asserted on every call rather than once: Authenticator.getDefault() (needed to check
        // whether we're still installed) isn't available until Java 9, and the default can be
        // silently replaced or cleared by anything else in the process (other libraries, test
        // cleanup) between connections.
        Authenticator.setDefault(this)
    }

    override fun getPasswordAuthentication(): PasswordAuthentication? {
        if (requestorType != RequestorType.PROXY) return null
        val credential = credentials[key(requestingHost, requestingPort)] ?: return null
        return PasswordAuthentication(credential.username, credential.password.clone())
    }

    private fun key(host: String, port: Int) = "${host.lowercase(Locale.ROOT)}:$port"
}

/**
 * Strips credentials from a proxy URL for safe use in error messages without risking credential
 * exposure. Works textually rather than via URI parsing so it handles reserved-character passwords
 * (containing '@', spaces, or other characters that make URI parsing fail).
 */
internal fun redactProxyUrl(proxyUrl: String): String {
    val schemeEnd = proxyUrl.indexOf("://")
    val authorityStart = if (schemeEnd < 0) 0 else schemeEnd + 3
    val afterScheme = proxyUrl.substring(authorityStart)
    val atIndex = afterScheme.lastIndexOf('@')
    if (atIndex < 0) return proxyUrl
    val userInfo = afterScheme.substring(0, atIndex)
    val colonIndex = userInfo.indexOf(':')
    val redactedUserInfo = if (colonIndex >= 0) {
        userInfo.substring(0, colonIndex) + ":***"
    } else {
        "$userInfo:***"
    }
    return proxyUrl.substring(0, authorityStart) + redactedUserInfo + "@" + afterScheme.substring(atIndex + 1)
}

/**
 * Basic auth on HTTPS CONNECT tunnels is disabled by default since 8u111. Clear it (best effort,
 * unless the host app set it explicitly) so authenticated proxies work. May still require the
 * -Djdk.http.auth.tunneling.disabledSchemes= JVM flag if a tunneled connection was opened earlier.
 *
 * The property is JVM-wide, so clearing it re-enables Basic over CONNECT for every
 * HttpURLConnection in the process, not only this SDK's. Two things keep that scoped: it runs only
 * when the caller supplied credentials in an explicit proxyUrl, and a value the host application
 * already set is left untouched.
 */
private fun enableBasicProxyAuthOverTunnel() {
    val property = "jdk.http.auth.tunneling.disabledSchemes"
    if (System.getProperty(property) == null) {
        System.setProperty(property, "")
    }
}

/**
 * Builds a socket factory that trusts all certificates. Used only when
 * SecretsManagerOptions.allowUnverifiedCertificate is set, and kept private to this file so it
 * is not accessible as a public API entry point from consumer code.
 */
private fun trustAllSslSocketFactory(): javax.net.ssl.SSLSocketFactory {
    val trustAllCerts: Array<javax.net.ssl.TrustManager> = arrayOf(
        object : javax.net.ssl.X509TrustManager {
            private val acceptedIssuers = arrayOf<java.security.cert.X509Certificate>()
            override fun checkClientTrusted(certs: Array<java.security.cert.X509Certificate?>?, authType: String?) {}
            override fun checkServerTrusted(certs: Array<java.security.cert.X509Certificate?>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = acceptedIssuers
        }
    )
    val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
    try {
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())
    } catch (e: java.security.NoSuchAlgorithmException) {
        e.printStackTrace()
    } catch (e: java.security.KeyManagementException) {
        e.printStackTrace()
    }
    return sslContext.socketFactory
}
