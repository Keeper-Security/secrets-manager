@file:JvmName("SecretsManagerException")

package com.keepersecurity.secretsManager.core

open class SecretsManagerException : Exception {
    companion object {
        // Pins the SUID to the value computed for the original single-constructor shape so jars
        // built before this PR can deserialize exceptions from jars built after it (e.g. Jenkins
        // controller/agent remoting). private const val generates private static final in bytecode,
        // which is the conventional form recognized by ObjectStreamClass.
        private const val serialVersionUID: Long = 5401507264959279624L
    }

    constructor(message: String) : super(message)
    constructor(message: String, cause: Throwable?) : super(message, cause)
}

internal class SecureRandomException(message: String): SecretsManagerException(message)
internal class SecureRandomSlowGenerationException(message: String): SecretsManagerException(message)

/**
 * Thrown when the Keeper backend throttles requests (HTTP 403 {"error":"throttled"}) and the SDK
 * has exhausted its automatic retries (see MAX_THROTTLE_RETRIES). Public so callers can catch
 * throttling specifically; extends Exception so existing `catch (e: Exception)` handlers still work.
 */
class KeeperThrottleException(message: String): Exception(message)
