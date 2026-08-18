@file:JvmName("SecretsManagerException")

package com.keepersecurity.secretsManager.core

open class SecretsManagerException : Exception {
    companion object {
        // Explicit serialVersionUID matches the computed value of the original single-constructor
        // shape, maintaining serialization compatibility with jars built before this PR.
        @JvmField
        val serialVersionUID: Long = 4308841855089494389L
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
