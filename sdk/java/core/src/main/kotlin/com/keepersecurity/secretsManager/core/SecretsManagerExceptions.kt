@file:JvmName("SecretsManagerException")

package com.keepersecurity.secretsManager.core

/**
 * Base type for errors raised by this SDK.
 *
 * [cause] is optional so a wrapped failure can keep the underlying exception and its stack trace.
 * `@JvmOverloads` keeps the single-argument form Java callers and subclasses already compile against.
 */
open class SecretsManagerException @JvmOverloads constructor(
    message: String,
    cause: Throwable? = null
): Exception(message, cause) {
    companion object {
        // Pins the SUID to the value computed for the original single-constructor shape so jars
        // built before this change can deserialize exceptions from jars built after it (e.g. Jenkins
        // controller/agent remoting). private const val generates private static final in bytecode,
        // which is the conventional form recognized by ObjectStreamClass.
        private const val serialVersionUID: Long = 5401507264959279624L
    }
}

/**
 * A failure of a [RequestSigner] or an [AppKeyProtector] whose message is safe to show to people.
 *
 * The SDK shows only the class name of other signer and protector failures, because their messages can hold a PIN
 * or key material. For this type, the SDK error text also shows the message, after the class name. It never shows
 * the messages of the causes. Control and format characters become spaces, and text after 500 characters is cut.
 *
 * Use it only for text that holds no secret, for example "Wrong PIN, 2 retries left" or "No device found". Never
 * put a PIN, a key, a token, or decrypted data in the message.
 */
open class SafeMessageException @JvmOverloads constructor(
    message: String,
    cause: Throwable? = null
): SecretsManagerException(message, cause)

internal class SecureRandomException(message: String): SecretsManagerException(message)
internal class SecureRandomSlowGenerationException(message: String): SecretsManagerException(message)

/**
 * Thrown when the Keeper backend throttles requests (HTTP 429 {"error":"throttled"}) and the SDK
 * has exhausted its automatic retries (see MAX_THROTTLE_RETRIES). Public so callers can catch
 * throttling specifically; extends Exception so existing `catch (e: Exception)` handlers still work.
 */
class KeeperThrottleException(message: String): Exception(message)
