/**
 * Base class for all errors raised by the Keeper Secrets Manager SDK. Extends Error so existing
 * `catch` handlers keep working; callers that want to distinguish SDK-originated errors from
 * unexpected runtime failures can check `instanceof KeeperError`.
 *
 * This module intentionally has no internal imports so any module can throw KeeperError without
 * creating a circular dependency.
 */
export class KeeperError extends Error {
    constructor(message: string) {
        super(message)
        this.name = 'KeeperError'
        // Restore the prototype chain so `instanceof` works across transpilation targets.
        Object.setPrototypeOf(this, KeeperError.prototype)
    }
}

/**
 * Thrown when the Keeper backend throttles requests (HTTP 403 {"error":"throttled"}) and the
 * SDK has exhausted its automatic retries (MAX_THROTTLE_RETRIES). Extends KeeperError so existing
 * `catch` handlers keep working; callers that want to react specifically to throttling can
 * check `instanceof KeeperThrottleError`.
 */
export class KeeperThrottleError extends KeeperError {
    constructor(message: string) {
        super(message)
        this.name = 'KeeperThrottleError'
        // Restore the prototype chain so `instanceof` works across transpilation targets.
        Object.setPrototypeOf(this, KeeperThrottleError.prototype)
    }
}

/**
 * Why a crypto operation on one key/item failed, classified by the caller (which mode it
 * requested) rather than by inspecting the thrown error - Node's OpenSSL and the browser's
 * WebCrypto throw differently-shaped errors for the same failure, so sniffing error text or
 * class names would classify the two platforms inconsistently.
 *
 * - 'integrity': an authenticated (AES-GCM) decrypt failed its tag check - the ciphertext or key
 *   was modified or does not match.
 * - 'format': an unauthenticated (AES-256-CBC) decrypt failed - CBC has no MAC, so this means
 *   malformed input or padding, never a verified integrity failure. A CBC decrypt can also
 *   succeed on tampered input (see 'malformed-data'), so CBC success proves nothing either way.
 * - 'missing-key': the key needed to perform the operation could not be found.
 * - 'malformed-data': decryption succeeded but the resulting plaintext was not the expected
 *   shape (for example, not valid JSON). Most often reached via a CBC decrypt that succeeded on
 *   tampered ciphertext without producing the original plaintext.
 * - 'unknown': the failure did not originate from a classified step.
 */
export type KeeperCryptoFailureReason = 'integrity' | 'format' | 'missing-key' | 'malformed-data' | 'unknown'

/**
 * Thrown for a classifiable crypto failure while processing one identified item (a folder,
 * record, etc.), so a caller can distinguish e.g. a tampered/corrupt key (`integrity`) from one
 * that is simply not present yet (`missing-key`) instead of seeing an opaque, unclassified error.
 */
export class KeeperCryptoError extends KeeperError {
    constructor(message: string, public readonly failure: KeeperCryptoFailureReason, public readonly uid: string) {
        super(message)
        this.name = 'KeeperCryptoError'
        // Restore the prototype chain so `instanceof` works across transpilation targets.
        Object.setPrototypeOf(this, KeeperCryptoError.prototype)
    }
}

/**
 * Passed to `SecretManagerOptions.onDecryptionError` for each item skipped because it could not
 * be decrypted, so a caller can react (e.g. log, alert, or throw to fail closed) instead of only
 * seeing a partial result with no indication anything was omitted.
 */
export type KeeperDecryptionErrorInfo = {
    uid: string
    failure: KeeperCryptoFailureReason
    message: string
}
