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
