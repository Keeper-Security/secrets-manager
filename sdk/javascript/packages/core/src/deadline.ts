import {KeeperError} from './errors'

export const DEFAULT_REQUEST_TIMEOUT_MS = 30000

// setTimeout stores its delay in a 32-bit signed integer. Anything larger silently becomes a 1ms
// delay (Node also prints a TimeoutOverflowWarning), which would abort the request almost
// immediately, the exact opposite of what a caller asking for a very long timeout wants. Clamp
// to the ceiling instead, roughly 24.8 days, which is indistinguishable from "no timeout" in
// practice while keeping the request bounded.
export const MAX_REQUEST_TIMEOUT_MS = 2147483647

export type Deadline = {
    signal: AbortSignal | undefined
    // The timeout actually in force, after defaulting and clamping. Callers report this in their
    // timeout message so the message can never name a value that was not applied.
    timeoutMs: number
    clear: () => void
}

/**
 * Resolve a caller-supplied timeout to the value that will actually be enforced.
 *
 * Undefined and null take the default. Everything else must be a finite number of at least 1:
 * 0, negatives, NaN and Infinity all collapse to a near-instant setTimeout, so accepting them
 * would turn a configuration mistake into every request failing in a couple of milliseconds
 * under an error message claiming a long timeout had elapsed.
 *
 * Throws a plain Error, not KeeperError: this rejects a bad argument before any request is
 * attempted, matching this SDK's convention that KeeperError signals a failed interaction with
 * Keeper's backend, not a caller-input/config mistake.
 */
export const resolveTimeoutMs = (timeoutMs?: number | null): number => {
    if (timeoutMs === undefined || timeoutMs === null) {
        return DEFAULT_REQUEST_TIMEOUT_MS
    }
    if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs < 1) {
        throw new Error(`Request timeout must be a finite number of milliseconds of at least 1, got ${timeoutMs}`)
    }
    return Math.min(Math.floor(timeoutMs), MAX_REQUEST_TIMEOUT_MS)
}

/**
 * A fixed deadline for a single network exchange, as a plain AbortController rather than the
 * AbortSignal.timeout() shorthand.
 *
 * Node's http.request(...) treats its own `timeout` option as an idle timer that resets on socket
 * activity, not a deadline, so a server can hold a request open indefinitely by trickling bytes.
 * Both platforms therefore need a signal that fires at a fixed point in time regardless of
 * activity. AbortController's support is also broader than AbortSignal.timeout()'s, so this avoids
 * hard-failing every request on older runtimes that lack the newer static method.
 *
 * The deadline must stay armed until the exchange is fully settled, response body included, and
 * callers must then call clear() or the underlying setTimeout outlives the request.
 */
export const deadlineSignal = (timeoutMs?: number | null): Deadline => {
    const ms = resolveTimeoutMs(timeoutMs)
    if (typeof AbortController === 'undefined') {
        return {signal: undefined, timeoutMs: ms, clear: () => {}}
    }
    const controller = new AbortController()
    const timer: any = setTimeout(() => controller.abort(), ms)
    // Node's Timeout object supports unref() so this timer alone can't keep the process alive if
    // the caller never settles (a thrown or mocked request, for instance); browsers' setTimeout
    // returns a plain number with no such method.
    timer.unref?.()
    return {signal: controller.signal, timeoutMs: ms, clear: () => clearTimeout(timer)}
}

/**
 * Validate a caller-supplied timeout at the public API boundary, and return the resolved value.
 *
 * resolveTimeoutMs() already rejects unusable values and clamps/floors the rest, but it only ran
 * inside deadlineSignal() on the platform call. A caller who supplies their own queryFunction, or
 * hits the offline cache, would otherwise get the raw, unresolved value: a fractional timeout, or
 * one above MAX_REQUEST_TIMEOUT_MS, would reach them unclamped even though the SDK's own network
 * calls never see it that way. Returning the resolved value here keeps that guarantee uniform.
 *
 * Undefined and null pass through untouched: they mean "not set", and the default is applied
 * later by resolveTimeoutMs rather than being frozen in at this layer.
 */
export const validateTimeoutMs = <T extends number | null | undefined>(timeoutMs: T): T => {
    if (timeoutMs === undefined || timeoutMs === null) {
        return timeoutMs
    }
    return resolveTimeoutMs(timeoutMs) as T
}

/**
 * Storage backend file download, thumbnail and upload URLs carry an AWS SigV4 signature in the
 * query string (an 8-hour bearer credential, confirmed against the backend's
 * DownloadRequestFactory). A timeout message embedding the full URL would leak that signature
 * into whatever logs the caller's catch-all error handler writes to. Stripped unconditionally,
 * since a future caller could route a bearer-style URL through post() or fileUpload() too.
 */
const truncateUrlForError = (url: string): string => {
    try {
        const parsed = new URL(url)
        return `${parsed.origin}${parsed.pathname}`
    } catch {
        return url.split('?')[0]
    }
}

/** Message used by both platforms so a timeout reads identically wherever it is raised. */
export const timeoutError = (url: string, timeoutMs: number): KeeperError =>
    new KeeperError(`Request to ${truncateUrlForError(url)} timed out after ${timeoutMs}ms`)
