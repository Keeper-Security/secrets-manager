import {platform} from "./platform";

// Single source of truth for the app-key storage slot; keeper.ts imports this rather than
// declaring its own copy of the literal.
export const KEY_APP_KEY = 'appKey'

const CACHE_KEY_LABEL = new TextEncoder().encode('KSM-cache-v1')
export const CACHE_FORMAT_VERSION = 0x02
export const DEFAULT_MAX_CACHE_AGE_MS = 24 * 60 * 60 * 1000

// No Buffer here - this module is shared with the browser bundle, which has no Buffer global.
// Exported so callers building the plaintext to cache (transmission key + response body) get
// the same non-boxing copy this module already uses internally, instead of a slower
// spread-into-array (measured ~440x slower for a 50MB payload, since that boxes every byte
// through an intermediate JS array).
export const concatBytes = (...parts: Uint8Array[]): Uint8Array => {
    const length = parts.reduce((sum, part) => sum + part.length, 0)
    const out = new Uint8Array(length)
    let offset = 0
    for (const part of parts) {
        out.set(part, offset)
        offset += part.length
    }
    return out
}

const readTimestamp = (data: Uint8Array): number => {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
    return Number(view.getBigUint64(0, false))
}

const writeTimestamp = (ms: number): Uint8Array => {
    const out = new Uint8Array(8)
    new DataView(out.buffer).setBigUint64(0, BigInt(ms), false)
    return out
}

// Under useObjects: true (browser), unwrap() stores the app key as a non-extractable CryptoKey
// rather than raw bytes, so it can never be handed to platform.getHmacDigest below. Exported so
// both platforms can pre-check appKey before ever calling deriveCacheKey, rather than relying on
// the TypeError below to propagate and be caught somewhere.
export const isRawKeyBytes = (value: unknown): value is Uint8Array => value instanceof Uint8Array

export const deriveCacheKey = (appKey: Uint8Array): Promise<Uint8Array> => {
    if (!isRawKeyBytes(appKey)) {
        throw new TypeError('deriveCacheKey requires appKey to be raw key bytes (Uint8Array)')
    }
    return platform.getHmacDigest('SHA256', appKey, CACHE_KEY_LABEL)
}

// The freshness timestamp goes inside the encrypted payload, not a cleartext header, so GCM's
// auth tag covers it too - otherwise the staleness check could be bypassed by editing the
// timestamp bytes without touching the ciphertext at all.
export const encodeCacheBlob = async (plaintext: Uint8Array, cacheKey: Uint8Array): Promise<Uint8Array> => {
    const encrypted = await platform.encryptWithKey(concatBytes(writeTimestamp(Date.now()), plaintext), cacheKey)
    return concatBytes(new Uint8Array([CACHE_FORMAT_VERSION]), encrypted)
}

export const decodeCacheBlob = async (raw: Uint8Array, cacheKey: Uint8Array, maxCacheAgeMs: number): Promise<Uint8Array> => {
    if (raw.length < 1 || raw[0] !== CACHE_FORMAT_VERSION) {
        throw new Error('cache blob is not in a recognized format')
    }
    const decrypted = await platform.decryptWithKey(raw.subarray(1), cacheKey)
    if (decrypted.length < 8) {
        throw new Error('cache blob is not in a recognized format')
    }
    // Math.abs, not a plain subtraction: if the wall clock has moved backward relative to when
    // this entry was encrypted (common on a VM/container before its first NTP sync), a plain
    // `Date.now() - written` goes negative and this check never trips, letting an entry written
    // during a period of clock skew stay "fresh" indefinitely regardless of maxCacheAgeMs.
    if (Math.abs(Date.now() - readTimestamp(decrypted.subarray(0, 8))) > maxCacheAgeMs) {
        throw new Error(`cached value is stale (age exceeds ${maxCacheAgeMs}ms)`)
    }
    return decrypted.subarray(8)
}
