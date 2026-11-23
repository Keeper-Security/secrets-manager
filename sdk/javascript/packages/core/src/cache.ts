import {validateTimeoutMs} from './deadline'
import {EncryptedPayload, KeeperHttpResponse, KeyValueStorage, platform, TransmissionKey} from './platform'

// Single source of truth for the app-key storage slot; keeper.ts imports this rather than
// declaring its own copy of the literal.
export const KEY_APP_KEY = 'appKey'

const CACHE_KEY_LABEL = 'KSM-cache-v2'
export const CACHE_FORMAT_VERSION = 0x03
export const DEFAULT_MAX_CACHE_AGE_MS = 24 * 60 * 60 * 1000

const concatBytes = (...parts: Uint8Array[]): Uint8Array => {
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

type QueryFunction = (
    url: string,
    transmissionKey: TransmissionKey,
    payload: EncryptedPayload,
    allowUnverifiedCertificate?: boolean,
    timeoutMs?: number
) => Promise<KeeperHttpResponse>

type CacheBackend = {
    read: () => Promise<Uint8Array | undefined>
    write: (blob: Uint8Array) => Promise<void>
}

type CacheScope = {
    storage: KeyValueStorage
    url: string
    requestBody: string
    transmissionKey: TransmissionKey
    serverPublicKey: Uint8Array
    clientPublicKey: Uint8Array
    allowUnverifiedCertificate?: boolean
}

type CacheRequest = CacheScope & {
    read?: (error: unknown) => Promise<Uint8Array | undefined>
    write?: (response: KeeperHttpResponse, plaintext: Uint8Array, parsed: unknown) => Promise<void>
}

// Only the SDK can mark a request as a cacheable read. Keep the public query signature unchanged.
const requests = new WeakMap<EncryptedPayload, CacheRequest>()

export const registerCacheRequest = (payload: EncryptedPayload, scope: CacheScope): CacheRequest => {
    const request = {...scope, allowUnverifiedCertificate: !!scope.allowUnverifiedCertificate}
    requests.set(payload, request)
    return request
}

const getCacheKey = async (request: CacheRequest): Promise<Uint8Array | undefined> => {
    try {
        const url = new URL(request.url)
        if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
            return undefined
        }
        // Browser object storage can hold a non-extractable app key instead of raw bytes.
        const appKey = await request.storage.getBytes(KEY_APP_KEY)
        if (!(appKey instanceof Uint8Array) || appKey.length !== 32) {
            return undefined
        }
        const {clientPublicKey} = request
        if (clientPublicKey.length !== 65 || clientPublicKey[0] !== 4) {
            return undefined
        }
        // Use the exact request body. This includes the client ID and all filters sent to the server.
        const scope = JSON.stringify([
            CACHE_KEY_LABEL, request.url, request.transmissionKey.publicKeyId,
            platform.bytesToBase64(request.serverPublicKey), platform.bytesToBase64(clientPublicKey),
            request.allowUnverifiedCertificate, request.requestBody
        ])
        return await platform.getHmacDigest('SHA256', appKey, platform.stringToBytes(scope))
    } catch {
        return undefined
    }
}

const isObject = (value: unknown): value is Record<string, unknown> =>
    value !== null && typeof value === 'object' && !Array.isArray(value)

export const isBoundReadReply = (reply: unknown): boolean =>
    isObject(reply) && (reply.encryptedAppKey == null || reply.encryptedAppKey === '') &&
    !('error' in reply) && !('result_code' in reply) &&
    (reply.appData == null || typeof reply.appData === 'string') &&
    [reply.records, reply.folders].every(list => list == null || (Array.isArray(list) && list.every(isObject)))

export const createCachedQuery = (
    storage: KeyValueStorage,
    backend: CacheBackend,
    maxCacheAgeMs: number,
    post: QueryFunction,
    isTransportFailure: (error: unknown) => boolean
): QueryFunction => async (url, transmissionKey, payload, allowUnverifiedCertificate, timeoutMs) => {
    const resolvedTimeoutMs = validateTimeoutMs(timeoutMs)
    const request = requests.get(payload)
    if (!request || request.storage !== storage || request.url !== url ||
        request.transmissionKey !== transmissionKey || request.allowUnverifiedCertificate !== !!allowUnverifiedCertificate ||
        !Number.isFinite(maxCacheAgeMs) || maxCacheAgeMs < 0) {
        return post(url, transmissionKey, payload, allowUnverifiedCertificate, resolvedTimeoutMs)
    }
    const cacheKey = await getCacheKey(request)
    let response: KeeperHttpResponse
    try {
        response = await post(url, transmissionKey, payload, allowUnverifiedCertificate, resolvedTimeoutMs)
    } catch (error) {
        if (cacheKey && isTransportFailure(error)) {
            request.read = async failure => {
                if (failure !== error) return undefined
                try {
                    const raw = await backend.read()
                    if (!raw) return undefined
                    const plaintext = await decodeCacheBlob(raw, cacheKey, maxCacheAgeMs)
                    if (!isBoundReadReply(JSON.parse(platform.bytesToString(plaintext)))) return undefined
                    return plaintext
                } catch {
                    return undefined
                }
            }
        }
        throw error
    }
    if (cacheKey && response.statusCode === 200) {
        // Save only after the SDK decodes the live reply and all its items.
        request.write = async (reply, plaintext, parsed) => {
            if (reply !== response || !isBoundReadReply(parsed)) return
            try {
                await backend.write(await encodeCacheBlob(plaintext, cacheKey))
            } catch {
                console.error('Failed to update cached response')
            }
        }
    }
    return response
}
