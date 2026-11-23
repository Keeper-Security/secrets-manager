const nodeCacheTransportCodes = new Set([
    'EAI_AGAIN',
    'ECONNREFUSED',
    'ECONNRESET',
    'EHOSTUNREACH',
    'ENETDOWN',
    'ENETUNREACH',
    'ENOTFOUND',
    'ETIMEDOUT',
])

const nodeCacheExcludedErrors = new WeakSet<object>()

export const excludeNodeCacheTransportFailure = (error: unknown): void => {
    if (typeof error === 'object' && error !== null) nodeCacheExcludedErrors.add(error)
}

export const isNodeCacheTransportFailure = (error: unknown): boolean => {
    if (typeof error !== 'object' || error === null || nodeCacheExcludedErrors.has(error)) return false
    try {
        const code = (error as {code?: unknown}).code
        return typeof code === 'string' && nodeCacheTransportCodes.has(code)
    } catch {
        return false
    }
}

const browserCacheTransportFailures = new WeakSet<TypeError>()

export const markBrowserCacheTransportFailure = (error: unknown): void => {
    if (error instanceof TypeError) browserCacheTransportFailures.add(error)
}

export const isBrowserCacheTransportFailure = (error: unknown): boolean =>
    error instanceof TypeError && browserCacheTransportFailures.has(error)
