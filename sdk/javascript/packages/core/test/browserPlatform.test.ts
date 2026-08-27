import {browserPlatform} from '../src/browser/browserPlatform'
import {DEFAULT_REQUEST_TIMEOUT_MS} from '../src/deadline'
import {KeeperError} from '../src/errors'

const fetchMock = jest.fn()

beforeEach(() => {
    fetchMock.mockReset()
    fetchMock.mockResolvedValue({
        status: 200,
        headers: new Headers(),
        statusText: 'OK',
        arrayBuffer: async () => new ArrayBuffer(0)
    })
    global.fetch = fetchMock as unknown as typeof fetch
})

// fetch rejects an aborted request with a DOMException. Reproduce that so the platform's
// translation to KeeperError is what is under test, not the runtime's abort machinery.
const rejectsWhenAborted = () => fetchMock.mockImplementation((_url: string, init: RequestInit) =>
    new Promise((_resolve, reject) => {
        init.signal!.addEventListener('abort', () =>
            reject(new DOMException('This operation was aborted', 'AbortError')))
    }))

const calls: [string, (timeoutMs?: number) => Promise<unknown>][] = [
    ['get', t => browserPlatform.get('https://example.com', {}, t)],
    ['post', t => browserPlatform.post('https://example.com', new Uint8Array([1, 2, 3]), {}, false, t)],
    ['fileUpload', t => browserPlatform.fileUpload('https://example.com', {field: 'value'}, new Uint8Array([1, 2, 3]), t)]
]

describe.each(calls)('%s', (name, call) => {
    test('passes an AbortSignal to fetch', async () => {
        await call(5000)
        expect(fetchMock.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal)
    })

    test('still produces a signal when timeoutMs is omitted', async () => {
        await call()
        expect(fetchMock.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal)
    })

    // Node wraps its timeout in a KeeperError. Leaving the browser to surface a raw DOMException
    // means `catch (e) { if (e instanceof KeeperError) ... }` silently misses timeouts on one
    // platform.
    test('a fired deadline rejects with a KeeperError, not a DOMException', async () => {
        if (name === 'fileUpload') {
            jest.spyOn(console, 'error').mockImplementation(() => {})
        }
        jest.useFakeTimers()
        try {
            rejectsWhenAborted()
            const promise = call(5000)
            jest.advanceTimersByTime(5000)
            await expect(promise).rejects.toBeInstanceOf(KeeperError)
            await expect(promise).rejects.toThrow(/timed out after 5000ms/)
        } finally {
            jest.useRealTimers()
            jest.restoreAllMocks()
        }
    })

    test('a failure that is not a timeout is passed through untouched', async () => {
        if (name === 'fileUpload') {
            jest.spyOn(console, 'error').mockImplementation(() => {})
        }
        const networkError = new TypeError('Failed to fetch')
        fetchMock.mockRejectedValue(networkError)
        await expect(call(5000)).rejects.toBe(networkError)
        jest.restoreAllMocks()
    })

    test('an unusable timeoutMs is rejected before any request is made', async () => {
        await expect(call(0)).rejects.toBeInstanceOf(KeeperError)
        expect(fetchMock).not.toHaveBeenCalled()
    })

    // Every request arms a setTimeout. Failing to clear it on the way out leaves one pending timer
    // per call for up to the full timeout, which a mocked-fetch assertion would never notice.
    test('a settled request leaves no pending timer behind', async () => {
        if (name === 'fileUpload') {
            jest.spyOn(console, 'error').mockImplementation(() => {})
        }
        jest.useFakeTimers()
        try {
            expect(jest.getTimerCount()).toBe(0)
            await call(5000)
            expect(jest.getTimerCount()).toBe(0)

            fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
            await expect(call(5000)).rejects.toBeInstanceOf(TypeError)
            expect(jest.getTimerCount()).toBe(0)
        } finally {
            jest.useRealTimers()
            jest.restoreAllMocks()
        }
    })
})

test('the default deadline is the shared default', async () => {
    jest.useFakeTimers()
    try {
        rejectsWhenAborted()
        const promise = browserPlatform.get('https://example.com', {}).catch(e => e)
        jest.advanceTimersByTime(DEFAULT_REQUEST_TIMEOUT_MS - 1)
        jest.advanceTimersByTime(1)
        await expect(promise).resolves.toThrow(new RegExp(`timed out after ${DEFAULT_REQUEST_TIMEOUT_MS}ms`))
    } finally {
        jest.useRealTimers()
    }
})

test('omitting timeoutMs aborts the deadline signal at DEFAULT_REQUEST_TIMEOUT_MS, not before', () => {
    jest.useFakeTimers()
    try {
        // Fire-and-forget rather than awaiting: get() clears its deadline timer once fetchMock's
        // already-resolved promise settles, which would erase the signal state this test needs
        // to observe. Staying synchronous keeps that resolution's microtask from running before
        // the assertions below do.
        void browserPlatform.get('https://example.com', {}).catch(() => {})
        const init = fetchMock.mock.calls[0][1]
        expect(init.signal.aborted).toBe(false)
        jest.advanceTimersByTime(DEFAULT_REQUEST_TIMEOUT_MS - 1)
        expect(init.signal.aborted).toBe(false)
        jest.advanceTimersByTime(1)
        expect(init.signal.aborted).toBe(true)
    } finally {
        jest.useRealTimers()
    }
})
