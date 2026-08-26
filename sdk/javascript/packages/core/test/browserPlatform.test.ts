import {browserPlatform} from '../src/browser/browserPlatform'
import {DEFAULT_REQUEST_TIMEOUT_MS} from '../src/platform'

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

test('get passes an AbortSignal to fetch', async () => {
    await browserPlatform.get('https://example.com', {}, 5000)
    const init = fetchMock.mock.calls[0][1]
    expect(init.signal).toBeInstanceOf(AbortSignal)
})

test('post passes an AbortSignal to fetch', async () => {
    await browserPlatform.post('https://example.com', new Uint8Array([1, 2, 3]), {}, false, 5000)
    const init = fetchMock.mock.calls[0][1]
    expect(init.signal).toBeInstanceOf(AbortSignal)
})

test('fileUpload passes an AbortSignal to fetch', async () => {
    await browserPlatform.fileUpload('https://example.com', {field: 'value'}, new Uint8Array([1, 2, 3]), 5000)
    const init = fetchMock.mock.calls[0][1]
    expect(init.signal).toBeInstanceOf(AbortSignal)
})

test('omitting timeoutMs still produces a signal, not undefined', async () => {
    await browserPlatform.get('https://example.com', {})
    const init = fetchMock.mock.calls[0][1]
    expect(init.signal).toBeInstanceOf(AbortSignal)
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
