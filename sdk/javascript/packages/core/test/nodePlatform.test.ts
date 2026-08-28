import {nodePlatform} from '../src/node/nodePlatform'
import {DEFAULT_REQUEST_TIMEOUT_MS} from '../src/deadline'
import {KeeperError} from '../src/errors'
import {createHmac} from 'crypto'
import * as https from 'https'
import {EventEmitter} from 'events'

jest.mock('https', () => ({
    request: jest.fn()
}))

class MockRequest extends EventEmitter {
    write = jest.fn()
    end = jest.fn()
    destroy = jest.fn()
}

// A response the test drives by hand: headers land when respond() is called, body chunks and the
// terminating 'end' only when the test says so. Without this the response callback, and therefore
// everything that happens after the headers, is never executed by any test.
class MockResponse extends EventEmitter {
    statusCode = 200
    statusMessage = 'OK'
    headers = {'content-type': 'application/octet-stream'}
    push(chunk: string) { this.emit('data', Buffer.from(chunk)) }
    finish() { this.emit('end') }
    fail(err: Error) { this.emit('error', err) }
}

let mockReq: MockRequest
let responseCallback: ((res: MockResponse) => void) | undefined

const respond = (): MockResponse => {
    const res = new MockResponse()
    responseCallback!(res)
    return res
}

beforeEach(() => {
    mockReq = new MockRequest()
    responseCallback = undefined
    ;(https.request as unknown as jest.Mock).mockReset().mockImplementation((_url, _options, cb) => {
        responseCallback = cb
        return mockReq
    })
})

test('hash produces different digests for different tags with the same data', async () => {
    const data = new TextEncoder().encode('client-key-bytes')
    const a = await nodePlatform.hash(data, 'KEEPER_SECRETS_MANAGER_CLIENT_ID')
    const b = await nodePlatform.hash(data, 'SOME_OTHER_TAG')
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false)
})

test('hash matches an independently computed HMAC-SHA512 over data and tag', async () => {
    const data = new TextEncoder().encode('client-key-bytes')
    const tag = 'KEEPER_SECRETS_MANAGER_CLIENT_ID'
    const digest = await nodePlatform.hash(data, tag)
    const expected = createHmac('sha512', data).update(tag).digest()
    expect(Buffer.from(digest).equals(expected)).toBe(true)
})

describe('request deadline', () => {
    test('get passes an AbortSignal deadline, not the old idle-timer timeout option', () => {
        jest.useFakeTimers()
        try {
            void nodePlatform.get('https://example.com', {}, 5000).catch(() => {})
            const options = (https.request as unknown as jest.Mock).mock.calls[0][1]
            expect(options.signal).toBeInstanceOf(AbortSignal)
            // The socket `timeout` option resets on activity, so it cannot bound a trickling
            // server. Its return would silently undo the fix.
            expect(options.timeout).toBeUndefined()
        } finally {
            jest.useRealTimers()
        }
    })

    test.each([
        ['get', () => nodePlatform.get('https://example.com', {}, 5000)],
        ['post', () => nodePlatform.post('https://example.com', new Uint8Array([1, 2, 3]), {}, false, 5000)],
        ['fileUpload', () => nodePlatform.fileUpload('https://example.com', {field: 'value'}, new Uint8Array([1, 2, 3]), 5000)]
    ])('%s sends a signal and no timeout option', (_name, call) => {
        jest.useFakeTimers()
        try {
            void call().catch(() => {})
            const options = (https.request as unknown as jest.Mock).mock.calls[0][1]
            expect(options.signal).toBeInstanceOf(AbortSignal)
            expect(options.timeout).toBeUndefined()
        } finally {
            jest.useRealTimers()
        }
    })

    test.each([
        ['get', () => nodePlatform.get('https://example.com', {}, 5000)],
        ['post', () => nodePlatform.post('https://example.com', new Uint8Array([1, 2, 3]), {}, false, 5000)],
        ['fileUpload', () => nodePlatform.fileUpload('https://example.com', {field: 'value'}, new Uint8Array([1, 2, 3]), 5000)]
    ])("%s's deadline firing destroys the request and rejects with a KeeperError", async (_name, call) => {
        jest.useFakeTimers()
        try {
            const promise = call()
            jest.advanceTimersByTime(5000)
            await expect(promise).rejects.toBeInstanceOf(KeeperError)
            await expect(promise).rejects.toThrow(/timed out after 5000ms/)
            expect(mockReq.destroy).toHaveBeenCalled()
        } finally {
            jest.useRealTimers()
        }
    })

    test('omitting timeoutMs defaults the deadline to DEFAULT_REQUEST_TIMEOUT_MS', async () => {
        jest.useFakeTimers()
        try {
            const promise = nodePlatform.get('https://example.com', {}).catch(e => e)
            jest.advanceTimersByTime(DEFAULT_REQUEST_TIMEOUT_MS - 1)
            expect(mockReq.destroy).not.toHaveBeenCalled()
            jest.advanceTimersByTime(1)
            const err = await promise
            expect(err).toBeInstanceOf(KeeperError)
            expect(mockReq.destroy).toHaveBeenCalled()
        } finally {
            jest.useRealTimers()
        }
    })

    test('an unusable timeoutMs is rejected rather than aborting the request immediately', async () => {
        await expect(nodePlatform.get('https://example.com', {}, 0)).rejects.toBeInstanceOf(KeeperError)
        await expect(nodePlatform.get('https://example.com', {}, Infinity)).rejects.toThrow(/greater than 0/)
        expect(https.request as unknown as jest.Mock).not.toHaveBeenCalled()
    })
})

describe('response handling', () => {
    test('get resolves with the full body once the response ends', async () => {
        const promise = nodePlatform.get('https://example.com', {}, 5000)
        const res = respond()
        res.push('hello ')
        res.push('world')
        res.finish()
        const result = await promise
        expect(result.statusCode).toBe(200)
        expect(Buffer.from(result.data).toString()).toBe('hello world')
    })

    test('post resolves with the full body once the response ends', async () => {
        const promise = nodePlatform.post('https://example.com', new Uint8Array([1, 2, 3]), {}, false, 5000)
        const res = respond()
        res.push('ok')
        res.finish()
        const result = await promise
        expect(Buffer.from(result.data).toString()).toBe('ok')
    })

    // The regression this guards: clearing the deadline when the response headers arrive leaves the
    // body read unbounded, so a server that sends headers instantly and then stalls or trickles
    // hangs the caller forever. Reproduced against a live server before this test existed.
    test.each([
        ['a stalled body', (res: MockResponse) => { res.push('x') }],
        ['a trickling body', (res: MockResponse) => { res.push('x'); res.push('x'); res.push('x') }],
        ['a body that never starts', (_res: MockResponse) => { /* headers only */ }]
    ])('the deadline stays armed across %s', async (_label, drive) => {
        jest.useFakeTimers()
        try {
            const promise = nodePlatform.get('https://example.com', {}, 5000)
            const res = respond()
            drive(res)
            jest.advanceTimersByTime(5000)
            await expect(promise).rejects.toBeInstanceOf(KeeperError)
            await expect(promise).rejects.toThrow(/timed out after 5000ms/)
            expect(mockReq.destroy).toHaveBeenCalled()
        } finally {
            jest.useRealTimers()
        }
    })

    test('a completed response disarms the deadline', async () => {
        jest.useFakeTimers()
        try {
            const promise = nodePlatform.get('https://example.com', {}, 5000)
            const res = respond()
            res.push('done')
            res.finish()
            await expect(promise).resolves.toMatchObject({statusCode: 200})
            jest.advanceTimersByTime(60000)
            expect(mockReq.destroy).not.toHaveBeenCalled()
        } finally {
            jest.useRealTimers()
        }
    })

    // Once the response has started, the request object no longer reports a mid-body socket
    // failure. Without a listener on the response stream the promise never settles at all.
    test('a mid-body response stream error rejects instead of hanging', async () => {
        const promise = nodePlatform.get('https://example.com', {}, 5000)
        const res = respond()
        res.push('partial')
        res.fail(new Error('aborted'))
        await expect(promise).rejects.toThrow(/aborted/)
    })

    test('fileUpload resolves as soon as the response headers arrive', async () => {
        const promise = nodePlatform.fileUpload('https://example.com', {field: 'value'}, new Uint8Array([1, 2, 3]), 5000)
        const res = new MockResponse()
        res.statusCode = 204
        res.statusMessage = 'No Content'
        mockReq.emit('response', res)
        await expect(promise).resolves.toMatchObject({statusCode: 204, statusMessage: 'No Content'})
    })

    // fileUpload never reads the response body, but the response object is still an EventEmitter.
    // A socket failure after headers land emits 'error' on it; with no listener that throws
    // instead of doing nothing, per Node's EventEmitter contract for unhandled 'error' events.
    test('a response stream error after fileUpload has already resolved does not throw', async () => {
        const promise = nodePlatform.fileUpload('https://example.com', {field: 'value'}, new Uint8Array([1, 2, 3]), 5000)
        const res = new MockResponse()
        mockReq.emit('response', res)
        await promise
        expect(() => res.fail(new Error('ECONNRESET mid response'))).not.toThrow()
    })
})

test('DEFAULT_REQUEST_TIMEOUT_MS is 30 seconds', () => {
    // Pinned to the literal, not compared against itself, so a change to the constant is a real
    // behavior change this test catches rather than a tautology that always passes.
    expect(DEFAULT_REQUEST_TIMEOUT_MS).toBe(30000)
})

// Download/thumbnail/upload URLs from the storage backend carry an AWS SigV4 signature in the
// query string (a bearer credential, valid for hours) - a timeout message embedding the full URL
// would leak it into whatever logs the caller's error handler writes to.
const SENSITIVE_URL = 'https://example.com/file_upload2/abc123?X-Amz-Signature=super-secret-token&X-Amz-Expires=28800'

test("get's timeout message keeps the path but strips the query string", async () => {
    jest.useFakeTimers()
    try {
        const promise = nodePlatform.get(SENSITIVE_URL, {}, 1000).catch(e => e)
        jest.advanceTimersByTime(1000)
        const err = await promise
        expect(err.message).toContain('https://example.com/file_upload2/abc123')
        expect(err.message).not.toContain('X-Amz-Signature')
        expect(err.message).not.toContain('super-secret-token')
    } finally {
        jest.useRealTimers()
    }
})

test("post's timeout message keeps the path but strips the query string", async () => {
    jest.useFakeTimers()
    try {
        const promise = nodePlatform.post(SENSITIVE_URL, new Uint8Array([1]), {}, false, 1000).catch(e => e)
        jest.advanceTimersByTime(1000)
        const err = await promise
        expect(err.message).toContain('https://example.com/file_upload2/abc123')
        expect(err.message).not.toContain('X-Amz-Signature')
        expect(err.message).not.toContain('super-secret-token')
    } finally {
        jest.useRealTimers()
    }
})

test("fileUpload's timeout message keeps the path but strips the query string", async () => {
    jest.useFakeTimers()
    try {
        const promise = nodePlatform.fileUpload(SENSITIVE_URL, {field: 'value'}, new Uint8Array([1]), 1000).catch(e => e)
        jest.advanceTimersByTime(1000)
        const err = await promise
        expect(err.message).toContain('https://example.com/file_upload2/abc123')
        expect(err.message).not.toContain('X-Amz-Signature')
        expect(err.message).not.toContain('super-secret-token')
    } finally {
        jest.useRealTimers()
    }
})
