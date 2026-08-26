import {nodePlatform} from '../src/node/nodePlatform'
import {DEFAULT_REQUEST_TIMEOUT_MS} from '../src/platform'
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

let mockReq: MockRequest

beforeEach(() => {
    mockReq = new MockRequest()
    ;(https.request as unknown as jest.Mock).mockReset().mockImplementation(() => mockReq)
})

test('hash produces different digests for different tags with the same data', async () => {
    const data = new TextEncoder().encode('client-key-bytes')
    const digestA = await nodePlatform.hash(data, 'TAG_A')
    const digestB = await nodePlatform.hash(data, 'TAG_B')
    expect(Buffer.from(digestA).equals(Buffer.from(digestB))).toBe(false)
})

test('hash matches an independently computed HMAC-SHA512 over data and tag', async () => {
    const data = new TextEncoder().encode('client-key-bytes')
    const tag = 'KEEPER_SECRETS_MANAGER_CLIENT_ID'
    const digest = await nodePlatform.hash(data, tag)
    const expected = createHmac('sha512', data).update(tag).digest()
    expect(Buffer.from(digest).equals(expected)).toBe(true)
})

test('get passes an AbortSignal deadline to the request instead of the old idle-timer timeout option', () => {
    // Fake timers even though nothing is advanced here: deadlineSignal() schedules a real
    // setTimeout unconditionally (it isn't mocked), and this test never lets the request
    // settle, so without fake timers that real timer outlives the test and fires later.
    jest.useFakeTimers()
    try {
        void nodePlatform.get('https://example.com', {}, 5000).catch(() => {})
        const options = (https.request as unknown as jest.Mock).mock.calls[0][1]
        expect(options.signal).toBeInstanceOf(AbortSignal)
        expect(options.timeout).toBeUndefined()
    } finally {
        jest.useRealTimers()
    }
})

test("get's deadline firing destroys the request and rejects with a KeeperError", async () => {
    jest.useFakeTimers()
    try {
        const promise = nodePlatform.get('https://example.com', {}, 5000)
        jest.advanceTimersByTime(5000)
        await expect(promise).rejects.toBeInstanceOf(KeeperError)
        await expect(promise).rejects.toThrow(/timed out/)
        expect(mockReq.destroy).toHaveBeenCalled()
    } finally {
        jest.useRealTimers()
    }
})

test("post's deadline firing destroys the request and rejects with a KeeperError", async () => {
    jest.useFakeTimers()
    try {
        const promise = nodePlatform.post('https://example.com', new Uint8Array([1, 2, 3]), {}, false, 5000)
        jest.advanceTimersByTime(5000)
        await expect(promise).rejects.toBeInstanceOf(KeeperError)
        await expect(promise).rejects.toThrow(/timed out/)
        expect(mockReq.destroy).toHaveBeenCalled()
    } finally {
        jest.useRealTimers()
    }
})

test("fileUpload's deadline firing destroys the request and rejects with a KeeperError", async () => {
    jest.useFakeTimers()
    try {
        const promise = nodePlatform.fileUpload('https://example.com', {field: 'value'}, new Uint8Array([1, 2, 3]), 5000)
        jest.advanceTimersByTime(5000)
        await expect(promise).rejects.toBeInstanceOf(KeeperError)
        await expect(promise).rejects.toThrow(/timed out/)
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
