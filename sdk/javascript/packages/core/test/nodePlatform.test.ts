import {nodePlatform} from '../src/node/nodePlatform'
import {DEFAULT_REQUEST_TIMEOUT_MS} from '../src/platform'
import {KeeperError} from '../src/errors'
import * as https from 'https'
import {createHmac} from 'crypto'
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

test('get sets the timeout option on the request', () => {
    void nodePlatform.get('https://example.com', {}, 5000).catch(() => {})
    const options = (https.request as unknown as jest.Mock).mock.calls[0][1]
    expect(options.timeout).toBe(5000)
})

test("get's timeout event destroys the request and rejects with a KeeperError", async () => {
    const promise = nodePlatform.get('https://example.com', {}, 5000)
    mockReq.emit('timeout')
    await expect(promise).rejects.toBeInstanceOf(KeeperError)
    await expect(promise).rejects.toThrow(/timed out/)
    expect(mockReq.destroy).toHaveBeenCalled()
})

test("post's timeout event destroys the request and rejects with a KeeperError", async () => {
    const promise = nodePlatform.post('https://example.com', new Uint8Array([1, 2, 3]), {}, false, 5000)
    mockReq.emit('timeout')
    await expect(promise).rejects.toBeInstanceOf(KeeperError)
    await expect(promise).rejects.toThrow(/timed out/)
    expect(mockReq.destroy).toHaveBeenCalled()
})

test("fileUpload's timeout event destroys the request and rejects with a KeeperError", async () => {
    const promise = nodePlatform.fileUpload('https://example.com', {field: 'value'}, new Uint8Array([1, 2, 3]), 5000)
    mockReq.emit('timeout')
    await expect(promise).rejects.toBeInstanceOf(KeeperError)
    await expect(promise).rejects.toThrow(/timed out/)
    expect(mockReq.destroy).toHaveBeenCalled()
})

test('omitting timeoutMs sets DEFAULT_REQUEST_TIMEOUT_MS instead of undefined', () => {
    void nodePlatform.get('https://example.com', {}).catch(() => {})
    const options = (https.request as unknown as jest.Mock).mock.calls[0][1]
    expect(options.timeout).toBe(DEFAULT_REQUEST_TIMEOUT_MS)
})
