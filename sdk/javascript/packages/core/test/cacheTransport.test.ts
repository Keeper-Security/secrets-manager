import {browserPlatform} from '../src/browser/browserPlatform'
import {isBrowserCacheTransportFailure, isNodeCacheTransportFailure} from '../src/cacheTransport'
import {KeeperError} from '../src/errors'
import {nodePlatform} from '../src/node/nodePlatform'
import {EventEmitter} from 'events'
import * as https from 'https'

jest.mock('https', () => ({request: jest.fn()}))

describe('Node cache transport failures', () => {
    const request = https.request as unknown as jest.Mock
    const post = () => nodePlatform.post('https://example.com', new Uint8Array(1), undefined, false, 1000)
    let req: EventEmitter

    beforeEach(() => {
        req = Object.assign(new EventEmitter(), {write: jest.fn(), end: jest.fn()})
        request.mockImplementation((_url, _options, onResponse) => {
            req.on('response', onResponse)
            return req
        })
    })

    afterEach(() => request.mockReset())

    test.each(['ENOTFOUND', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT'])('accepts %s before headers', async code => {
        const error = Object.assign(new Error('Network request failed'), {code})
        const result = post()
        req.emit('error', error)
        await expect(result).rejects.toBe(error)
        expect(isNodeCacheTransportFailure(error)).toBe(true)
    })

    test.each(['CERT_HAS_EXPIRED', 'ERR_INVALID_URL', 'HPE_INVALID_STATUS', 'ABORT_ERR', undefined])(
        'rejects %s before headers', async code => {
            const error = Object.assign(new Error('Request failed'), {code})
            const result = post()
            req.emit('error', error)
            await expect(result).rejects.toBe(error)
            expect(isNodeCacheTransportFailure(error)).toBe(false)
        }
    )

    test.each(['request', 'response'])('rejects a %s error after HTTP headers', async source => {
        const response = Object.assign(new EventEmitter(), {statusCode: 403, headers: {}})
        const error = Object.assign(new Error('Connection reset'), {code: 'ECONNRESET'})
        const result = post()
        req.emit('response', response)
        const emitter = source === 'request' ? req : response
        emitter.emit('error', error)
        await expect(result).rejects.toBe(error)
        expect(isNodeCacheTransportFailure(error)).toBe(false)
    })

    test('rejects a request setup error', async () => {
        const error = Object.assign(new Error('Request setup failed'), {code: 'ECONNRESET'})
        request.mockImplementationOnce(() => { throw error })
        await expect(post()).rejects.toBe(error)
        expect(isNodeCacheTransportFailure(error)).toBe(false)
    })

    test('returns a complete HTTP error reply', async () => {
        const response = Object.assign(new EventEmitter(), {statusCode: 403, headers: {}})
        const data = Buffer.from('Forbidden')
        const result = post()
        req.emit('response', response)
        response.emit('data', data)
        response.emit('end')
        await expect(result).resolves.toEqual({statusCode: 403, headers: {}, data})
    })
})

describe('browser cache transport failures', () => {
    const post = (headers?: Record<string, string>) =>
        browserPlatform.post('https://example.com', new Uint8Array(1), headers, false, 1000)

    afterEach(() => jest.restoreAllMocks())

    test('marks only the TypeError from the Fetch rejection', async () => {
        const error = new TypeError('Failed to fetch')
        jest.spyOn(globalThis, 'fetch').mockRejectedValue(error)
        expect(isBrowserCacheTransportFailure(error)).toBe(false)
        await expect(post()).rejects.toBe(error)
        expect(isBrowserCacheTransportFailure(error)).toBe(true)
        expect(isBrowserCacheTransportFailure(new TypeError(error.message))).toBe(false)
    })

    test('does not mark a request header error', async () => {
        const fetchMock = jest.spyOn(globalThis, 'fetch')
        const error = await post({'invalid header name': 'value'}).catch(e => e)
        expect(error).toMatchObject({name: 'TypeError'})
        expect(fetchMock).not.toHaveBeenCalled()
        expect(isBrowserCacheTransportFailure(error)).toBe(false)
    })

    test('does not mark an abort that Fetch reports', async () => {
        const error = new DOMException('Aborted', 'AbortError')
        jest.spyOn(globalThis, 'fetch').mockRejectedValue(error)
        await expect(post()).rejects.toBe(error)
        expect(isBrowserCacheTransportFailure(error)).toBe(false)
    })

    test('does not mark a body error after HTTP headers', async () => {
        const error = new TypeError('Failed to read response body')
        const response = new Response(null, {status: 403})
        jest.spyOn(response, 'arrayBuffer').mockRejectedValue(error)
        jest.spyOn(globalThis, 'fetch').mockResolvedValue(response)
        await expect(post()).rejects.toBe(error)
        expect(isBrowserCacheTransportFailure(error)).toBe(false)
    })

    test('does not mark a deadline as a transport failure', async () => {
        const error = new TypeError('Failed to fetch')
        jest.useFakeTimers()
        try {
            jest.spyOn(globalThis, 'fetch').mockImplementation((_url, options) =>
                new Promise((_resolve, reject) => {
                    options?.signal?.addEventListener('abort', () => reject(error))
                }))
            const result = post().catch(e => e)
            jest.advanceTimersByTime(1000)
            const timeout = await result
            expect(timeout).toBeInstanceOf(KeeperError)
            expect(isBrowserCacheTransportFailure(timeout)).toBe(false)
            expect(isBrowserCacheTransportFailure(error)).toBe(false)
        } finally {
            jest.useRealTimers()
        }
    })
})
