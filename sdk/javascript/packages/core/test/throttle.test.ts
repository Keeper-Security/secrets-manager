import {
    getSecrets,
    initializeStorage,
    inMemoryStorage,
    platform,
    SecretManagerOptions,
    KeeperHttpResponse,
    KeeperThrottleError,
    parseThrottle,
    throttleDelay,
} from '../'

// A valid one-time token (same fixture the e2e suite uses) so initializeStorage produces a
// real client key pair; throttle behaviour is exercised purely through the mocked queryFunction.
const FAKE_TOKEN = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'
const enc = new TextEncoder()

const throttle403 = (retryAfter?: number): KeeperHttpResponse => ({
    statusCode: 403,
    data: enc.encode(
        JSON.stringify(
            retryAfter === undefined
                ? { error: 'throttled', message: 'throttled' }
                : { error: 'throttled', message: 'throttled', retry_after: retryAfter }
        )
    ),
    headers: [],
})

// Build options backed by a freshly initialized in-memory storage, plus a recording sleeper
// (so retries never actually wait).
const makeOptions = async (
    queryFunction: SecretManagerOptions['queryFunction']
): Promise<{ options: SecretManagerOptions; sleeps: number[] }> => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_TOKEN, 'fake.keepersecurity.com')
    const sleeps: number[] = []
    const options: SecretManagerOptions = {
        storage,
        queryFunction,
        throttleSleep: async (ms: number) => {
            sleeps.push(ms)
        },
    }
    return { options, sleeps }
}

describe('throttleDelay (unit)', () => {
    test('exponential sequence with zero jitter', () => {
        expect([0, 1, 2, 3, 4].map((a) => throttleDelay(a, 0, 0))).toEqual([
            11000, 22000, 44000, 88000, 176000,
        ])
    })
    test('retry_after takes precedence', () => {
        expect(throttleDelay(3, 7, 0)).toBe(7000)
    })
    test('non-positive retry_after is ignored', () => {
        expect(throttleDelay(0, 0, 0)).toBe(11000)
        expect(throttleDelay(1, -5, 0)).toBe(22000)
    })
    test('jitter bounds keep the first delay in [8.25s, 13.75s]', () => {
        expect(throttleDelay(0, 0, -0.25)).toBe(8250)
        expect(throttleDelay(0, 0, 0.25)).toBe(13750)
    })
})

describe('parseThrottle (unit)', () => {
    test('throttled via error / result_code with retry_after variants', () => {
        expect(parseThrottle('{"error":"throttled"}')).toBe(0)
        expect(parseThrottle('{"result_code":"throttled","retry_after":5}')).toBe(5)
        expect(parseThrottle('{"error":"throttled","retry_after":"3"}')).toBe(3)
        expect(parseThrottle('{"error":"throttled","retry_after":-2}')).toBe(0)
    })
    test('non-throttle / non-JSON / empty -> null', () => {
        expect(parseThrottle('{"error":"key"}')).toBeNull()
        expect(parseThrottle('not json')).toBeNull()
        expect(parseThrottle('')).toBeNull()
    })
})

describe('throttle retry (e2e via getSecrets)', () => {
    test('retries then succeeds', async () => {
        let call = 0
        const { options, sleeps } = await makeOptions(async (_url, tk) => {
            if (call++ === 0) return throttle403()
            return { statusCode: 200, data: await platform.encryptWithKey(enc.encode('{}'), tk.key), headers: [] }
        })
        const secrets = await getSecrets(options)
        expect(secrets.records).toEqual([])
        expect(sleeps.length).toBe(1)
    })

    test('exhaustion throws KeeperThrottleError after 5 retries', async () => {
        let call = 0
        const { options, sleeps } = await makeOptions(async () => {
            call++
            return throttle403()
        })
        await expect(getSecrets(options)).rejects.toBeInstanceOf(KeeperThrottleError)
        expect(sleeps.length).toBe(5)
        expect(call).toBe(6) // 5 retries + the final throttled response
    })

    test('honors retry_after from the response body', async () => {
        let call = 0
        const { options, sleeps } = await makeOptions(async () =>
            call++ === 0 ? throttle403(3) : throttle403()
        )
        await expect(getSecrets(options)).rejects.toBeInstanceOf(KeeperThrottleError)
        // retry_after = 3s with +/-25% jitter -> [2.25s, 3.75s]
        expect(sleeps[0]).toBeGreaterThanOrEqual(2250)
        expect(sleeps[0]).toBeLessThanOrEqual(3750)
    })

    test('non-throttle 403 is not retried', async () => {
        const { options, sleeps } = await makeOptions(async () => ({
            statusCode: 403,
            data: enc.encode(JSON.stringify({ error: 'access_denied', message: 'nope' })),
            headers: [],
        }))
        await expect(getSecrets(options)).rejects.not.toBeInstanceOf(KeeperThrottleError)
        expect(sleeps.length).toBe(0)
    })

    test('a 502 carrying a throttled body is not retried (403 gate)', async () => {
        const { options, sleeps } = await makeOptions(async () => ({
            statusCode: 502,
            data: enc.encode(JSON.stringify({ error: 'throttled' })),
            headers: [],
        }))
        await expect(getSecrets(options)).rejects.toThrow()
        expect(sleeps.length).toBe(0)
    })
})
