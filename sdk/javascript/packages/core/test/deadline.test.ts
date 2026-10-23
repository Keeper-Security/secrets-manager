import {
    DEFAULT_REQUEST_TIMEOUT_MS,
    MAX_REQUEST_TIMEOUT_MS,
    deadlineSignal,
    resolveTimeoutMs,
    validateTimeoutMs
} from '../src/deadline'
import {KeeperError} from '../src/errors'

test('the default is five minutes', () => {
    // Asserted against the literal, not against the constant: comparing the constant to itself
    // passes no matter what the value is changed to.
    expect(DEFAULT_REQUEST_TIMEOUT_MS).toBe(300000)
})

test('an omitted timeout resolves to the default', () => {
    expect(resolveTimeoutMs()).toBe(300000)
    expect(resolveTimeoutMs(undefined)).toBe(300000)
    expect(resolveTimeoutMs(null)).toBe(300000)
})

test('a usable timeout is passed through', () => {
    expect(resolveTimeoutMs(1)).toBe(1)
    expect(resolveTimeoutMs(5000)).toBe(5000)
    expect(resolveTimeoutMs(30000)).toBe(30000)
    expect(resolveTimeoutMs(600000)).toBe(600000)
    expect(resolveTimeoutMs(MAX_REQUEST_TIMEOUT_MS)).toBe(MAX_REQUEST_TIMEOUT_MS)
})

test('a fractional timeout is floored to whole milliseconds', () => {
    expect(resolveTimeoutMs(1500.9)).toBe(1500)
})

// setTimeout truncates anything past 2^31-1 to a 1ms delay, which would abort the request
// essentially at once. Clamping keeps a very long timeout long instead of inverting it.
test.each([
    ['2^31', 2147483648],
    ['2^32', 4294967296],
    ['a year', 365 * 24 * 60 * 60 * 1000]
])('%s clamps to the ceiling rather than truncating to 1ms', (_label, value) => {
    expect(resolveTimeoutMs(value)).toBe(MAX_REQUEST_TIMEOUT_MS)
})

// Each of these collapses to a near-instant setTimeout. Accepting them would turn a configuration
// mistake into every request failing in about two milliseconds, under a message naming a timeout
// that was never applied. Infinity is the dangerous one: it is the obvious way to write "no
// timeout".
test.each([
    ['zero', 0],
    ['a fraction below 1', 0.5],
    ['a negative', -1],
    ['NaN', NaN],
    ['Infinity', Infinity],
    ['-Infinity', -Infinity]
])('%s is rejected instead of silently aborting the request', (_label, value) => {
    let error: any
    try {
        resolveTimeoutMs(value)
    } catch (e) {
        error = e
    }
    expect(error).toBeInstanceOf(Error)
    expect(error).not.toBeInstanceOf(KeeperError)
    expect(error.message).toMatch(/at least 1/)
})

test('a non-numeric timeout is rejected', () => {
    let error: any
    try {
        resolveTimeoutMs('5000' as unknown as number)
    } catch (e) {
        error = e
    }
    expect(error).toBeInstanceOf(Error)
    expect(error).not.toBeInstanceOf(KeeperError)
})

test('deadlineSignal reports the timeout it actually enforces, not the one requested', () => {
    const clamped = deadlineSignal(MAX_REQUEST_TIMEOUT_MS + 1)
    expect(clamped.timeoutMs).toBe(MAX_REQUEST_TIMEOUT_MS)
    clamped.clear()

    const defaulted = deadlineSignal()
    expect(defaulted.timeoutMs).toBe(300000)
    defaulted.clear()
})

test.each([
    ['omitted', undefined],
    ['null', null]
])('%s timeout stays active until the full five-minute deadline', (_label, timeoutMs) => {
    jest.useFakeTimers()
    try {
        const deadline = deadlineSignal(timeoutMs)
        expect(deadline.timeoutMs).toBe(300000)
        expect(deadline.signal!.aborted).toBe(false)
        jest.advanceTimersByTime(30000)
        expect(deadline.signal!.aborted).toBe(false)
        jest.advanceTimersByTime(269999)
        expect(deadline.signal!.aborted).toBe(false)
        jest.advanceTimersByTime(1)
        expect(deadline.signal!.aborted).toBe(true)
        deadline.clear()
        expect(jest.getTimerCount()).toBe(0)
    } finally {
        jest.useRealTimers()
    }
})

test.each([5000, 30000, 600000])('deadlineSignal honors an explicit %dms deadline', timeoutMs => {
    jest.useFakeTimers()
    try {
        const {signal, clear} = deadlineSignal(timeoutMs)
        expect(signal!.aborted).toBe(false)
        jest.advanceTimersByTime(timeoutMs - 1)
        expect(signal!.aborted).toBe(false)
        jest.advanceTimersByTime(1)
        expect(signal!.aborted).toBe(true)
        clear()
    } finally {
        jest.useRealTimers()
    }
})

test('validateTimeoutMs returns the resolved, clamped value, not the raw input', () => {
    expect(validateTimeoutMs(1500.9)).toBe(1500)
    expect(validateTimeoutMs(MAX_REQUEST_TIMEOUT_MS + 1)).toBe(MAX_REQUEST_TIMEOUT_MS)
})

test('validateTimeoutMs passes undefined/null through untouched', () => {
    expect(validateTimeoutMs(undefined)).toBeUndefined()
    expect(validateTimeoutMs(null)).toBeNull()
})

test('validateTimeoutMs still rejects an unusable value', () => {
    expect(() => validateTimeoutMs(0)).toThrow(/at least 1/)
})

test.each([
    ['default', undefined],
    ['explicit', 5000]
])('clear() disarms the %s deadline so a settled request cannot be aborted later', (_label, timeoutMs) => {
    jest.useFakeTimers()
    try {
        const {signal, clear} = deadlineSignal(timeoutMs)
        expect(jest.getTimerCount()).toBe(1)
        clear()
        expect(jest.getTimerCount()).toBe(0)
        jest.advanceTimersByTime(600000)
        expect(signal!.aborted).toBe(false)
    } finally {
        jest.useRealTimers()
    }
})

test('clearing one deadline does not affect another request', () => {
    jest.useFakeTimers()
    try {
        const settled = deadlineSignal()
        const pending = deadlineSignal(5000)
        settled.clear()
        expect(jest.getTimerCount()).toBe(1)
        jest.advanceTimersByTime(4999)
        expect(pending.signal!.aborted).toBe(false)
        jest.advanceTimersByTime(1)
        expect(pending.signal!.aborted).toBe(true)
        jest.advanceTimersByTime(300000)
        expect(settled.signal!.aborted).toBe(false)
        pending.clear()
        expect(jest.getTimerCount()).toBe(0)
    } finally {
        jest.useRealTimers()
    }
})

test.each([
    ['default', undefined, 300000],
    ['null', null, 300000],
    ['explicit', 5000, 5000]
])('%s deadline returns no signal when AbortController is unavailable', (_label, timeoutMs, expectedMs) => {
    const original = global.AbortController
    // @ts-expect-error - simulating a runtime with no AbortController support
    delete global.AbortController
    try {
        const {signal, timeoutMs: resolvedMs, clear} = deadlineSignal(timeoutMs)
        expect(signal).toBeUndefined()
        expect(resolvedMs).toBe(expectedMs)
        expect(() => clear()).not.toThrow()
    } finally {
        global.AbortController = original
    }
})
