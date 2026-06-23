import {platform} from '../'

// KSM-984: null/undefined guard on base64 decoders (tested through the platform API)

test('platform.base64ToBytes throws on null', () => {
    expect(() => platform.base64ToBytes(null as any)).toThrow(/null/)
})

test('platform.base64ToBytes throws on undefined', () => {
    expect(() => platform.base64ToBytes(undefined as any)).toThrow(/undefined/)
})

test('platform.base64ToBytes still works on valid input', () => {
    const bytes = platform.base64ToBytes('YWJj')
    expect(bytes).toBeInstanceOf(Uint8Array)
    expect(Array.from(bytes)).toEqual([97, 98, 99]) // "abc"
})

test('platform.base64ToBytes returns empty array for empty string', () => {
    const bytes = platform.base64ToBytes('')
    expect(bytes).toBeInstanceOf(Uint8Array)
    expect(bytes.length).toBe(0)
})
