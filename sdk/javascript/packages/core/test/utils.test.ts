import {platform, KeeperError, getTotpCode} from '../'

// A null/undefined config value must surface as a typed, catchable KeeperError, not a cryptic native throw.
test('platform.base64ToBytes throws KeeperError on null', () => {
    expect(() => platform.base64ToBytes(null as any)).toThrow(KeeperError)
    expect(() => platform.base64ToBytes(null as any)).toThrow(/null/)
})

test('platform.base64ToBytes throws KeeperError on undefined', () => {
    expect(() => platform.base64ToBytes(undefined as any)).toThrow(KeeperError)
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

// A TOTP secret with a long run of "=" that is not at the end made the padding trim
// take quadratic time, so one long value could stall the caller.
test('getTotpCode rejects a long secret of "=" characters without stalling', async () => {
    const secret = '='.repeat(100000) + 'A'
    const url = `otpauth://totp/ACME:john.doe@email.com?secret=${secret}&issuer=ACME`
    const start = Date.now()
    const totp = await getTotpCode(url, 59)
    expect(Date.now() - start).toBeLessThan(500)
    expect(totp).toBeNull()
})

test('getTotpCode still accepts a padded base32 secret', async () => {
    const url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====&issuer=ACME&digits=8'
    const totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('65353130')
})
