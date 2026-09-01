import { KeeperCryptoError, KeeperError, KeeperCryptoFailureReason } from '../'

describe('KeeperCryptoError', () => {
    // The setPrototypeOf chain must survive transpilation, otherwise consumers' `instanceof KeeperError`
    // catches would silently break when a KeeperCryptoError is thrown.
    test('is instanceof KeeperCryptoError, KeeperError, and Error', () => {
        const err = new KeeperCryptoError('bad key', 'integrity', 'uid-1')
        expect(err).toBeInstanceOf(KeeperCryptoError)
        expect(err).toBeInstanceOf(KeeperError)
        expect(err).toBeInstanceOf(Error)
    })

    test('.name is KeeperCryptoError', () => {
        const err = new KeeperCryptoError('bad key', 'integrity', 'uid-1')
        expect(err.name).toBe('KeeperCryptoError')
    })

    test('carries message, failure, and uid exactly as constructed, for every failure reason', () => {
        const reasons: KeeperCryptoFailureReason[] = ['integrity', 'format', 'missing-key', 'malformed-data', 'unknown']
        for (const failure of reasons) {
            const err = new KeeperCryptoError(`failed: ${failure}`, failure, `uid-${failure}`)
            expect(err.message).toBe(`failed: ${failure}`)
            expect(err.failure).toBe(failure)
            expect(err.uid).toBe(`uid-${failure}`)
        }
    })

    test('two instances do not share state', () => {
        const a = new KeeperCryptoError('message a', 'missing-key', 'uid-a')
        const b = new KeeperCryptoError('message b', 'format', 'uid-b')
        expect(a.message).toBe('message a')
        expect(a.failure).toBe('missing-key')
        expect(a.uid).toBe('uid-a')
        expect(b.message).toBe('message b')
        expect(b.failure).toBe('format')
        expect(b.uid).toBe('uid-b')
    })
})
