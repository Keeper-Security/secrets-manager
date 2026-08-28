import {localConfigStorage, secureStorage} from '../src/browser/localConfigStorage'
import {KeeperError} from '../src/errors'

// How the fake database behaves. Each mode drives one of the paths that, before this fix, left a
// promise pending forever instead of rejecting.
type FakeMode = 'ok' | 'openError' | 'openBlocked' | 'requestError' | 'missingStore'

const later = (fn: () => void) => setTimeout(fn, 0)

// Minimal IndexedDB double covering only the surface this module touches: indexedDB.open, the
// open request's four handlers, db.transaction().objectStore(), and the store's get/put/delete
// requests. Handlers fire on a later task, as the real implementation does, so a wrapper that
// never attaches one simply never settles, which is exactly the defect under test.
const installFakeIndexedDB = (mode: FakeMode) => {
    const data = new Map<string, any>()

    const request = (run: (req: any) => void) => {
        const req: any = {onsuccess: null, onerror: null, result: undefined, error: null}
        later(() => {
            if (mode === 'requestError') {
                req.error = new DOMException('the quota has been exceeded', 'QuotaExceededError')
                req.onerror?.()
                return
            }
            run(req)
            req.onsuccess?.()
        })
        return req
    }

    const store = {
        get: (key: string) => request(req => { req.result = data.get(key) }),
        put: (value: any, key: string) => request(() => { data.set(key, value) }),
        delete: (key: string) => request(() => { data.delete(key) })
    }

    const db = {
        createObjectStore: () => store,
        transaction: () => {
            if (mode === 'missingStore') {
                throw new DOMException('One of the specified object stores was not found.', 'NotFoundError')
            }
            return {objectStore: () => store}
        }
    }

    ;(globalThis as any).indexedDB = {
        open: () => {
            const req: any = {
                onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null,
                result: db, error: null
            }
            later(() => {
                if (mode === 'openError') {
                    req.error = new DOMException('access to storage is denied', 'SecurityError')
                    req.onerror?.()
                } else if (mode === 'openBlocked') {
                    req.onblocked?.()
                } else {
                    req.onupgradeneeded?.()
                    req.onsuccess?.()
                }
            })
            return req
        }
    }
}

// Every failure case here is a promise that used to never settle. Racing a short timer turns a
// regression into a fast, legible failure instead of a suite that stalls until Jest's timeout.
const rejectionFrom = async (p: Promise<unknown>): Promise<unknown> => {
    let timer: ReturnType<typeof setTimeout> | undefined
    const neverSettled = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('promise never settled: the failure path still hangs')), 500)
    })
    try {
        await Promise.race([p, neverSettled])
        return new Error('expected a rejection but the promise resolved')
    } catch (e) {
        return e
    } finally {
        clearTimeout(timer)
    }
}

const expectKeeperError = (err: unknown, pattern: RegExp) => {
    expect(err).toBeInstanceOf(KeeperError)
    expect((err as Error).message).toMatch(pattern)
}

afterEach(() => {
    delete (globalThis as any).indexedDB
})

describe('browser localConfigStorage', () => {
    const storage = () => localConfigStorage('test-db', false)

    test('rejects when opening the database fails', async () => {
        installFakeIndexedDB('openError')
        expectKeeperError(await rejectionFrom(storage().getString('key')),
            /open of database 'test-db' failed: SecurityError/)
    })

    test('rejects when the open is blocked by another connection', async () => {
        installFakeIndexedDB('openBlocked')
        expectKeeperError(await rejectionFrom(storage().getString('key')),
            /open of database 'test-db' is blocked/)
    })

    test('rejects when the object store is missing', async () => {
        installFakeIndexedDB('missingStore')
        expectKeeperError(await rejectionFrom(storage().getString('key')),
            /transaction on store 'secrets' failed: NotFoundError/)
    })

    test('rejects when a read fails', async () => {
        installFakeIndexedDB('requestError')
        expectKeeperError(await rejectionFrom(storage().getString('key')),
            /read of key 'key' failed: QuotaExceededError/)
    })

    test('rejects when a write fails', async () => {
        installFakeIndexedDB('requestError')
        expectKeeperError(await rejectionFrom(storage().saveString('key', 'value')),
            /write of key 'key' failed: QuotaExceededError/)
    })

    test('rejects when a delete fails', async () => {
        installFakeIndexedDB('requestError')
        expectKeeperError(await rejectionFrom(storage().delete('key')),
            /delete of key 'key' failed: QuotaExceededError/)
    })

    test('still reads back what it wrote when IndexedDB is healthy', async () => {
        installFakeIndexedDB('ok')
        const s = storage()
        await s.saveString('key', 'value')
        expect(await s.getString('key')).toBe('value')
        await s.delete('key')
        expect(await s.getString('key')).toBeUndefined()
    })
})

describe('browser secureStorage', () => {
    // secureStorage awaits a read before it returns the storage object, so an IndexedDB failure
    // used to hang the constructor itself and never hand the caller anything to catch.
    test('rejects when opening the database fails', async () => {
        installFakeIndexedDB('openError')
        expectKeeperError(await rejectionFrom(secureStorage('secure-db')),
            /open of database 'secure-db' failed: SecurityError/)
    })

    test('rejects when a read fails', async () => {
        installFakeIndexedDB('requestError')
        expectKeeperError(await rejectionFrom(secureStorage('secure-db')),
            /read of key '__secureKey__' failed: QuotaExceededError/)
    })

    test('still round-trips through encryption when IndexedDB is healthy', async () => {
        installFakeIndexedDB('ok')
        const s = await secureStorage('secure-db')
        await s.saveString('key', 'value')
        expect(await s.getString('key')).toBe('value')
    })
})
