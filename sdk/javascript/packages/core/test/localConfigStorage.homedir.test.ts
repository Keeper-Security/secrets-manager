// A dedicated file so this mock doesn't leak into localConfigStorage.test.ts's os.tmpdir()-based
// beforeEach. os.homedir() throws in an environment with no $HOME and no matching /etc/passwd
// entry for the current uid (some containers); this proves that failure is deferred to the call
// that actually relies on the default cache path, not raised merely by importing the module.
jest.mock('os', () => ({
    homedir: () => { throw new Error('no matching entry in the password file was found for the current uid') }
}))

import {createCachingFunction, inMemoryStorage} from '../'

test('importing the module does not crash when os.homedir() is unusable', () => {
    expect(() => require('../')).not.toThrow()
})

test('an explicit cachePath does not need os.homedir()', () => {
    const storage = inMemoryStorage({})
    expect(() => createCachingFunction(storage, {cachePath: '/explicit/path/cache.dat'})).not.toThrow()
})

test('relying on the default cachePath surfaces the os.homedir() failure at call time', () => {
    const storage = inMemoryStorage({})
    expect(() => createCachingFunction(storage)).toThrow(/password file/)
})
