import {DEFAULT_MAX_CACHE_AGE_MS} from '../src/cache'

test('DEFAULT_MAX_CACHE_AGE_MS is 24 hours', () => {
    expect(DEFAULT_MAX_CACHE_AGE_MS).toBe(24 * 60 * 60 * 1000)
})
