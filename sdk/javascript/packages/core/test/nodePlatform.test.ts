import {nodePlatform} from '../src/node/nodePlatform'
import {createHmac} from 'crypto'

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
