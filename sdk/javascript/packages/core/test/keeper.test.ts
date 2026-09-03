import {
    KeeperHttpResponse,
    getSecrets,
    getFolders,
    deleteSecret,
    initializeStorage,
    generateTransmissionKey,
    platform,
    SecretManagerOptions, inMemoryStorage, loadJsonConfig, getTotpCode, generatePassword
} from '../'

import * as fs from 'fs'

const FAKE_ONE_TIME_TOKEN = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

const keyErrorResponse = (keyId: number) => JSON.stringify({ error: 'key', key_id: keyId })

afterEach(() => {
    jest.restoreAllMocks()
})

test('Get secrets e2e', async () => {

    const responses: { transmissionKey: string, data: string, statusCode: number } [] = JSON.parse(fs.readFileSync('../../../fake_data.json').toString())

    let responseNo = 0

    const getRandomBytesStub = (): Uint8Array => platform.base64ToBytes(responses[responseNo].transmissionKey)

    const postStub = (): Promise<KeeperHttpResponse> => {
        const response = responses[responseNo++]
        return Promise.resolve({
            data: platform.base64ToBytes(response.data),
            statusCode: response.statusCode,
            headers: []
        })
    }

    platform.getRandomBytes = getRandomBytesStub
    platform.post = postStub
    const kvs = inMemoryStorage({})

    const fakeOneTimeCode = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

    await initializeStorage(kvs, fakeOneTimeCode, 'fake.keepersecurity.com')
    const options: SecretManagerOptions = {
        storage: kvs,
        queryFunction: postStub
    }
    const secrets = await getSecrets(options)
    expect(secrets.records[1].data.fields[2].value[0]).toBe('Lex1S++Wx6g^,LC.(Vp<')
    try {
        await getSecrets(options)
        fail('Did not throw')
    } catch (e) {
        const message = (e as Error).message
        expect(JSON.parse(message).message).toBe('Signature is invalid')
    }
})

test('Storage prefixes', async () => {
    let storage = inMemoryStorage({})
    await initializeStorage(storage, 'US:ONE_TIME_TOKEN')
    expect(await storage.getString('hostname')).toBe('keepersecurity.com')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'EU:ONE_TIME_TOKEN')
    expect(await storage.getString('hostname')).toBe('keepersecurity.eu')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'AU:ONE_TIME_TOKEN')
    expect(await storage.getString('hostname')).toBe('keepersecurity.com.au')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'eu:ONE_TIME_TOKEN')
    expect(await storage.getString('hostname')).toBe('keepersecurity.eu')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'IL5:ONE_TIME_TOKEN')
    expect(await storage.getString('hostname')).toBe('il5.keepersecurity.us')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'fake.keepersecurity.com:ONE_TIME_TOKEN')
    expect(await storage.getString('hostname')).toBe('fake.keepersecurity.com')
})

test('Storage base64', async () => {
    const base64Config = 'eyJhcHBLZXkiOiAiRkFLRV9BUFBfS0VZIiwgICAgICJjbGllbnRJZCI6ICJGQUtFX0NMSUVOVF9LRVkiL' +
        'CAgICAgImhvc3RuYW1lIjogImZha2Uua2VlcGVyc2VjdXJpdHkuY29tIiwgICAgICJwcml2YXRlS2V5IjogIkZBS0VfUFJJVkFUR' +
        'V9LRVkiLCAgICAKInNlcnZlclB1YmxpY0tleUlkIjogIjEwIiB9'

    let storage = loadJsonConfig(base64Config)
    expect(await storage.getString('hostname')).toBe('fake.keepersecurity.com')

    const jsonConfig = '{"hostname": "fake.keepersecurity.com"}'
    storage = loadJsonConfig(jsonConfig)
    expect(await storage.getString('hostname')).toBe('fake.keepersecurity.com')
})

test('TOTP', async () => {
    // test default algorithm
    // {Algorithm: "", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
    let url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=&digits=8&period=30'
    let totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('65353130') // using default algorithm SHA1

    // test default digits
    // { Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 0}, Output: "353130"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=0&period=30'
    totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('353130') // using default digits = 6

    // test default period
    // {Algorithm: "SHA1", Period: 0, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=0'
    totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('65353130') // using default period = 30

    // test empty secret
    // {Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "", Digits: 8}, Output: "no secret key provided"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url)
    expect(totp).toBeNull() // Empty secret shouldn't produce valid TOTP

    // test invalid algorithm
    // { Algorithm: "SHA1024", Period: 30, UnixTime: 0, Secret: "12345678901234567890", Digits: 8}, Output: "invalid algorithm - use one of SHA1/SHA256/SHA512"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1024&digits=8&period=30'
    totp = await getTotpCode(url)
    expect(totp).toBeNull() // SHA1024 is unsupported algorithm for TOTP

    // test invalid secret
    // { Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "1NVAL1D", Digits: 8}, Output: "bad secret key"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=1NVAL1D&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url)
    expect(totp).toBeNull() // Invalid secret shouldn't produce valid TOTP

    // Check seconds passed
    // {Algorithm: "SHA1", Period: 30, UnixTime: 59, Secret: "12345678901234567890", Digits: 8}, Output: "94287082"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url, 59)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('94287082')
    expect(totp!.timeLeft).toBe(1)
    // {Algorithm: "SHA256", Period: 30, UnixTime: 59, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "46119246"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 59)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('46119246')
    expect(totp!.timeLeft).toBe(1)
    // {Algorithm: "SHA512", Period: 30, UnixTime: 59, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "90693936"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 59)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('90693936')
    expect(totp!.timeLeft).toBe(1)

    // Check different periods - 1 sec. before split
    // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890", Digits: 8}, Output: "07081804"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url, 1111111109)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('07081804')
    // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "68084774"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 1111111109)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('68084774')
    // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111109, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "25091201"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 1111111109)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('25091201')

    // Check different periods - 1 sec. after split
    // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890", Digits: 8}, Output: "14050471"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url, 1111111111)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('14050471')
    // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "67062674"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 1111111111)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('67062674')
    // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111111, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "99943326"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 1111111111)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('99943326')

    // Check different time periods
    // {Algorithm: "SHA1", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890", Digits: 8}, Output: "89005924"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url, 1234567890)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('89005924')
    // {Algorithm: "SHA256", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "91819424"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 1234567890)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('91819424')
    // {Algorithm: "SHA512", Period: 30, UnixTime: 1234567890, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "93441116"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 1234567890)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('93441116')

    // {Algorithm: "SHA1", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890", Digits: 8}, Output: "69279037"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url, 2000000000)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('69279037')
    // {Algorithm: "SHA256", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "90698825"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 2000000000)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('90698825')
    // {Algorithm: "SHA512", Period: 30, UnixTime: 2000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "38618901"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 2000000000)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('38618901')

    // {Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('65353130')
    // {Algorithm: "SHA256", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "77737706"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('77737706')
    // {Algorithm: "SHA512", Period: 30, UnixTime: 20000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "47863826"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp!.code).toBe('47863826')
})

test('GeneratePassword', async () => {
    let password = await generatePassword()
    expect(password).not.toBeNull()
    expect(password.length).toBe(32)

    password = await generatePassword(32, 32)
    expect(/^[a-z]{32}$/.test(password)).toBe(true)

    password = await generatePassword(32, 0, 32)
    expect(/^[A-Z]{32}$/.test(password)).toBe(true)

    password = await generatePassword(32, 0, 0, 32)
    expect(/^[0-9]{32}$/.test(password)).toBe(true)

    password = await generatePassword(32, 0, 0, 0, 32)
    expect(password).not.toBeNull()
    expect(password.length).toBe(32)
    expect(/^["!@#$%()+;<>=?[\]{}^.,]{32}$/.test(password)).toBe(true)
})

test('IL5 dynamic key - Layer 1: generateTransmissionKey uses serverPublicKey from storage', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({
        serverPublicKey: fakeKey,
        serverPublicKeyId: '20'
    })
    platform.getRandomBytes = () => new Uint8Array(32)
    const transmissionKey = await generateTransmissionKey(storage)
    expect(transmissionKey.publicKeyId).toBe(20)
    expect(transmissionKey.key.length).toBe(32)
})

test('IL5 dynamic key - Layer 2: initializeStorage saves serverPublicKeyId and serverPublicKey from 4-segment IL5 OTT', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await initializeStorage(storage, `IL5:ONE_TIME_TOKEN:20:${fakeKey}`)
    expect(await storage.getString('hostname')).toBe('il5.keepersecurity.us')
    expect(await storage.getString('serverPublicKeyId')).toBe('20')
    expect(await storage.getString('serverPublicKey')).toBe(fakeKey)
})

test('IL5 dynamic key - Layer 2: initializeStorage ignores extra segments for non-IL5 regions', async () => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, 'US:ONE_TIME_TOKEN:garbage:garbage2')
    expect(await storage.getString('hostname')).toBe('keepersecurity.com')
    expect(await storage.getString('serverPublicKey')).toBeUndefined()
})

test('IL5 dynamic key - Layer 3: getSecrets writes serverPublicKey and serverPublicKeyId from options to storage', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    const options: SecretManagerOptions = {
        storage,
        serverPublicKey: fakeKey,
        serverPublicKeyId: '20',
        queryFunction: async () => ({ statusCode: 200, data: new Uint8Array(0), headers: [] })
    }
    // Writes happen in fetchAndDecryptSecrets before prepareGetPayload; clientId missing is the expected failure point
    await expect(getSecrets(options)).rejects.toThrow('Client Id is missing from the configuration')
    expect(await storage.getString('serverPublicKey')).toBe(fakeKey)
    expect(await storage.getString('serverPublicKeyId')).toBe('20')
})

test('IL5 dynamic key - rotation suppression: server key_id hint ignored when serverPublicKey is in storage', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({
        hostname: 'il5.keepersecurity.us',
        serverPublicKey: fakeKey,
        serverPublicKeyId: '20'
    })
    const keyError = JSON.stringify({ error: 'key', key_id: 7 })
    const options: SecretManagerOptions = {
        storage,
        queryFunction: async () => ({
            statusCode: 400,
            data: new TextEncoder().encode(keyError),
            headers: []
        })
    }
    // Storage has no clientId so prepareGetPayload throws before reaching the key error handler.
    // Full rotation suppression coverage requires an e2e test with initialized storage.
    await expect(getSecrets(options)).rejects.toThrow()
    expect(await storage.getString('serverPublicKeyId')).toBe('20')
})

test('key rotation - retries are bounded, not infinite', async () => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    let calls = 0
    const enc = new TextEncoder()
    const options: SecretManagerOptions = {
        storage,
        queryFunction: async () => {
            calls++
            if (calls > 50) {
                throw new Error('runaway loop detected in key rotation retry')
            }
            return { statusCode: 400, data: enc.encode(keyErrorResponse(7)), headers: [] }
        }
    }
    await expect(getSecrets(options)).rejects.toThrow(/key rotation exhausted/i)
    // MAX_KEY_ROTATION_RETRIES = 3: initial attempt + 3 retries = 4 total calls.
    expect(calls).toBe(4)
})

test('key rotation - suggested key id is adopted and persisted', async () => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    let calls = 0
    const enc = new TextEncoder()
    const emptyResponse = enc.encode(JSON.stringify({ records: [], folders: [], expiresOn: 0, warnings: [] }))
    const options: SecretManagerOptions = {
        storage,
        queryFunction: async (_url, tk) => {
            calls++
            if (calls > 50) {
                throw new Error('runaway loop detected in key rotation retry')
            }
            if (calls === 1) {
                return { statusCode: 400, data: enc.encode(keyErrorResponse(8)), headers: [] }
            }
            // Verify the rotation was adopted: second request should use key_id 8.
            expect(tk.publicKeyId).toBe(8)
            return { statusCode: 200, data: await platform.encryptWithKey(emptyResponse, tk.key), headers: [] }
        }
    }
    const secrets = await getSecrets(options)
    expect(secrets.records).toEqual([])
    expect(calls).toBe(2)
    // Verify the suggested key_id 8 was persisted to storage.
    expect(await storage.getString('serverPublicKeyId')).toBe('8')
})

test('key rotation - unsupported suggested key id is rejected, not persisted', async () => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    let calls = 0
    const enc = new TextEncoder()
    const options: SecretManagerOptions = {
        storage,
        queryFunction: async () => {
            calls++
            if (calls > 50) {
                throw new Error('runaway loop detected in key rotation retry')
            }
            return { statusCode: 400, data: enc.encode(keyErrorResponse(99)), headers: [] }
        }
    }
    await expect(getSecrets(options)).rejects.toThrow(/unsupported key id 99/)
    // Rejected before the retry loop persists anything: one request, config untouched.
    expect(calls).toBe(1)
    expect(await storage.getString('serverPublicKeyId')).toBeUndefined()
})

test('stale pinned server key: diagnostic message propagates to caller, key preserved', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    await storage.saveString('serverPublicKey', fakeKey)
    await storage.saveString('serverPublicKeyId', '20')
    let calls = 0
    const enc = new TextEncoder()
    const options: SecretManagerOptions = {
        storage,
        queryFunction: async () => {
            calls++
            if (calls > 50) {
                throw new Error('runaway loop detected')
            }
            return {
                statusCode: 400,
                data: enc.encode(keyErrorResponse(7)),
                headers: []
            }
        }
    }
    await expect(getSecrets(options)).rejects.toThrow(/Server rejected the custom server public key/)
    await expect(getSecrets(options)).rejects.toThrow(/Please update your IL5 KSM configuration/)
    expect(await storage.getString('serverPublicKeyId')).toBe('20')
    expect(await storage.getString('serverPublicKey')).toBe(fakeKey)
})

test('id-only serverPublicKeyId pin does not reclobber a completed rotation on a later call', async () => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    const enc = new TextEncoder()
    const emptyResponse = enc.encode(JSON.stringify({ records: [], folders: [], expiresOn: 0, warnings: [] }))
    let queryCalls = 0
    const options: SecretManagerOptions = {
        storage,
        serverPublicKeyId: '8',
        queryFunction: async (_url, tk) => {
            queryCalls++
            if (tk.publicKeyId !== 7) {
                return { statusCode: 400, data: enc.encode(keyErrorResponse(7)), headers: [] }
            }
            return { statusCode: 200, data: await platform.encryptWithKey(emptyResponse, tk.key), headers: [] }
        }
    }
    await getSecrets(options)
    expect(queryCalls).toBe(2) // pinned 8 rejected once, rotates to 7, succeeds
    expect(await storage.getString('serverPublicKeyId')).toBe('7')

    await getSecrets(options)
    // Same options object, same pin, on a later call: must not re-clobber storage back to '8'
    // and pay the rotation round trip again.
    expect(queryCalls).toBe(3)
    expect(await storage.getString('serverPublicKeyId')).toBe('7')
})

test('pinned serverPublicKey is not reclobbered on subsequent calls', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    const enc = new TextEncoder()
    const emptyResponse = enc.encode(JSON.stringify({ records: [], folders: [], expiresOn: 0, warnings: [] }))
    const saveStringSpy = jest.spyOn(storage, 'saveString')
    const options: SecretManagerOptions = {
        storage,
        serverPublicKey: fakeKey,
        serverPublicKeyId: '20',
        queryFunction: async (_url, tk) => ({ statusCode: 200, data: await platform.encryptWithKey(emptyResponse, tk.key), headers: [] })
    }
    await getSecrets(options)
    await getSecrets(options)
    const serverPublicKeyWrites = saveStringSpy.mock.calls.filter(([key]) => key === 'serverPublicKey')
    expect(serverPublicKeyWrites.length).toBe(1)
})

test('empty-string serverPublicKey is treated as not supplied, not persisted or reclobbered', async () => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    const enc = new TextEncoder()
    const emptyResponse = enc.encode(JSON.stringify({ records: [], folders: [], expiresOn: 0, warnings: [] }))
    const saveStringSpy = jest.spyOn(storage, 'saveString')
    const options: SecretManagerOptions = {
        storage,
        serverPublicKey: '',
        queryFunction: async (_url, tk) => ({ statusCode: 200, data: await platform.encryptWithKey(emptyResponse, tk.key), headers: [] })
    }
    await getSecrets(options)
    await getSecrets(options)
    const serverPublicKeyWrites = saveStringSpy.mock.calls.filter(([key]) => key === 'serverPublicKey')
    expect(serverPublicKeyWrites.length).toBe(0)
    expect(await storage.getString('serverPublicKey')).toBeUndefined()
})

test('empty-string serverPublicKey paired with an out-of-table id does not bypass table-membership validation', async () => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    const options: SecretManagerOptions = {
        storage,
        serverPublicKey: '',
        serverPublicKeyId: '99',
        queryFunction: async () => {
            throw new Error('should not reach the network')
        }
    }
    await expect(getSecrets(options)).rejects.toThrow(/serverPublicKeyId 99 is not supported/)
    expect(await storage.getString('serverPublicKeyId')).toBeUndefined()
    expect(await storage.getString('serverPublicKey')).toBeUndefined()
})

test('caller-supplied serverPublicKeyId outside the bundled table is rejected upfront, not persisted', async () => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    const options: SecretManagerOptions = {
        storage,
        serverPublicKeyId: '99',
        queryFunction: async () => {
            throw new Error('should not reach the network')
        }
    }
    await expect(getSecrets(options)).rejects.toThrow(/serverPublicKeyId 99 is not supported/)
    expect(await storage.getString('serverPublicKeyId')).toBeUndefined()
})

test('caller-supplied serverPublicKeyId in an invalid format is rejected with a format error, not a table-membership error', async () => {
    for (const invalid of ['abc', '-1', '7.5', '0', '']) {
        const storage = inMemoryStorage({})
        await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
        const options: SecretManagerOptions = {
            storage,
            serverPublicKeyId: invalid,
            queryFunction: async () => {
                throw new Error('should not reach the network')
            }
        }
        await expect(getSecrets(options)).rejects.toThrow(`serverPublicKeyId '${invalid}' must be a positive integer`)
        expect(await storage.getString('serverPublicKeyId')).toBeUndefined()
    }
})

test('concurrent calls against fresh storage do not corrupt the persisted serverPublicKeyId', async () => {
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    const enc = new TextEncoder()
    const emptyResponse = enc.encode(JSON.stringify({ records: [], folders: [], expiresOn: 0, warnings: [] }))
    // Two different ids on the racing calls, not the same id twice: pinning the same id on both
    // (the previous version of this test) converges on that id regardless of whether the
    // write-once guard exists at all, so it can't detect the guard's removal.
    await Promise.all([
        getSecrets({
            storage,
            serverPublicKeyId: '8',
            queryFunction: async (_url, tk) => ({ statusCode: 200, data: await platform.encryptWithKey(emptyResponse, tk.key), headers: [] })
        }),
        getSecrets({
            storage,
            serverPublicKeyId: '10',
            queryFunction: async (_url, tk) => ({ statusCode: 200, data: await platform.encryptWithKey(emptyResponse, tk.key), headers: [] })
        })
    ])
    const settled = await storage.getString('serverPublicKeyId')
    expect(['8', '10']).toContain(settled)

    // A later call with yet another id must not overwrite whatever the race settled on - this is
    // what actually exercises the write-once guard.
    await getSecrets({
        storage,
        serverPublicKeyId: '12',
        queryFunction: async (_url, tk) => ({ statusCode: 200, data: await platform.encryptWithKey(emptyResponse, tk.key), headers: [] })
    })
    expect(await storage.getString('serverPublicKeyId')).toBe(settled)
})

test('an out-of-table serverPublicKeyId alongside a pinned custom key is not validated against the bundled table', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    const enc = new TextEncoder()
    const emptyResponse = enc.encode(JSON.stringify({ records: [], folders: [], expiresOn: 0, warnings: [] }))
    const options: SecretManagerOptions = {
        storage,
        serverPublicKey: fakeKey,
        serverPublicKeyId: '20', // outside the bundled 7-18 table; legitimate for a custom key (IL5)
        queryFunction: async (_url, tk) => {
            expect(tk.publicKeyId).toBe(20)
            return { statusCode: 200, data: await platform.encryptWithKey(emptyResponse, tk.key), headers: [] }
        }
    }
    const secrets = await getSecrets(options)
    expect(secrets.records).toEqual([])
    expect(await storage.getString('serverPublicKeyId')).toBe('20')
})

test('pinning both fields together rebinds the pair atomically, not split across two independent gates', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    await storage.saveString('serverPublicKeyId', '10') // stale id from an earlier rotation, no custom key yet
    const enc = new TextEncoder()
    const emptyResponse = enc.encode(JSON.stringify({ records: [], folders: [], expiresOn: 0, warnings: [] }))
    const options: SecretManagerOptions = {
        storage,
        serverPublicKey: fakeKey,
        serverPublicKeyId: '20',
        queryFunction: async (_url, tk) => {
            expect(tk.publicKeyId).toBe(20)
            return { statusCode: 200, data: await platform.encryptWithKey(emptyResponse, tk.key), headers: [] }
        }
    }
    await getSecrets(options)
    expect(await storage.getString('serverPublicKey')).toBe(fakeKey)
    expect(await storage.getString('serverPublicKeyId')).toBe('20')
})

test('a storage failure between the id write and the key write fails loud on the next call, not silently', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    let saveStringCalls = 0
    const originalSaveString = storage.saveString.bind(storage)
    jest.spyOn(storage, 'saveString').mockImplementation(async (key: string, value: string) => {
        saveStringCalls++
        if (saveStringCalls === 2) {
            throw new Error('simulated storage failure')
        }
        return originalSaveString(key, value)
    })
    const options: SecretManagerOptions = {
        storage,
        serverPublicKey: fakeKey,
        serverPublicKeyId: '20', // out-of-table when unpaired with a custom key
        queryFunction: async () => { throw new Error('should not reach the network') }
    }
    await expect(getSecrets(options)).rejects.toThrow('simulated storage failure')
    // id write (call #1) succeeded; key write (call #2) is what threw.
    expect(await storage.getString('serverPublicKeyId')).toBe('20')
    expect(await storage.getString('serverPublicKey')).toBeUndefined()
    // The mismatched pair must fail loud on the very next transmission-key lookup, not silently
    // default to key id 7 while still holding no custom key.
    await expect(generateTransmissionKey(storage)).rejects.toThrow('Key number 20 is not supported')
})

test('an id-only pin after an earlier key-only pin uses storage, not this call, to decide whether a custom key applies', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    const enc = new TextEncoder()
    const emptyResponse = enc.encode(JSON.stringify({ records: [], folders: [], expiresOn: 0, warnings: [] }))
    await getSecrets({
        storage,
        serverPublicKey: fakeKey,
        queryFunction: async (_url, tk) => ({ statusCode: 200, data: await platform.encryptWithKey(emptyResponse, tk.key), headers: [] })
    })
    const secrets = await getSecrets({
        storage,
        serverPublicKeyId: '20',
        queryFunction: async (_url, tk) => {
            expect(tk.publicKeyId).toBe(20)
            return { statusCode: 200, data: await platform.encryptWithKey(emptyResponse, tk.key), headers: [] }
        }
    })
    expect(secrets.records).toEqual([])
    expect(await storage.getString('serverPublicKeyId')).toBe('20')
})

test('a custom-key-paired serverPublicKeyId still gets format-validated, not sent as NaN', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    const options: SecretManagerOptions = {
        storage,
        serverPublicKey: fakeKey,
        serverPublicKeyId: 'not-a-number',
        queryFunction: async () => { throw new Error('should not reach the network') }
    }
    await expect(getSecrets(options)).rejects.toThrow(`serverPublicKeyId 'not-a-number' must be a positive integer`)
    expect(await storage.getString('serverPublicKey')).toBeUndefined()
    expect(await storage.getString('serverPublicKeyId')).toBeUndefined()
})

test('postQuery persists serverPublicKey/serverPublicKeyId on its own, for callers that never go through fetchAndDecryptSecrets first', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
    const enc = new TextEncoder()
    const deleteResponse = enc.encode(JSON.stringify({ records: [] }))
    const options: SecretManagerOptions = {
        storage,
        serverPublicKey: fakeKey,
        serverPublicKeyId: '20',
        queryFunction: async (_url, tk) => {
            expect(tk.publicKeyId).toBe(20)
            return { statusCode: 200, data: await platform.encryptWithKey(deleteResponse, tk.key), headers: [] }
        }
    }
    await deleteSecret(options, ['fake-record-uid'])
    expect(await storage.getString('serverPublicKey')).toBe(fakeKey)
    expect(await storage.getString('serverPublicKeyId')).toBe('20')
})

test('IL5 dynamic key - Layer 2: lowercase il5 prefix is treated as IL5', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await initializeStorage(storage, `il5:ONE_TIME_TOKEN:20:${fakeKey}`)
    expect(await storage.getString('hostname')).toBe('il5.keepersecurity.us')
    expect(await storage.getString('serverPublicKeyId')).toBe('20')
    expect(await storage.getString('serverPublicKey')).toBe(fakeKey)
})

test('IL5 dynamic key - Layer 2: rejects token with more than 4 segments', async () => {
    const storage = inMemoryStorage({})
    await expect(
        initializeStorage(storage, 'IL5:ONE_TIME_TOKEN:20:SOMEKEY:extra')
    ).rejects.toThrow('IL5 token has unexpected extra segments')
})

test('IL5 dynamic key - Layer 2: rejects non-integer serverPublicKeyId', async () => {
    const storage = inMemoryStorage({})
    await expect(
        initializeStorage(storage, 'IL5:ONE_TIME_TOKEN:notanumber:SOMEKEY')
    ).rejects.toThrow("IL5 token: serverPublicKeyId 'notanumber' must be a positive integer")
})

test('IL5 dynamic key - Layer 2: rejects malformed (too short) serverPublicKey', async () => {
    const storage = inMemoryStorage({})
    await expect(
        initializeStorage(storage, 'IL5:ONE_TIME_TOKEN:20:tooshort')
    ).rejects.toThrow('IL5 token: serverPublicKey appears malformed')
})

test('IL5 dynamic key - Layer 2: rejects key id \'0\' with the "IL5 token:" prefix, matching its sibling checks', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await expect(
        initializeStorage(storage, `IL5:ONE_TIME_TOKEN:0:${fakeKey}`)
    ).rejects.toThrow("IL5 token: serverPublicKeyId '0' must be a positive integer")
})

test('getFolders skips an undecryptable folder and returns the good one', async () => {
    const transmissionKey = new Uint8Array(32).fill(1)
    const appKey = new Uint8Array(32).fill(2)
    const folderKey = new Uint8Array(32).fill(3)

    const goodFolderKeyWrapped = await platform.encryptWithKey(folderKey, appKey)
    const goodFolderData = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify({ name: 'Good Folder' })), folderKey, true)
    const badFolderKeyWrapped = new Uint8Array(16).fill(9)

    const serverResponse = {
        folders: [
            { folderUid: 'good-uid', folderKey: platform.bytesToBase64(goodFolderKeyWrapped), data: platform.bytesToBase64(goodFolderData) },
            { folderUid: 'bad-uid', folderKey: platform.bytesToBase64(badFolderKeyWrapped), data: '' }
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    // postQuery uses options.queryFunction (not platform.post); pin getRandomBytes so the
    // transmission key matches the key used to encrypt the response above.
    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({ data: encryptedResponse, statusCode: 200, headers: [] })

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, 'US:FAKE_CLIENT_KEY')
    await kvs.saveBytes('appKey', appKey)

    const folders = await getFolders({ storage: kvs, queryFunction: queryFn })

    expect(folders.length).toBe(1)
    expect(folders[0].folderUid).toBe('good-uid')
    expect(folders[0].name).toBe('Good Folder')
})

test('flat record with innerFolderUid decrypts recordKey using the folder key, not the app key', async () => {
    const transmissionKey = new Uint8Array(32).fill(1)
    const appKey = new Uint8Array(32).fill(2)
    const folderKey = new Uint8Array(32).fill(3)
    const recordKey = new Uint8Array(32).fill(4)
    const folderUid = 'folder-uid-1'
    const recordUid = 'record-uid-1'

    const wrappedFolderKey = await platform.encryptWithKey(folderKey, appKey)
    const wrappedRecordKey = await platform.encryptWithKey(recordKey, folderKey)
    const recordData = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify({ title: 'Shared Record', type: 'login', fields: [], custom: [] })), recordKey)

    const serverResponse = {
        folders: [
            { folderUid, folderKey: platform.bytesToBase64(wrappedFolderKey), data: '', records: [] }
        ],
        records: [
            {
                recordUid,
                recordKey: platform.bytesToBase64(wrappedRecordKey),
                data: platform.bytesToBase64(recordData),
                revision: 1,
                files: [],
                innerFolderUid: folderUid
            }
        ],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({ data: encryptedResponse, statusCode: 200, headers: [] })

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, 'US:FAKE_CLIENT_KEY')
    await kvs.saveBytes('appKey', appKey)

    const secrets = await getSecrets({ storage: kvs, queryFunction: queryFn })

    // Bug: the flat-records loop always unwraps recordKey with KEY_APP_KEY, ignoring
    // innerFolderUid. Since recordKey here is wrapped with the folder key, unwrapping
    // with the app key throws, the record is caught and silently skipped, and
    // secrets.records comes back empty instead of containing the decrypted record.
    expect(secrets.records.length).toBe(1)
    expect(secrets.records[0].data.title).toBe('Shared Record')
    expect(secrets.records[0].folderUid).toBe(folderUid)
})

test('flat record with innerFolderUid falls back to the app key when no matching folder is returned', async () => {
    const transmissionKey = new Uint8Array(32).fill(5)
    const appKey = new Uint8Array(32).fill(6)
    const recordKey = new Uint8Array(32).fill(7)
    const recordUid = 'record-uid-2'

    const wrappedRecordKey = await platform.encryptWithKey(recordKey, appKey)
    const recordData = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify({ title: 'Orphaned Record', type: 'login', fields: [], custom: [] })), recordKey)

    const serverResponse = {
        folders: [],
        records: [
            {
                recordUid,
                recordKey: platform.bytesToBase64(wrappedRecordKey),
                data: platform.bytesToBase64(recordData),
                revision: 1,
                files: [],
                innerFolderUid: 'folder-uid-not-in-response'
            }
        ],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({ data: encryptedResponse, statusCode: 200, headers: [] })

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, 'US:FAKE_CLIENT_KEY')
    await kvs.saveBytes('appKey', appKey)

    const secrets = await getSecrets({ storage: kvs, queryFunction: queryFn })

    expect(secrets.records.length).toBe(1)
    expect(secrets.records[0].data.title).toBe('Orphaned Record')
})

test('getFolders skips a folder that names itself as its own parent instead of hanging', async () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})

    const transmissionKey = new Uint8Array(32).fill(11)
    const appKey = new Uint8Array(32).fill(12)
    const folderKey = new Uint8Array(32).fill(13)

    const goodFolderKeyWrapped = await platform.encryptWithKey(folderKey, appKey)
    const goodFolderData = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify({ name: 'Good Root Folder' })), folderKey, true)

    const serverResponse = {
        folders: [
            { folderUid: 'self-parent-uid', folderKey: 'unused-folder-key', data: '', parent: 'self-parent-uid' },
            { folderUid: 'good-root-uid', folderKey: platform.bytesToBase64(goodFolderKeyWrapped), data: platform.bytesToBase64(goodFolderData) }
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({ data: encryptedResponse, statusCode: 200, headers: [] })

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, 'US:FAKE_CLIENT_KEY')
    await kvs.saveBytes('appKey', appKey)

    const folders = await getFolders({ storage: kvs, queryFunction: queryFn })

    expect(folders.length).toBe(1)
    expect(folders[0].folderUid).toBe('good-root-uid')
    expect(folders[0].name).toBe('Good Root Folder')

    const cycleLog = consoleErrorSpy.mock.calls.map(call => call[0]).find(msg => msg.includes('self-parent-uid'))
    expect(cycleLog).toBeDefined()
    expect(cycleLog).toContain('parent cycle detected at folder UID self-parent-uid')

    consoleErrorSpy.mockRestore()
})

test('getFolders detects a two-folder parent cycle and logs each folder naming the other as the cycle point', async () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})

    const transmissionKey = new Uint8Array(32).fill(21)

    const serverResponse = {
        folders: [
            { folderUid: 'folder-a', folderKey: 'unused-folder-key', data: '', parent: 'folder-b' },
            { folderUid: 'folder-b', folderKey: 'unused-folder-key', data: '', parent: 'folder-a' }
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({ data: encryptedResponse, statusCode: 200, headers: [] })

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, 'US:FAKE_CLIENT_KEY')

    const folders = await getFolders({ storage: kvs, queryFunction: queryFn })

    expect(folders).toEqual([])
    // 2 per-folder skip lines plus the KSM-1267 summary line naming both skipped UIDs.
    expect(consoleErrorSpy).toHaveBeenCalledTimes(3)
    expect(consoleErrorSpy.mock.calls[0][0]).toContain('Folder folder-a skipped due to error')
    expect(consoleErrorSpy.mock.calls[0][0]).toContain('Folder data inconsistent - parent cycle detected at folder UID folder-b')
    expect(consoleErrorSpy.mock.calls[1][0]).toContain('Folder folder-b skipped due to error')
    expect(consoleErrorSpy.mock.calls[1][0]).toContain('Folder data inconsistent - parent cycle detected at folder UID folder-a')

    consoleErrorSpy.mockRestore()
})

test('getFolders detects a longer three-folder parent cycle and skips every folder in the ring', async () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})

    const transmissionKey = new Uint8Array(32).fill(31)

    const serverResponse = {
        folders: [
            { folderUid: 'ring-a', folderKey: 'unused-folder-key', data: '', parent: 'ring-b' },
            { folderUid: 'ring-b', folderKey: 'unused-folder-key', data: '', parent: 'ring-c' },
            { folderUid: 'ring-c', folderKey: 'unused-folder-key', data: '', parent: 'ring-a' }
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({ data: encryptedResponse, statusCode: 200, headers: [] })

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, 'US:FAKE_CLIENT_KEY')

    const folders = await getFolders({ storage: kvs, queryFunction: queryFn })

    expect(folders).toEqual([])
    // 3 per-folder skip lines plus the KSM-1267 summary line naming all three skipped UIDs.
    expect(consoleErrorSpy).toHaveBeenCalledTimes(4)
    for (const call of consoleErrorSpy.mock.calls.slice(0, 3)) {
        expect(call[0]).toContain('parent cycle detected at folder UID')
    }

    consoleErrorSpy.mockRestore()
})

// The wall-clock bound below is the real regression guard: a synchronous infinite loop cannot be
// preempted by Jest's timer-based timeout, so a future revert of the fix would hang this test
// indefinitely rather than fail fast; the bounded implementation is what keeps this test reliable.
test('getFolders resolves a large folder-parent cycle quickly instead of hanging the event loop', async () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})

    const transmissionKey = new Uint8Array(32).fill(41)
    const ringSize = 500
    const ringFolders: { folderUid: string, folderKey: string, data: string, parent: string }[] = []
    for (let i = 0; i < ringSize; i++) {
        ringFolders.push({ folderUid: `folder-${i}`, folderKey: 'unused-folder-key', data: '', parent: `folder-${(i + 1) % ringSize}` })
    }

    const serverResponse = {
        folders: ringFolders,
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({ data: encryptedResponse, statusCode: 200, headers: [] })

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, 'US:FAKE_CLIENT_KEY')

    const start = Date.now()
    const folders = await getFolders({ storage: kvs, queryFunction: queryFn })
    const elapsed = Date.now() - start

    expect(folders).toEqual([])
    expect(elapsed).toBeLessThan(2000)
    // ringSize per-folder skip lines plus the KSM-1267 summary line, which is not itself a
    // cycle message, so it is checked separately from the loop below.
    expect(consoleErrorSpy).toHaveBeenCalledTimes(ringSize + 1)
    for (const call of consoleErrorSpy.mock.calls.slice(0, ringSize)) {
        expect(call[0]).toContain('parent cycle detected at folder UID')
    }
    expect(consoleErrorSpy.mock.calls[ringSize][0]).toContain(`getFolders: ${ringSize} of ${ringSize} folder(s) could not be decrypted`)

    consoleErrorSpy.mockRestore()
}, 5000)

test('getFolders decrypts a real two-level, non-cyclic parent chain (root then child)', async () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})

    const transmissionKey = new Uint8Array(32).fill(51)
    const appKey = new Uint8Array(32).fill(52)
    const rootFolderKey = new Uint8Array(32).fill(53)
    const childFolderKey = new Uint8Array(32).fill(54)
    const rootUid = 'root-folder-uid'
    const childUid = 'child-folder-uid'

    const rootFolderKeyWrapped = await platform.encryptWithKey(rootFolderKey, appKey)
    const rootFolderData = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify({ name: 'Root Folder' })), rootFolderKey, true)

    const childFolderKeyWrapped = await platform.encryptWithKey(childFolderKey, rootFolderKey, true)
    const childFolderData = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify({ name: 'Child Folder' })), childFolderKey, true)

    const serverResponse = {
        folders: [
            { folderUid: rootUid, folderKey: platform.bytesToBase64(rootFolderKeyWrapped), data: platform.bytesToBase64(rootFolderData) },
            { folderUid: childUid, folderKey: platform.bytesToBase64(childFolderKeyWrapped), data: platform.bytesToBase64(childFolderData), parent: rootUid }
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({ data: encryptedResponse, statusCode: 200, headers: [] })

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, 'US:FAKE_CLIENT_KEY')
    await kvs.saveBytes('appKey', appKey)

    const folders = await getFolders({ storage: kvs, queryFunction: queryFn })

    expect(folders.length).toBe(2)
    const root = folders.find(f => f.folderUid === rootUid)
    const child = folders.find(f => f.folderUid === childUid)
    expect(root?.name).toBe('Root Folder')
    expect(child?.name).toBe('Child Folder')
    expect(consoleErrorSpy).not.toHaveBeenCalled()

    consoleErrorSpy.mockRestore()
})

test('getFolders keeps the "unable to locate shared folder" message distinct from the cycle message', async () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})

    const transmissionKey = new Uint8Array(32).fill(61)
    const appKey = new Uint8Array(32).fill(62)
    const folderKey = new Uint8Array(32).fill(63)

    const goodFolderKeyWrapped = await platform.encryptWithKey(folderKey, appKey)
    const goodFolderData = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify({ name: 'Good Folder' })), folderKey, true)

    const serverResponse = {
        folders: [
            { folderUid: 'orphan-uid', folderKey: 'unused-folder-key', data: '', parent: 'missing-parent-uid' },
            { folderUid: 'good-uid', folderKey: platform.bytesToBase64(goodFolderKeyWrapped), data: platform.bytesToBase64(goodFolderData) }
        ],
        records: [],
        expiresOn: 0,
        warnings: []
    }
    const encryptedResponse = await platform.encryptWithKey(
        platform.stringToBytes(JSON.stringify(serverResponse)), transmissionKey)

    platform.getRandomBytes = () => transmissionKey
    const queryFn = (): Promise<KeeperHttpResponse> => Promise.resolve({ data: encryptedResponse, statusCode: 200, headers: [] })

    const kvs = inMemoryStorage({})
    await initializeStorage(kvs, 'US:FAKE_CLIENT_KEY')
    await kvs.saveBytes('appKey', appKey)

    const folders = await getFolders({ storage: kvs, queryFunction: queryFn })

    expect(folders.length).toBe(1)
    expect(folders[0].folderUid).toBe('good-uid')

    // 1 per-folder skip line plus the KSM-1267 summary line.
    expect(consoleErrorSpy).toHaveBeenCalledTimes(2)
    expect(consoleErrorSpy.mock.calls[0][0]).toBe('Folder orphan-uid skipped due to error (missing-key): KeeperCryptoError, Folder data inconsistent - unable to locate shared folder for orphan-uid')
    expect(consoleErrorSpy.mock.calls[0][0]).not.toContain('parent cycle detected')

    consoleErrorSpy.mockRestore()
})
