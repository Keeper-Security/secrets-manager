import {
    KeeperHttpResponse,
    getSecrets,
    getFolders,
    initializeStorage,
    generateTransmissionKey,
    platform,
    SecretManagerOptions, inMemoryStorage, loadJsonConfig, getTotpCode, generatePassword,
    downloadFile, downloadThumbnail, uploadFile, KeeperFile, KeeperRecord, DEFAULT_REQUEST_TIMEOUT_MS
} from '../'

import * as fs from 'fs'

const FAKE_ONE_TIME_TOKEN = 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c'

const keyErrorResponse = (keyId: number) => JSON.stringify({ error: 'key', key_id: keyId })

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

// requestTimeoutMs is only useful if it survives the trip from SecretManagerOptions to the
// platform call. Nothing below asserts on timing; each test checks the value that actually reached
// the wire, so dropping a forwarding argument anywhere in keeper.ts fails here.
describe('request timeout propagation', () => {
    const savedPlatform = {get: platform.get, post: platform.post, fileUpload: platform.fileUpload, decrypt: platform.decrypt}

    afterEach(() => {
        platform.get = savedPlatform.get
        platform.post = savedPlatform.post
        platform.fileUpload = savedPlatform.fileUpload
        platform.decrypt = savedPlatform.decrypt
        // The uploadFile case seeds the module-global key cache; clear it so nothing leaks into
        // whatever runs next.
        platform.cleanKeyCache()
    })

    test('getSecrets forwards options.requestTimeoutMs to the query function', async () => {
        const storage = inMemoryStorage({})
        await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
        const seen: (number | undefined)[] = []
        const options: SecretManagerOptions = {
            storage,
            requestTimeoutMs: 4321,
            queryFunction: async (_url, _key, _payload, _allowUnverified, timeoutMs) => {
                seen.push(timeoutMs)
                return {statusCode: 500, data: new TextEncoder().encode('nope'), headers: []}
            }
        }
        await expect(getSecrets(options)).rejects.toBeDefined()
        expect(seen).toEqual([4321])
    })

    test('getSecrets leaves the timeout undefined when none is configured, so the platform default applies', async () => {
        const storage = inMemoryStorage({})
        await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
        const seen: (number | undefined)[] = []
        const options: SecretManagerOptions = {
            storage,
            queryFunction: async (_url, _key, _payload, _allowUnverified, timeoutMs) => {
                seen.push(timeoutMs)
                return {statusCode: 500, data: new TextEncoder().encode('nope'), headers: []}
            }
        }
        await expect(getSecrets(options)).rejects.toBeDefined()
        expect(seen).toEqual([undefined])
    })

    test('a timed-out request is not retried, it propagates to the caller', async () => {
        const storage = inMemoryStorage({})
        await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
        let calls = 0
        const options: SecretManagerOptions = {
            storage,
            requestTimeoutMs: 1000,
            queryFunction: async () => {
                calls++
                throw new Error('Request to https://fake.keepersecurity.com/x timed out after 1000ms')
            }
        }
        await expect(getSecrets(options)).rejects.toThrow(/timed out after 1000ms/)
        // The throttle and key-rotation loops both live in postQuery; neither may swallow a
        // timeout and spin.
        expect(calls).toBe(1)
    })

    describe.each([
        ['downloadFile', (f: KeeperFile, t?: number, o?: SecretManagerOptions) => downloadFile(f, t, o)],
        ['downloadThumbnail', (f: KeeperFile, t?: number, o?: SecretManagerOptions) => downloadThumbnail(f, t, o)]
    ])('%s', (name, download) => {
        const file = (): KeeperFile => ({
            fileUid: 'file-uid',
            data: {} as any,
            url: 'https://example.com/file',
            thumbnailUrl: 'https://example.com/thumb'
        } as unknown as KeeperFile)

        let seen: (number | undefined)[]
        beforeEach(() => {
            seen = []
            platform.get = (async (_url: string, _headers: any, timeoutMs?: number) => {
                seen.push(timeoutMs)
                return {statusCode: 200, headers: [], data: new Uint8Array()}
            }) as typeof platform.get
            platform.decrypt = (async () => new Uint8Array([1])) as typeof platform.decrypt
        })

        test('inherits options.requestTimeoutMs', async () => {
            await download(file(), undefined, {storage: inMemoryStorage({}), requestTimeoutMs: 7000})
            expect(seen).toEqual([7000])
        })

        test('an explicit timeoutMs wins over the configured one', async () => {
            await download(file(), 250, {storage: inMemoryStorage({}), requestTimeoutMs: 7000})
            expect(seen).toEqual([250])
        })

        test('sends undefined when neither is given, so the platform default applies', async () => {
            await download(file())
            expect(seen).toEqual([undefined])
        })
    })

    test('uploadFile forwards options.requestTimeoutMs to platform.fileUpload', async () => {
        const storage = inMemoryStorage({})
        await initializeStorage(storage, FAKE_ONE_TIME_TOKEN, 'fake.keepersecurity.com')
        await platform.generatePrivateKey('ownerKey', storage)
        await storage.saveBytes('appOwnerPublicKey', await platform.exportPublicKey('ownerKey', storage))
        // importKey seeds the platform key cache as well as storage: prepareFileUploadPayload
        // calls platform.encrypt without passing storage, so the key must already be cached.
        await platform.importKey('appKey', platform.getRandomBytes(32), storage)

        const seen: (number | undefined)[] = []
        platform.fileUpload = (async (_url: string, _params: any, _data: Uint8Array, timeoutMs?: number) => {
            seen.push(timeoutMs)
            return {statusCode: 200, statusMessage: 'OK', headers: {}}
        }) as typeof platform.fileUpload

        // No recordUid, so the record and link keys are encrypted under the app key seeded above
        // rather than a per-record key this test would otherwise have to plant in storage.
        const ownerRecord = {recordUid: '', data: {fields: []}, revision: 1} as unknown as KeeperRecord
        const options: SecretManagerOptions = {
            storage,
            requestTimeoutMs: 9000,
            queryFunction: async (_url, transmissionKey) => ({
                statusCode: 200,
                headers: [],
                data: await platform.encryptWithKey(
                    platform.stringToBytes(JSON.stringify({
                        url: 'https://example.com/upload',
                        parameters: '{}',
                        successStatusCode: 200
                    })),
                    transmissionKey.key)
            })
        }

        await uploadFile(options, ownerRecord, {name: 'f.txt', title: 'f', type: 'text/plain', data: new Uint8Array([1, 2, 3])})
        expect(seen).toEqual([9000])
    })
})

test('DEFAULT_REQUEST_TIMEOUT_MS is exported from the package entry point', () => {
    expect(DEFAULT_REQUEST_TIMEOUT_MS).toBe(30000)
})
