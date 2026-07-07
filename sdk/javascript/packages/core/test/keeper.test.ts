import {
    KeeperHttpResponse,
    getSecrets,
    getFolders,
    initializeStorage,
    generateTransmissionKey,
    platform,
    SecretManagerOptions, inMemoryStorage, loadJsonConfig, getTotpCode, generatePassword
} from '../'

import * as fs from 'fs'

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

test('stale pinned server key: diagnostic message propagates to caller, key preserved', async () => {
    const fakeKey = 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM'
    const storage = inMemoryStorage({})
    await initializeStorage(storage, 'YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c', 'fake.keepersecurity.com')
    await storage.saveString('serverPublicKey', fakeKey)
    await storage.saveString('serverPublicKeyId', '20')
    const keyError = JSON.stringify({ error: 'key', key_id: 7 })
    const options: SecretManagerOptions = {
        storage,
        queryFunction: async () => ({
            statusCode: 400,
            data: new TextEncoder().encode(keyError),
            headers: []
        })
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
