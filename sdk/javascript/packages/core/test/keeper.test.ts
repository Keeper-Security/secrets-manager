import {
    KeeperHttpResponse,
    getSecrets,
    initializeStorage,
    platform,
    localConfigStorage, SecretManagerOptions, inMemoryStorage, loadJsonConfig, getTotpCode, generatePassword
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
    const kvs = localConfigStorage()

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
    } catch ({message}) {
        expect(JSON.parse(message as string).message).toBe('Signature is invalid')
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
