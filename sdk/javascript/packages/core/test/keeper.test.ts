import {
    KeeperHttpResponse,
    getSecrets,
    initializeStorage,
    platform,
    localConfigStorage, SecretManagerOptions, inMemoryStorage, loadJsonConfig, getTotpCode
} from '../'

import * as fs from 'fs'
import { generatePassword } from '../src/utils'

test('Get secrets e2e', async () => {

    const responses: { transmissionKey: string, data: string, statusCode: number } [] = JSON.parse(fs.readFileSync('../../../test_data.json').toString())

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
    await initializeStorage(kvs, 'VB3sGkzVyRB9Lup6WE7Rx-ETFZxyWR2zqY2b9f2zwBo', 'local.keepersecurity.com')
    const options: SecretManagerOptions = {
        storage: kvs,
        queryFunction: postStub
    }
    const secrets = await getSecrets(options)
    expect(secrets.records[1].data.fields[1].value[0]).toBe('N$B!lkoOrVL1RUNDBvn2')
    try {
        await getSecrets(options)
        fail('Did not throw')
    } catch ({message}) {
        expect(JSON.parse(message as string).message).toBe('Signature is invalid')
    }
})

test('Storage prefixes', async () => {
    let storage = inMemoryStorage({})
    await initializeStorage(storage, 'US:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw')
    expect(await storage.getString('hostname')).toBe('keepersecurity.com')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'EU:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw')
    expect(await storage.getString('hostname')).toBe('keepersecurity.eu')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'AU:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw')
    expect(await storage.getString('hostname')).toBe('keepersecurity.com.au')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'eu:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw')
    expect(await storage.getString('hostname')).toBe('keepersecurity.eu')

    storage = inMemoryStorage({})
    await initializeStorage(storage, 'local.keepersecurity.com:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw')
    expect(await storage.getString('hostname')).toBe('local.keepersecurity.com')
})

test('Storage base64', async () => {
    const base64Config = 'eyAgICAgImFwcEtleSI6ICI4S3gyNVN2dGtSU3NFWUl1cjdtSEt0THFBTkZOQjdBWlJhOWNxaTJQU1FFPSIsICAgICAiY2x' +
        'pZW50SWQiOiAiNEgvVTVKNkRjZktMWUJJSUFWNVl3RUZHNG4zWGhpRHZOdG9Qa21TTUlUZVROWnNhL0VKMHpUYnBBQ1J0bU' +
        '5VQlJIK052UisyNHNRaFU5dUdqTFRaSHc9PSIsICAgICAiaG9zdG5hbWUiOiAia2VlcGVyc2VjdXJpdHkuY29tIiwgICAgI' +
        'CJwcml2YXRlS2V5IjogIk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ3VoekRJNGlW' +
        'UzVCdzlsNWNmZkZYcFArRmh1bE5INDFHRFdWY3NiZ1h5aU9oUkFOQ0FBVGsxZnpvTDgvVkxwdVl1dTEzd0VsUE5wM2FHMmd' +
        'sRmtFUHp4YWlNZ1ArdnRVZDRnWjIzVHBHdTFzMXRxS2FFZTloN1ZDVk1qd3ZEQTMxYW5mTWxZRjUiLCAgICAgInNlcnZlcl' +
        'B1YmxpY0tleUlkIjogIjEwIiB9'
    let storage = loadJsonConfig(base64Config)
    expect(await storage.getString('hostname')).toBe('keepersecurity.com')

    const jsonConfig = '{"hostname": "keepersecurity.com"}'
    storage = loadJsonConfig(jsonConfig)
    expect(await storage.getString('hostname')).toBe('keepersecurity.com')
})

test('TOTP', async () => {
    // test default algorithm
    // {Algorithm: "", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
    let url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=&digits=8&period=30'
    let totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('65353130') // using default algorithm SHA1

    // test default digits
    // { Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 0}, Output: "353130"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=0&period=30'
    totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('353130') // using default digits = 6

    // test default period
    // {Algorithm: "SHA1", Period: 0, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=0'
    totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('65353130') // using default period = 30

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
    expect(totp![0]).toBe('94287082')
    expect(totp![1]).toBe(29)
    // {Algorithm: "SHA256", Period: 30, UnixTime: 59, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "46119246"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 59)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('46119246')
    expect(totp![1]).toBe(29)
    // {Algorithm: "SHA512", Period: 30, UnixTime: 59, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "90693936"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 59)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('90693936')
    expect(totp![1]).toBe(29)

    // Check different periods - 1 sec. before split
    // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890", Digits: 8}, Output: "07081804"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url, 1111111109)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('07081804')
    // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "68084774"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 1111111109)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('68084774')
    // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111109, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "25091201"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 1111111109)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('25091201')

    // Check different periods - 1 sec. after split
    // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890", Digits: 8}, Output: "14050471"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url, 1111111111)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('14050471')
    // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "67062674"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 1111111111)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('67062674')
    // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111111, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "99943326"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 1111111111)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('99943326')

    // Check different time periods
    // {Algorithm: "SHA1", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890", Digits: 8}, Output: "89005924"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url, 1234567890)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('89005924')
    // {Algorithm: "SHA256", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "91819424"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 1234567890)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('91819424')
    // {Algorithm: "SHA512", Period: 30, UnixTime: 1234567890, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "93441116"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 1234567890)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('93441116')

    // {Algorithm: "SHA1", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890", Digits: 8}, Output: "69279037"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url, 2000000000)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('69279037')
    // {Algorithm: "SHA256", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "90698825"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 2000000000)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('90698825')
    // {Algorithm: "SHA512", Period: 30, UnixTime: 2000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "38618901"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 2000000000)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('38618901')

    // {Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30'
    totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('65353130')
    // {Algorithm: "SHA256", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "77737706"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30'
    totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('77737706')
    // {Algorithm: "SHA512", Period: 30, UnixTime: 20000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "47863826"}
    url = 'otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30'
    totp = await getTotpCode(url, 20000000000)
    expect(totp).not.toBeNull()
    expect(totp![0]).toBe('47863826')
})

test('GeneratePassword', async () => {
    let password = await generatePassword()
    expect(password).not.toBeNull()
    expect(password.length).toBe(64)

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
