package com.keepersecurity.secretsManager.core

import kotlin.test.*

internal class CryptoUtilsTest {

    @Test
    fun privateKeyIsCompatible() {
        val privateKey64 = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg34GXYbMpXKaHcHZW4dIMO3WYU8zTjB6t+41SRsY1rwqgCgYIKoZIzj0DAQehRANCAAQGH/4ZwpGR9B7AlMjVY7ekpjOcaD3rhuO25CmOZxI3wqRDdhXQIdDnuWvQPCZ3ymtjL3C8JrVIcloklwYI9T7+"
        val privateKey = base64ToBytes(privateKey64)
        val exportedPublicKey = exportPublicKey(privateKey)
        assertEquals("BAYf/hnCkZH0HsCUyNVjt6SmM5xoPeuG47bkKY5nEjfCpEN2FdAh0Oe5a9A8JnfKa2MvcLwmtUhyWiSXBgj1Pv4=", bytesToBase64(exportedPublicKey))
        val data = getRandomBytes(32)
        val ciphertext = publicEncrypt(data, exportedPublicKey)
        val plaintext = privateDecrypt(ciphertext, privateKey)
        assertContentEquals(data, plaintext)
    }

    @Test
    fun privateKeySize() {
        val privateKey = generateKeyPair()
        assertEquals(150, privateKey.size)
    }

    @Test
    fun testTotp() {
        // test default algorithm
        // {Algorithm: "", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        var url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=&digits=8&period=30"
        var totp = getTotpCode(url, 20000000000)
        assertEquals("65353130", totp?.first) // using default algorithm SHA1

        // test default digits
        // { Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 0}, Output: "353130"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=0&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("353130", totp?.first) // using default digits = 6

        // test default period
        // {Algorithm: "SHA1", Period: 0, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=0"
        totp = getTotpCode(url, 20000000000)
        assertEquals("65353130", totp?.first) // using default period = 30

        // test empty secret
        // {Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "", Digits: 8}, Output: "no secret key provided"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url)
        assertNull(totp, "Empty secret shouldn't produce valid TOTP")

        // test invalid algorithm
        // { Algorithm: "SHA1024", Period: 30, UnixTime: 0, Secret: "12345678901234567890", Digits: 8}, Output: "invalid algorithm - use one of SHA1/SHA256/SHA512"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1024&digits=8&period=30"
        totp = getTotpCode(url)
        assertNull(totp, "SHA1024 is unsupported algorithm for TOTP")

        // test invalid secret
        // { Algorithm: "SHA1", Period: 30, UnixTime: 0, Secret: "1NVAL1D", Digits: 8}, Output: "bad secret key"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=1NVAL1D&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url)
        assertNull(totp, "Invalid secret shouldn't produce valid TOTP")

        // Check seconds passed
        // {Algorithm: "SHA1", Period: 30, UnixTime: 59, Secret: "12345678901234567890", Digits: 8}, Output: "94287082"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 59)
        assertEquals("94287082", totp?.first)
        assertEquals(29, totp?.second)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 59, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "46119246"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 59)
        assertEquals("46119246", totp?.first)
        assertEquals(29, totp?.second)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 59, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "90693936"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 59)
        assertEquals("90693936", totp?.first)
        assertEquals(29, totp?.second)

        // Check different periods - 1 sec. before split
        // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890", Digits: 8}, Output: "07081804"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 1111111109)
        assertEquals("07081804", totp?.first)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "68084774"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 1111111109)
        assertEquals("68084774", totp?.first)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111109, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "25091201"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 1111111109)
        assertEquals("25091201", totp?.first)

        // Check different periods - 1 sec. after split
        // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890", Digits: 8}, Output: "14050471"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 1111111111)
        assertEquals("14050471", totp?.first)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "67062674"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 1111111111)
        assertEquals("67062674", totp?.first)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111111, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "99943326"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 1111111111)
        assertEquals("99943326", totp?.first)

        // Check different time periods
        // {Algorithm: "SHA1", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890", Digits: 8}, Output: "89005924"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 1234567890)
        assertEquals("89005924", totp?.first)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "91819424"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 1234567890)
        assertEquals("91819424", totp?.first)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 1234567890, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "93441116"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 1234567890)
        assertEquals("93441116", totp?.first)

        // {Algorithm: "SHA1", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890", Digits: 8}, Output: "69279037"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 2000000000)
        assertEquals("69279037", totp?.first)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "90698825"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 2000000000)
        assertEquals("90698825", totp?.first)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 2000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "38618901"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 2000000000)
        assertEquals("38618901", totp?.first)

        // {Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("65353130", totp?.first)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "77737706"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("77737706", totp?.first)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 20000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "47863826"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("47863826", totp?.first)
    }
}