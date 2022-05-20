package com.keepersecurity.secretsManager.core

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
//import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import kotlin.test.*

internal class CryptoUtilsTest {

    init {
        Security.addProvider(BouncyCastleFipsProvider())
//        Security.addProvider(BouncyCastleProvider())
    }

    @Test
    fun privateKeyIsCompatible() {
        val keyPair = generateKeyPair()
        val data = getRandomBytes(32)
        val publicKey = extractPublicRaw(keyPair.public)
        val ciphertext = publicEncrypt(data, publicKey)
        val plaintext = privateDecrypt(ciphertext, keyPair.private.encoded)
        assertContentEquals(data, plaintext)
    }

    @Test
    fun testTotp() {
        // test default algorithm
        // {Algorithm: "", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        var url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=&digits=8&period=30"
        var totp = getTotpCode(url, 20000000000)
        assertEquals("65353130", totp?.code) // using default algorithm SHA1

        // test default digits
        // { Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 0}, Output: "353130"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=0&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("353130", totp?.code) // using default digits = 6

        // test default period
        // {Algorithm: "SHA1", Period: 0, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=0"
        totp = getTotpCode(url, 20000000000)
        assertEquals("65353130", totp?.code) // using default period = 30

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
        assertEquals("94287082", totp?.code)
        assertEquals(1, totp?.timeLeft)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 59, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "46119246"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 59)
        assertEquals("46119246", totp?.code)
        assertEquals(1, totp?.timeLeft)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 59, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "90693936"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 59)
        assertEquals("90693936", totp?.code)
        assertEquals(1, totp?.timeLeft)

        // Check different periods - 1 sec. before split
        // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890", Digits: 8}, Output: "07081804"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 1111111109)
        assertEquals("07081804", totp?.code)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111109, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "68084774"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 1111111109)
        assertEquals("68084774", totp?.code)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111109, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "25091201"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 1111111109)
        assertEquals("25091201", totp?.code)

        // Check different periods - 1 sec. after split
        // {Algorithm: "SHA1", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890", Digits: 8}, Output: "14050471"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 1111111111)
        assertEquals("14050471", totp?.code)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 1111111111, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "67062674"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 1111111111)
        assertEquals("67062674", totp?.code)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 1111111111, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "99943326"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 1111111111)
        assertEquals("99943326", totp?.code)

        // Check different time periods
        // {Algorithm: "SHA1", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890", Digits: 8}, Output: "89005924"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 1234567890)
        assertEquals("89005924", totp?.code)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 1234567890, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "91819424"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 1234567890)
        assertEquals("91819424", totp?.code)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 1234567890, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "93441116"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 1234567890)
        assertEquals("93441116", totp?.code)

        // {Algorithm: "SHA1", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890", Digits: 8}, Output: "69279037"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 2000000000)
        assertEquals("69279037", totp?.code)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 2000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "90698825"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 2000000000)
        assertEquals("90698825", totp?.code)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 2000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "38618901"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 2000000000)
        assertEquals("38618901", totp?.code)

        // {Algorithm: "SHA1", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890", Digits: 8}, Output: "65353130"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME&algorithm=SHA1&digits=8&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("65353130", totp?.code)
        // {Algorithm: "SHA256", Period: 30, UnixTime: 20000000000, Secret: "12345678901234567890123456789012", Digits: 8}, Output: "77737706"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ACME&algorithm=SHA256&digits=8&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("77737706", totp?.code)
        // {Algorithm: "SHA512", Period: 30, UnixTime: 20000000000, Secret: "1234567890123456789012345678901234567890123456789012345678901234", Digits: 8}, Output: "47863826"}
        url = "otpauth://totp/ACME:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=&issuer=ACME&algorithm=SHA512&digits=8&period=30"
        totp = getTotpCode(url, 20000000000)
        assertEquals("47863826", totp?.code)
    }

    @Test
    fun testGeneratePassword() {
        var password = generatePassword()
        assertEquals(64, password.length)

        password = generatePassword(32, 32)
        assertTrue { "^[a-z]{32}$".toRegex().matches(password) }

        password = generatePassword(32, 0, 32)
        assertTrue { "^[A-Z]{32}$".toRegex().matches(password) }

        password = generatePassword(32, 0, 0, 32)
        assertTrue { "^[0-9]{32}$".toRegex().matches(password) }

        password = generatePassword(32, 0, 0, 0, 32)
        assertTrue { password.length == 32 }
        assertTrue { password.filter { "\"!@#$%()+;<>=?[\\]{}^.,".contains(it) }.length == password.length }
    }

    @Test
    fun testWebSafe64FromBytes() {
        val urlSafeRegex = "^[a-zA-Z0-9_-]*\$".toRegex()

        for (i in 1..3){
            val paddedStr = webSafe64FromBytes(getRandomBytes(i))
            assertTrue(urlSafeRegex.containsMatchIn(paddedStr))
        }

        assertEquals("YQ", webSafe64FromBytes("a".toByteArray()))
        assertEquals("YWE", webSafe64FromBytes("aa".toByteArray()))
        assertEquals("YWFh", webSafe64FromBytes("aaa".toByteArray()))
        assertEquals("YWFhYQ", webSafe64FromBytes("aaaa".toByteArray()))
        assertEquals("8J-Ygw", webSafe64FromBytes("\uD83D\uDE03".toByteArray())) // encoded 😃 and will produce padded string along with the hyphen =>  `8J-Ygw==`
    }
}
