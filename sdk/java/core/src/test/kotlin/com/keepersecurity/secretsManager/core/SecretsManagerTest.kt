package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import kotlin.test.*

@ExperimentalSerializationApi
internal class SecretsManagerTest {

    @Serializable
    data class TestResponse(val transmissionKey: String, val data: String, val statusCode: Int)

    @ExperimentalSerializationApi
    @Test
    fun getSecretsE2E() {
        val file = File("../../test_data.json")
        val inputStream = BufferedReader(FileReader(file))
        val jsonString = inputStream.lines().reduce { x: String, y: String -> x + y }
        val testResponses = Json.decodeFromString<List<TestResponse>>(jsonString.get())
        var responseNo = 0
        TestStubs.transmissionKeyStub = { base64ToBytes(testResponses[responseNo].transmissionKey) }
        val testPostFunction: (
            url: String,
            transmissionKey: TransmissionKey,
            payload: EncryptedPayload,
        ) -> KeeperHttpResponse = { _, _, _ ->
            val response = testResponses[responseNo++]
            KeeperHttpResponse(response.statusCode, base64ToBytes(response.data))
        }
        val storage = LocalConfigStorage()
        initializeStorage(storage, "VB3sGkzVyRB9Lup6WE7Rx-ETFZxyWR2zqY2b9f2zwBo", "local.keepersecurity.com")
        val options = SecretsManagerOptions(storage, testPostFunction)
        val secrets = getSecrets(options)
        val record = secrets.getRecordByUid("i3v4ehaoB-Bwsb7bbbek2g")
        assertNotNull(record)
        val password = record.getPassword()
        assertNotNull(password)
        assertEquals("N\$B!lkoOrVL1RUNDBvn2", password)
        try {
            getSecrets(options)
            fail("Did not throw")
        } catch (e: Exception) {
            val message = Json.decodeFromString<JsonObject>(e.message!!)["message"]!!.jsonPrimitive
            assertEquals("Signature is invalid", message.content)
        }
    }

    @Test
    fun testStoragePrefixes() {
        var storage = InMemoryStorage()
        initializeStorage(storage, "US:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw")
        assertEquals("keepersecurity.com", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "EU:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw")
        assertEquals("keepersecurity.eu", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "AU:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw")
        assertEquals("keepersecurity.com.au", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "eu:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw")
        assertEquals("keepersecurity.eu", storage.getString("hostname"))
        storage = InMemoryStorage()
        initializeStorage(storage, "local.keepersecurity.com:BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw")
        assertEquals("local.keepersecurity.com", storage.getString("hostname"))
    }

    @Test
    fun testStorageBase64Config() {
        val base64Config: String = "eyAgICAgImFwcEtleSI6ICI4S3gyNVN2dGtSU3NFWUl1cjdtSEt0THFBTkZOQjdBWlJhOWNxaTJQU1FFPSIsICAgICAiY2x" +
                "pZW50SWQiOiAiNEgvVTVKNkRjZktMWUJJSUFWNVl3RUZHNG4zWGhpRHZOdG9Qa21TTUlUZVROWnNhL0VKMHpUYnBBQ1J0bU" +
                "5VQlJIK052UisyNHNRaFU5dUdqTFRaSHc9PSIsICAgICAiaG9zdG5hbWUiOiAia2VlcGVyc2VjdXJpdHkuY29tIiwgICAgI" +
                "CJwcml2YXRlS2V5IjogIk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ3VoekRJNGlW" +
                "UzVCdzlsNWNmZkZYcFArRmh1bE5INDFHRFdWY3NiZ1h5aU9oUkFOQ0FBVGsxZnpvTDgvVkxwdVl1dTEzd0VsUE5wM2FHMmd" +
                "sRmtFUHp4YWlNZ1ArdnRVZDRnWjIzVHBHdTFzMXRxS2FFZTloN1ZDVk1qd3ZEQTMxYW5mTWxZRjUiLCAgICAgInNlcnZlcl" +
                "B1YmxpY0tleUlkIjogIjEwIiB9"
        val storage = InMemoryStorage(base64Config)
        assertEquals("keepersecurity.com", storage.getString("hostname"))
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

    //    @Test // uncomment to debug the integration test
    fun integrationTest() {
        val trustAllPostFunction: (
            url: String,
            transmissionKey: TransmissionKey,
            payload: EncryptedPayload,
        ) -> KeeperHttpResponse = { url, transmissionKey, payload -> postFunction(url, transmissionKey, payload, true) }
        val storage = LocalConfigStorage("config-prod-msp1.json")
        initializeStorage(storage, "BZ1RK0CpTSuGbjozAQW9DmUuUyN42Rxg-ulNsUN5gXw", "keepersecurity.com")
        val options = SecretsManagerOptions(storage, trustAllPostFunction)
//        val options = SecretsManagerOptions(storage, ::cachingPostFunction)
        val secrets = getSecrets(options)
        val record = secrets.records[0]
        val password = record.getPassword()
        if (password != null) {
            println(password)
//            record.updatePassword("new password")
//            updateSecret(options, record)
        }
//        val file = record.getFileByUid("XISgEFjKffxAsjzYCUJ6Bg")
//        if (file != null) {
//            val fileBytes = downloadFile(file)
//            val fos = FileOutputStream(file.data.name)
//            fos.write(fileBytes)
//            fos.close()
//        }
    }
}