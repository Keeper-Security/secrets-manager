package com.keepersecurity.secretsManager.core

import org.bouncycastle.util.BigIntegers
import java.math.BigInteger
import kotlin.test.*

internal class CryptoUtilsTest {

    @Test
    fun privateKeyCompatibilityTest() {
        val privateKey64 = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg34GXYbMpXKaHcHZW4dIMO3WYU8zTjB6t+41SRsY1rwqgCgYIKoZIzj0DAQehRANCAAQGH/4ZwpGR9B7AlMjVY7ekpjOcaD3rhuO25CmOZxI3wqRDdhXQIdDnuWvQPCZ3ymtjL3C8JrVIcloklwYI9T7+"
        val privateKey = base64ToBytes(privateKey64)
        val importedPrivateKey = importPrivateKey(privateKey)
        val privateRaw = privateKey.copyOfRange(36, 68)
        println(bytesToBase64(privateRaw))
        val privateInt = BigInteger(1, privateRaw)
//        val privateInt = BigIntegers.fromUnsignedByteArray(privateRaw)
        println(privateInt.toString(16).uppercase())
        val privateHex = importedPrivateKey.s.toString(16)
        assertEquals(privateKey64, bytesToBase64(importedPrivateKey.s.toByteArray()))
        val exportedPublicKey = exportPublicKey(privateKey)
        assertEquals(65, exportedPublicKey.size)
        assertEquals("BJyaZ/P2+IoV4nNSsjW9nCj3zLYF/ZM3LJuQ8c5LVckD5L9gUVGEewsyPvkjdBQO5hMA4tz1hBbnw9Ge970xyB0=", bytesToBase64(exportedPublicKey))
        val data = getRandomBytes(32)
        val ciphertext = publicEncrypt(data, exportedPublicKey)
        val plaintext = privateDecrypt(ciphertext, privateKey)
        assertContentEquals(data, plaintext)
    }
}