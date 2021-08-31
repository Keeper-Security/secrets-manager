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
}