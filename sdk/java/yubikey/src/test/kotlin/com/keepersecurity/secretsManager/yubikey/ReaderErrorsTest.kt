package com.keepersecurity.secretsManager.yubikey

import javax.smartcardio.CardException
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

internal class ReaderErrorsTest {

    // On Linux, pcsc-lite refuses a client outside an active local session with an access error. Reporting that as
    // "no readers" sends people to plug in a YubiKey that is already plugged in.
    @Test
    fun pcscErrorsOtherThanNoReadersAreNotHidden() {
        for (code in listOf("SCARD_E_NO_SERVICE", "SCARD_E_NO_ACCESS")) {
            val failure = CardException("list() failed", RuntimeException(code))
            val ex = assertFailsWith<YubiKeyException>("$code must be reported") { YubiKeySigner.terminals { throw failure } }
            assertTrue(ex.message!!.contains(code), ex.message)
        }
    }
}
