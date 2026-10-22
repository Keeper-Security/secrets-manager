package com.keepersecurity.secretsManager.yubikey

import kotlin.test.*

internal class YubiKeySignerTest {

    private fun signer(card: FakePivCard, pin: String = "123456", slot: PivSlot? = PivSlot.AUTHENTICATION) =
        YubiKeySigner(pin.toCharArray(), null, slot) { YubiKeySigner.Connection(card, null) }

    // pinProvider null: a signer without a PIN
    private fun lazySigner(card: FakePivCard, pinProvider: PinProvider?, slot: PivSlot? = null) =
        YubiKeySigner(null, pinProvider, slot) { YubiKeySigner.Connection(card, null) }

    private fun forPublicKey(card: FakePivCard, publicKey: ByteArray) =
        YubiKeySigner.forPublicKey("123456".toCharArray(), null, publicKey) { YubiKeySigner.Connection(card, null) }

    private fun forPublicKey(card: FakePivCard, pinProvider: PinProvider?, publicKey: ByteArray) =
        YubiKeySigner.forPublicKey(null, pinProvider, publicKey) { YubiKeySigner.Connection(card, null) }

    private class CountingPinProvider(private val pin: String = "123456") : PinProvider {
        var calls = 0
        override fun pin(): CharArray {
            calls++
            return pin.toCharArray()
        }
    }

    private val unattendedAppKey = ByteArray(32) { it.toByte() }

    // A PIN-less config as it exists after binding: key generated without a PIN, app key wrapped
    private fun pinlessConfig(card: FakePivCard): Pair<ByteArray, ByteArray> = lazySigner(card, null).use { signer ->
        val publicKey = signer.generateKey(pinPolicy = PinPolicy.NEVER)
        publicKey to signer.wrap(unattendedAppKey)
    }

    @Test
    fun pinlessKeyWrapsAndUnwrapsAppKeyWithoutPin() {
        val card = FakePivCard()
        val (publicKey, wrapped) = pinlessConfig(card)
        assertEquals(YubiKeySigner.PINLESS_WRAPPING_KEY_NAME, certificateName(card, PivSlot.KEY_MANAGEMENT), "the PIN-less config gets the PIN-less wrapping key")
        assertEquals(1, card.keys[PivSlot.KEY_MANAGEMENT.keyRef]!!.pinPolicy, "the PIN-less wrapping key has PIN policy NEVER")
        forPublicKey(card, null, publicKey).use { signer ->
            assertContentEquals(unattendedAppKey, signer.unwrap(wrapped), "unwrap returns the wrapped app key")
        }
        assertEquals(0, card.pinAttempts, "wrap and unwrap must not send a PIN")
    }

    @Test
    fun pinlessKeySignsAfterSecurityStatusIsLost() {
        val card = FakePivCard()
        val (publicKey, _) = pinlessConfig(card)
        val data = "unattended".toByteArray()
        forPublicKey(card, null, publicKey).use { signer ->
            assertTrue(YubiKeySigner.verify(publicKey, data, signer.sign(data)), "signature before the reset")
            card.resetSecurityStatus()
            assertTrue(YubiKeySigner.verify(publicKey, data, signer.sign(data)), "signature after the card lost its security status")
        }
        assertEquals(0, card.pinAttempts, "signing must not send a PIN")
    }

    @Test
    fun pinlessKeyLocationNamesUnattendedUseAndFollowsReplacement() {
        val card = FakePivCard()
        val (publicKey, _) = pinlessConfig(card)
        forPublicKey(card, null, publicKey).use { signer ->
            assertEquals("YubiKey 5C NFC FIPS, serial 34822070, PIV slot 82 (RETIRED1), unattended (no PIN)", signer.keyLocation)
        }
        signer(card, slot = PivSlot.RETIRED1).use { signer ->
            signer.generateKey(pinPolicy = PinPolicy.NEVER, overwrite = true)
            assertTrue(signer.keyLocation!!.endsWith("unattended (no PIN)"), "a replacement PIN-less key keeps the suffix")
            signer.generateKey(overwrite = true)
            assertEquals("YubiKey 5C NFC FIPS, serial 34822070, PIV slot 82 (RETIRED1)", signer.keyLocation, "a PIN-protected replacement drops the suffix")
        }
    }

    @Test
    fun pinlessAndPinConfigsUseSeparateWrappingKeys() {
        val card = FakePivCard()
        val appKey = ByteArray(32) { 7 }
        val (pinPublicKey, pinWrapped) = signer(card, slot = null).use { it.generateKey() to it.wrap(appKey) }
        val (pinlessPublicKey, pinlessWrapped) = lazySigner(card, null).use {
            it.generateKey(pinPolicy = PinPolicy.NEVER) to it.wrap(appKey)
        }
        assertFalse(
            AppKeyWrap.parse(pinWrapped).wrappingPublicKey.contentEquals(AppKeyWrap.parse(pinlessWrapped).wrappingPublicKey),
            "the two configs must not share a wrapping key"
        )
        forPublicKey(card, pinPublicKey).use { assertContentEquals(appKey, it.unwrap(pinWrapped), "PIN config") }
        forPublicKey(card, null, pinlessPublicKey).use { assertContentEquals(appKey, it.unwrap(pinlessWrapped), "PIN-less config") }
    }

    @Test
    fun pinKeyWithoutPinFailsBeforeGenerating() {
        val card = FakePivCard()
        val ex = assertFailsWith<YubiKeyException> { lazySigner(card, null).use { it.generateKey() } }
        assertTrue(ex.message!!.contains("the signer has none"), ex.message)
        assertTrue(card.keys.isEmpty(), "no key may be generated without the PIN")
    }

    @Test
    fun pinKeyWithoutPinFailsToSign() {
        val card = FakePivCard()
        card.installKey(PivSlot.RETIRED1.keyRef)
        val publicKey = FakePivCard.rawPublicKey(card.keys[PivSlot.RETIRED1.keyRef]!!)
        val ex = assertFailsWith<YubiKeyException> { forPublicKey(card, null, publicKey).use { it.sign(ByteArray(1)) } }
        assertTrue(ex.message!!.contains("requires the PIV PIN"), ex.message)
    }

    @Test
    fun pinProviderIsAskedOnlyWhenNeeded() {
        val card = FakePivCard()
        card.installKey(PivSlot.RETIRED1.keyRef, pinPolicy = 1)
        card.installKey(PivSlot.RETIRED2.keyRef, pinPolicy = 2)
        val pinless = FakePivCard.rawPublicKey(card.keys[PivSlot.RETIRED1.keyRef]!!)
        val withPin = FakePivCard.rawPublicKey(card.keys[PivSlot.RETIRED2.keyRef]!!)

        val notAsked = CountingPinProvider()
        forPublicKey(card, notAsked, pinless).use { it.sign(ByteArray(1)) }
        assertEquals(0, notAsked.calls)

        val asked = CountingPinProvider()
        forPublicKey(card, asked, withPin).use { signer ->
            signer.sign(ByteArray(1))
            signer.sign(ByteArray(2))
            card.resetSecurityStatus()
            signer.sign(ByteArray(3))
        }
        assertEquals(1, asked.calls, "the PIN is asked for once and kept until close")
    }

    @Test
    fun picksFreeRetiredSlotsPerConfig() {
        val card = FakePivCard()
        card.certificates[PivSlot.RETIRED1.objectId] = byteArrayOf(1)
        signer(card, slot = null).use { signer ->
            assertNull(signer.slot)
            assertNull(signer.keyLocation)
            signer.generateKey()
            assertEquals(PivSlot.RETIRED2, signer.slot, "RETIRED1 holds a certificate")
        }
        signer(card, slot = null).use { signer ->
            signer.generateKey()
            assertEquals(PivSlot.RETIRED3, signer.slot, "RETIRED2 now holds a key")
        }
        assertEquals(setOf(0x83, 0x84, 0x9D), card.keys.keys, "two client keys and the shared wrapping key")
    }

    @Test
    fun forPublicKeyFindsTheSlotOfEachConfig() {
        val card = FakePivCard()
        card.installKey(PivSlot.RETIRED2.keyRef)
        card.installKey(PivSlot.RETIRED3.keyRef)
        for (slot in listOf(PivSlot.RETIRED2, PivSlot.RETIRED3)) {
            val publicKey = FakePivCard.rawPublicKey(card.keys[slot.keyRef]!!)
            forPublicKey(card, publicKey).use { signer ->
                assertEquals(slot, signer.slot)
                val data = "config".toByteArray()
                assertTrue(YubiKeySigner.verify(publicKey, data, signer.sign(data)), "signature of the key in $slot")
            }
        }
    }

    @Test
    fun keyLocationWithoutManagementApplication() {
        val card = FakePivCard()
        card.deviceInfo = null
        signer(card).use { signer ->
            signer.generateKey()
            assertEquals("YubiKey, serial 19088743, PIV slot 9A (AUTHENTICATION)", signer.keyLocation)
        }
    }

    @Test
    fun deviceNames() {
        fun name(formFactor: Int, nfc: Boolean, version: IntArray = intArrayOf(5, 4, 3)) =
            DeviceInfo(null, formFactor and 0x0F, (formFactor and 0x80) != 0, (formFactor and 0x40) != 0, nfc, version).name
        assertEquals("YubiKey 5C NFC FIPS", name(0x83, nfc = true))
        assertEquals("YubiKey 5 Nano", name(0x02, nfc = false))
        assertEquals("YubiKey C Bio", name(0x07, nfc = false))
        assertEquals("YubiKey 4", name(0x01, nfc = false, version = intArrayOf(4, 3, 5)))
    }

    private fun certificateName(card: FakePivCard, slot: PivSlot): String? {
        val value = card.certificates[slot.objectId] ?: return null
        return Certificates.commonName(Tlv.parse(value)[0x70]!!)
    }

    @Test
    fun generateKeyCreatesAndReusesTheWrappingKey() {
        val card = FakePivCard()
        signer(card, slot = null).use { signer ->
            signer.generateKey()
            assertEquals(PivSlot.RETIRED1, signer.slot)
        }
        assertEquals(YubiKeySigner.WRAPPING_KEY_NAME, certificateName(card, PivSlot.KEY_MANAGEMENT))

        signer(card, slot = null).use { it.generateKey() }
        assertEquals(setOf(0x9D, 0x82, 0x83), card.keys.keys, "a second config reuses the wrapping key")
    }

    @Test
    fun wrappingKeyCertificateIsValidAndAllowsKeyAgreement() {
        val card = FakePivCard()
        signer(card, slot = null).use { it.generateKey() }
        val der = Tlv.parse(card.certificates[PivSlot.KEY_MANAGEMENT.objectId]!!)[0x70]!!
        val x509 = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(der.inputStream()) as java.security.cert.X509Certificate
        val publicKey = FakePivCard.rawPublicKey(card.keys[PivSlot.KEY_MANAGEMENT.keyRef]!!)
        x509.verify(AppKeyWrap.p256PublicKey(publicKey))
        assertTrue(x509.keyUsage[4], "the wrapping key certificate allows key agreement")
    }

    @Test
    fun wrappingKeyMovesToRetiredSlotWhenKeyManagementIsTaken() {
        val card = FakePivCard()
        card.installKey(PivSlot.KEY_MANAGEMENT.keyRef)
        signer(card, slot = null).use { it.generateKey() }
        assertNull(card.certificates[PivSlot.KEY_MANAGEMENT.objectId], "a foreign 9D key is left alone")
        assertEquals(YubiKeySigner.WRAPPING_KEY_NAME, certificateName(card, PivSlot.RETIRED2))
    }

    @Test
    fun wrapWithoutWrappingKeyFails() {
        val card = FakePivCard()
        card.installKey(PivSlot.RETIRED1.keyRef)
        val publicKey = FakePivCard.rawPublicKey(card.keys[0x82]!!)
        val ex = assertFailsWith<YubiKeyException> { forPublicKey(card, publicKey).use { it.wrap(ByteArray(32)) } }
        assertTrue(ex.message!!.contains("no app key wrapping key"), ex.message)
    }

    // The wrapping key is found by certificate name. Anyone with the factory management key can write a
    // certificate with that name, so the key behind it has to be checked too.
    private fun plantWrappingKey(card: FakePivCard, slot: PivSlot, name: String, pinPolicy: Int, origin: Int) {
        card.installKey(slot.keyRef, pinPolicy, origin)
        val publicKey = FakePivCard.rawPublicKey(card.keys[slot.keyRef]!!)
        card.certificates[slot.objectId] = tlv(0x70, Certificates.selfSigned(publicKey, name, true) { ByteArray(64) })
    }

    @Test
    fun wrappingKeyImportedIntoTheCardIsRejected() {
        // (certificate name, PIN policy of the client key and of the planted key)
        for ((name, policy) in listOf(YubiKeySigner.WRAPPING_KEY_NAME to 2, YubiKeySigner.PINLESS_WRAPPING_KEY_NAME to 1)) {
            val card = FakePivCard()
            card.installKey(PivSlot.RETIRED1.keyRef, pinPolicy = policy)
            plantWrappingKey(card, PivSlot.RETIRED5, name, pinPolicy = policy, origin = 2)
            val publicKey = FakePivCard.rawPublicKey(card.keys[0x82]!!)
            val ex = assertFailsWith<YubiKeyException>("wrapping to an imported key named '$name' must fail") {
                forPublicKey(card, null, publicKey).use { it.wrap(ByteArray(32)) }
            }
            assertTrue(ex.message!!.contains("RETIRED5"), ex.message)
        }
    }

    @Test
    fun wrappingKeyWithTheWrongPinPolicyIsRejected() {
        // (certificate name, PIN policy of the client key, PIN policy of the planted key); both keys generated on the card
        val cases = listOf(
            Triple(YubiKeySigner.WRAPPING_KEY_NAME, 2, 1),
            Triple(YubiKeySigner.PINLESS_WRAPPING_KEY_NAME, 1, 2)
        )
        for ((name, clientPolicy, plantedPolicy) in cases) {
            val card = FakePivCard()
            card.installKey(PivSlot.RETIRED1.keyRef, pinPolicy = clientPolicy)
            plantWrappingKey(card, PivSlot.RETIRED5, name, pinPolicy = plantedPolicy, origin = 1)
            val publicKey = FakePivCard.rawPublicKey(card.keys[0x82]!!)
            val ex = assertFailsWith<YubiKeyException>("'$name' with PIN policy $plantedPolicy must be rejected") {
                forPublicKey(card, null, publicKey).use { it.wrap(ByteArray(32)) }
            }
            assertTrue(ex.message!!.contains("RETIRED5"), ex.message)
        }
    }

    @Test
    fun onBoundNamesTheCertificateAfterTheApplication() {
        val card = FakePivCard()
        signer(card, slot = null).use { signer ->
            signer.generateKey()
            assertNull(certificateName(card, PivSlot.RETIRED1))
            signer.onBound(com.keepersecurity.secretsManager.core.AppData("Production App", "General"))
            assertEquals("Production App", certificateName(card, PivSlot.RETIRED1))
            // Only once, at binding
            signer.onBound(com.keepersecurity.secretsManager.core.AppData("Renamed", "General"))
            assertEquals("Production App", certificateName(card, PivSlot.RETIRED1))
        }
    }

    @Test
    fun forPublicKeyRejectsUnknownKey() {
        val card = FakePivCard()
        card.installKey(PivSlot.AUTHENTICATION.keyRef)
        val other = FakePivCard.rawPublicKey(FakePivCard.Key(FakePivCard.newKeyPair(), 2))
        val ex = assertFailsWith<YubiKeyException> { forPublicKey(card, other) }
        assertEquals("The key of this config is not on the connected YubiKey", ex.message)
    }

    @Test
    fun autoSlotNeedsMetadata() {
        val ex = assertFailsWith<YubiKeyException> { signer(FakePivCard(version = intArrayOf(4, 3, 5)), slot = null).generateKey() }
        assertTrue(ex.message!!.contains("Pass the slot explicitly"), ex.message)
    }

    @Test
    fun signWithoutSlotFails() {
        val ex = assertFailsWith<YubiKeyException> { signer(FakePivCard(), slot = null).sign(ByteArray(1)) }
        assertTrue(ex.message!!.startsWith("No slot selected"), ex.message)
    }

    @Test
    fun generateSignVerify() {
        val card = FakePivCard()
        signer(card).use { signer ->
            val publicKey = signer.generateKey()
            assertEquals(65, publicKey.size)
            assertContentEquals(publicKey, signer.publicKey)
            assertEquals("5.4.3", signer.version)

            val data = "request".toByteArray()
            assertTrue(YubiKeySigner.verify(publicKey, data, signer.sign(data)))
            assertTrue(YubiKeySigner.verify(publicKey, data, signer.sign(data)))
        }
    }

    @Test
    fun chainedResponses() {
        val card = FakePivCard(chainResponses = true)
        signer(card).use { signer ->
            val publicKey = signer.generateKey()
            val data = "chained".toByteArray()
            assertTrue(YubiKeySigner.verify(publicKey, data, signer.sign(data)))
        }
    }

    @Test
    fun wrongPinIsReportedWithRetriesLeft() {
        val card = FakePivCard()
        card.installKey(PivSlot.AUTHENTICATION.keyRef)
        val ex = assertFailsWith<YubiKeyException> { signer(card, pin = "654321").verifyPin() }
        assertTrue(ex.message!!.startsWith("Wrong PIV PIN, 2 retries left"), ex.message)
        assertTrue(ex.message!!.contains("factory default"), ex.message)

        signer(card).use { it.verifyPin() }

        val signCard = FakePivCard()
        signCard.installKey(PivSlot.AUTHENTICATION.keyRef)
        val signEx = assertFailsWith<YubiKeyException> { signer(signCard, pin = "654321").sign(ByteArray(1)) }
        assertEquals(ex.message, signEx.message, "sign() reports a wrong PIN like verifyPin()")
    }

    @Test
    fun verifyPinNeedsNoPinForAPinlessKey() {
        val card = FakePivCard()
        val publicKey = lazySigner(card, null).use { it.generateKey(pinPolicy = PinPolicy.NEVER) }
        forPublicKey(card, null, publicKey).use { it.verifyPin() }
        assertEquals(0, card.pinAttempts)
    }

    @Test
    fun wrongPinLeavesSlotUntouched() {
        val card = FakePivCard()
        val ex = assertFailsWith<YubiKeyException> { signer(card, pin = "654321").generateKey() }
        assertTrue(ex.message!!.startsWith("Wrong PIV PIN"), ex.message)
        assertTrue(card.keys.isEmpty(), "no key may be generated when the PIN is wrong")
        assertEquals(65, signer(card).generateKey().size)
    }

    @Test
    fun reVerifiesPinAfterSecurityStatusIsLost() {
        val card = FakePivCard()
        signer(card).use { signer ->
            val publicKey = signer.generateKey()
            card.resetSecurityStatus()
            val data = "after reset".toByteArray()
            assertTrue(YubiKeySigner.verify(publicKey, data, signer.sign(data)))
        }
    }

    @Test
    fun pinAlwaysSlot() {
        val card = FakePivCard()
        signer(card, slot = PivSlot.SIGNATURE).use { signer ->
            val publicKey = signer.generateKey()
            val commandsBefore = card.signCommands
            val attemptsBefore = card.pinAttempts
            repeat(3) {
                val data = "sig$it".toByteArray()
                assertTrue(YubiKeySigner.verify(publicKey, data, signer.sign(data)))
            }
            assertEquals(3, card.signCommands - commandsBefore, "one sign command per sign(), none refused for a missing PIN")
            assertEquals(3, card.pinAttempts - attemptsBefore, "the PIN is sent before each sign()")
        }
    }

    @Test
    fun refusesToOverwriteExistingKey() {
        val card = FakePivCard()
        signer(card).use { signer ->
            val first = signer.generateKey()
            val ex = assertFailsWith<YubiKeyException> { signer.generateKey() }
            assertTrue(ex.message!!.contains("already holds a key"), ex.message)
            assertContentEquals(first, signer.publicKey)
            assertFalse(first.contentEquals(signer.generateKey(overwrite = true)))
        }
    }

    @Test
    fun refusesToOverwriteCertificateOnOlderFirmware() {
        val card = FakePivCard(version = intArrayOf(4, 3, 5))
        card.certificates[PivSlot.AUTHENTICATION.objectId] = byteArrayOf(1, 2, 3)
        signer(card).use { signer ->
            val ex = assertFailsWith<YubiKeyException> { signer.generateKey() }
            assertTrue(ex.message!!.contains("already holds a certificate"), ex.message)

            val publicKey = signer.generateKey(overwrite = true)
            assertFalse(card.certificates.containsKey(PivSlot.AUTHENTICATION.objectId), "stale certificate must be deleted")
            val data = "old firmware".toByteArray()
            assertTrue(YubiKeySigner.verify(publicKey, data, signer.sign(data)))
        }
    }

    @Test
    fun publicKeyCannotBeReadOnOlderFirmware() {
        val card = FakePivCard(version = intArrayOf(4, 3, 5))
        signer(card).use { signer ->
            signer.generateKey()
            assertFailsWith<YubiKeyException>("GET METADATA needs firmware 5.3") { signer.publicKey }
        }
    }

    @Test
    fun keyLocationOnOlderFirmwareNamesYubiKey4() {
        val card = FakePivCard(version = intArrayOf(4, 3, 5))
        signer(card).use { signer ->
            signer.generateKey()
            assertEquals("YubiKey 4, PIV slot 9A (AUTHENTICATION)", signer.keyLocation)
        }
    }

    @Test
    fun rejectsDevicesWithoutP256() {
        val card = FakePivCard(supportsP256 = false)
        val ex = assertFailsWith<YubiKeyException> { signer(card).generateKey() }
        assertTrue(ex.message!!.contains("P-256"), ex.message)
    }

    @Test
    fun wrongManagementKey() {
        val card = FakePivCard()
        val ex = assertFailsWith<YubiKeyException> { signer(card).generateKey(ByteArray(24) { 7 }) }
        assertEquals("Wrong PIV management key", ex.message)
        assertTrue(card.keys.isEmpty())
    }

    @Test
    fun signFailsOnEmptySlot() {
        val ex = assertFailsWith<YubiKeyException> { signer(FakePivCard()).sign(ByteArray(1)) }
        assertTrue(ex.message!!.contains("no key"), ex.message)
    }
}
