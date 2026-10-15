package com.keepersecurity.secretsManager.yubikey

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec
import javax.smartcardio.Card
import javax.smartcardio.CardChannel
import javax.smartcardio.CommandAPDU
import javax.smartcardio.ResponseAPDU

// Simulates the subset of the YubiKey PIV application used by PivSession
internal class FakePivCard(
    var version: IntArray = intArrayOf(5, 4, 3),
    var supportsP256: Boolean = true,
    // Split responses into 32 byte chunks with 61xx to exercise GET RESPONSE
    var chainResponses: Boolean = false
) : CardChannel() {

    // origin is the GET METADATA tag 03 value: 1 generated on the card, 2 imported
    class Key(val keyPair: KeyPair, val pinPolicy: Int, val origin: Int = 1)

    val pin = "123456"
    val managementKey = YubiKeySigner.DEFAULT_MANAGEMENT_KEY
    var pinRetries = 3
    val keys = HashMap<Int, Key>()
    val certificates = HashMap<Int, ByteArray>()
    var signCount = 0
    // VERIFY commands that carry a PIN (not the retry count queries)
    var pinAttempts = 0

    private var pinVerified = false
    private var managementAuthenticated = false
    private var witness: ByteArray? = null
    private var pending = ByteArray(0)
    private var managementSelected = false
    private var chained = ByteArray(0)
    var chainedCommands = 0

    // READ CONFIG response of a YubiKey 5C NFC FIPS, firmware 5.4.3, serial 34822070
    var deviceInfo: ByteArray? = hex("2E0102031E0302031E0204021357B604018305030504030602000007010F0801000D02031E0E02031E0A01000F0100")

    fun installKey(keyRef: Int, pinPolicy: Int = 2, origin: Int = 1) {
        keys[keyRef] = Key(newKeyPair(), pinPolicy, origin)
    }

    // Simulates another application selecting the card, which drops the PIN state
    fun resetSecurityStatus() {
        pinVerified = false
        managementAuthenticated = false
    }

    override fun transmit(command: CommandAPDU): ResponseAPDU {
        if (command.ins == 0xC0) return respond(ByteArray(0), 0x9000, fromPending = true)
        // Command chaining: CLA 10 means more data follows
        if ((command.cla and 0x10) != 0) {
            chained += command.data
            return sw(0x9000)
        }
        val data = chained + command.data
        chained = ByteArray(0)
        if (data.size > 255) chainedCommands++
        return when (command.ins) {
            0xA4 -> select(data)
            0x1D -> deviceInfo?.takeIf { managementSelected && version[0] >= 5 }?.let { respond(it) } ?: sw(0x6D00)
            0xFD -> respond(ByteArray(3) { version[it].toByte() })
            0x20 -> verify(data)
            0x87 -> if (command.p2 == KEY_REF_MANAGEMENT) authenticate(command.p1, data) else sign(command.p1, command.p2, data)
            0x47 -> generate(command.p2, data)
            0xF7 -> metadata(command.p2)
            0xF8 -> if (version[0] >= 5) respond(byteArrayOf(0x01, 0x23, 0x45, 0x67)) else sw(0x6D00)
            0xCB -> certificates[objectId(data)]?.let { respond(tlv(0x53, it)) } ?: sw(0x6A82)
            0xDB -> putData(data)
            else -> sw(0x6D00)
        }
    }

    private fun select(aid: ByteArray): ResponseAPDU {
        managementSelected = aid.contentEquals(MANAGEMENT_AID)
        // Device info over CCID needs firmware 5
        if (managementSelected) return if (deviceInfo != null && version[0] >= 5) respond("Virtual mgr".toByteArray()) else sw(0x6A82)
        // Selecting PIV resets its security status, as on a real YubiKey
        resetSecurityStatus()
        return respond(ByteArray(0))
    }

    private fun verify(data: ByteArray): ResponseAPDU {
        if (data.isEmpty()) return if (pinVerified) sw(0x9000) else sw(0x63C0 or pinRetries)
        pinAttempts++
        if (pinRetries == 0) return sw(0x6983)
        val expected = ByteArray(8) { if (it < pin.length) pin[it].code.toByte() else 0xFF.toByte() }
        if (!expected.contentEquals(data)) {
            pinRetries--
            pinVerified = false
            return sw(0x63C0 or pinRetries)
        }
        pinRetries = 3
        pinVerified = true
        return sw(0x9000)
    }

    private fun authenticate(algorithm: Int, data: ByteArray): ResponseAPDU {
        if (algorithm != ALG_3DES) return sw(0x6A86)
        val fields = Tlv.parse(Tlv.parse(data)[0x7C]!!)
        val cipher = { mode: Int, input: ByteArray ->
            Cipher.getInstance("DESede/ECB/NoPadding").run {
                init(mode, SecretKeySpec(managementKey, "DESede"))
                doFinal(input)
            }
        }
        val challenge = fields[0x81]
        if (challenge == null) {
            witness = ByteArray(8).also { SecureRandom().nextBytes(it) }
            return respond(tlv(0x7C, tlv(0x80, cipher(Cipher.ENCRYPT_MODE, witness!!))))
        }
        val expected = witness ?: return sw(0x6982)
        witness = null
        if (!expected.contentEquals(fields[0x80])) return sw(0x6982)
        managementAuthenticated = true
        return respond(tlv(0x7C, tlv(0x82, cipher(Cipher.ENCRYPT_MODE, challenge))))
    }

    private fun sign(algorithm: Int, keyRef: Int, data: ByteArray): ResponseAPDU {
        val key = keys[keyRef] ?: return sw(0x6A88)
        if (algorithm != ALG_ECCP256) return sw(0x6A80)
        if (key.pinPolicy != 1 && !pinVerified) return sw(0x6982)
        if (key.pinPolicy == 3) pinVerified = false
        val fields = Tlv.parse(Tlv.parse(data)[0x7C]!!)
        fields[0x85]?.let { peer ->
            val secret = KeyAgreement.getInstance("ECDH").run {
                init(key.keyPair.private)
                doPhase(AppKeyWrap.p256PublicKey(peer), true)
                generateSecret()
            }
            return respond(tlv(0x7C, tlv(0x82, secret)))
        }
        val digest = fields[0x81]!!
        val signature = Signature.getInstance("NONEwithECDSA").run {
            initSign(key.keyPair.private)
            update(digest)
            sign()
        }
        signCount++
        return respond(tlv(0x7C, tlv(0x82, signature)))
    }

    private fun generate(keyRef: Int, data: ByteArray): ResponseAPDU {
        if (!managementAuthenticated) return sw(0x6982)
        val template = Tlv.parse(Tlv.parse(data)[0xAC]!!)
        if (!supportsP256 || template[0x80]?.get(0)?.toInt() != ALG_ECCP256) return sw(0x6A80)
        val pinPolicy = template[0xAA]?.get(0)?.toInt() ?: if (keyRef == 0x9C) 3 else 2
        val key = Key(newKeyPair(), pinPolicy)
        keys[keyRef] = key
        return respond(tlv(0x7F49, tlv(0x86, rawPublicKey(key))))
    }

    private fun metadata(keyRef: Int): ResponseAPDU {
        if (version[0] < 5 || (version[0] == 5 && version[1] < 3)) return sw(0x6D00)
        if (keyRef == KEY_REF_MANAGEMENT) {
            return respond(tlv(0x01, byteArrayOf(ALG_3DES.toByte())) + tlv(0x02, byteArrayOf(0, 1)))
        }
        if (keyRef == KEY_REF_PIN) {
            return respond(
                tlv(0x01, byteArrayOf(0xFF.toByte())) +
                        tlv(0x05, byteArrayOf(if (pin == "123456") 1 else 0)) +
                        tlv(0x06, byteArrayOf(3, pinRetries.toByte()))
            )
        }
        val key = keys[keyRef] ?: return sw(0x6A88)
        return respond(
            tlv(0x01, byteArrayOf(ALG_ECCP256.toByte())) +
                    tlv(0x02, byteArrayOf(key.pinPolicy.toByte(), 1)) +
                    tlv(0x03, byteArrayOf(key.origin.toByte())) +
                    tlv(0x04, tlv(0x86, rawPublicKey(key)))
        )
    }

    private fun putData(data: ByteArray): ResponseAPDU {
        if (!managementAuthenticated) return sw(0x6982)
        val fields = Tlv.parse(data)
        val id = objectId(data)
        val value = fields[0x53]!!
        if (value.isEmpty()) certificates.remove(id) else certificates[id] = value
        return sw(0x9000)
    }

    private fun objectId(data: ByteArray): Int =
        Tlv.parse(data)[0x5C]!!.fold(0) { acc, b -> (acc shl 8) or b.u() }

    private fun respond(data: ByteArray, status: Int = 0x9000, fromPending: Boolean = false): ResponseAPDU {
        val payload = if (fromPending) pending else data
        if (!chainResponses || payload.size <= 32) {
            pending = ByteArray(0)
            return ResponseAPDU(payload + byteArrayOf((status shr 8).toByte(), status.toByte()))
        }
        pending = payload.copyOfRange(32, payload.size)
        val remaining = minOf(pending.size, 0xFF)
        return ResponseAPDU(payload.copyOfRange(0, 32) + byteArrayOf(0x61, remaining.toByte()))
    }

    private fun sw(status: Int) = ResponseAPDU(byteArrayOf((status shr 8).toByte(), status.toByte()))

    override fun getCard(): Card = throw UnsupportedOperationException()
    override fun getChannelNumber() = 0
    override fun transmit(command: ByteBuffer, response: ByteBuffer): Int = throw UnsupportedOperationException()
    override fun close() {}

    companion object {
        private val MANAGEMENT_AID = hex("A000000527471117")

        fun hex(value: String) = ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

        fun newKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }

        fun rawPublicKey(key: Key): ByteArray {
            val point = (key.keyPair.public as ECPublicKey).w
            val out = ByteArrayOutputStream()
            out.write(0x04)
            out.write(fixed32(point.affineX))
            out.write(fixed32(point.affineY))
            return out.toByteArray()
        }

        private fun fixed32(value: BigInteger): ByteArray {
            val bytes = value.toByteArray().takeLast(32).toByteArray()
            return ByteArray(32 - bytes.size) + bytes
        }
    }
}
