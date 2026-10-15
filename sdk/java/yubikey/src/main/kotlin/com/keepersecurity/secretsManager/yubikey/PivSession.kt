package com.keepersecurity.secretsManager.yubikey

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.smartcardio.CardChannel
import javax.smartcardio.CommandAPDU

internal const val ALG_3DES = 0x03
internal const val ALG_AES128 = 0x08
internal const val ALG_AES192 = 0x0A
internal const val ALG_AES256 = 0x0C
internal const val ALG_ECCP256 = 0x11

internal const val KEY_REF_MANAGEMENT = 0x9B

private const val INS_SELECT = 0xA4
private const val INS_VERIFY = 0x20
private const val INS_AUTHENTICATE = 0x87
private const val INS_GENERATE = 0x47
private const val INS_GET_DATA = 0xCB
private const val INS_PUT_DATA = 0xDB
private const val INS_GET_RESPONSE = 0xC0
private const val INS_GET_VERSION = 0xFD
private const val INS_GET_METADATA = 0xF7
private const val INS_GET_SERIAL = 0xF8
private const val INS_READ_DEVICE_INFO = 0x1D

private const val SW_OK = 0x9000
private const val SW_SECURITY_STATUS = 0x6982
private const val SW_AUTH_BLOCKED = 0x6983
private const val SW_INCORRECT_DATA = 0x6A80
private const val SW_FILE_NOT_FOUND = 0x6A82
private const val SW_INCORRECT_P1P2 = 0x6A86
private const val SW_REFERENCE_NOT_FOUND = 0x6A88

private const val TAG_DYN_AUTH = 0x7C
private const val TAG_WITNESS = 0x80
private const val TAG_CHALLENGE = 0x81
private const val TAG_RESPONSE = 0x82
private const val TAG_EXPONENTIATION = 0x85

private val PIV_AID = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x03, 0x08)
private val MANAGEMENT_AID = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17)

internal class PivMetadata(
    val algorithm: Int,
    val pinPolicy: Int?,
    val touchPolicy: Int?,
    // 1 when the key was generated on the card, 2 when it was imported
    val origin: Int?,
    val isDefault: Boolean?,
    val publicKey: ByteArray?
)

internal const val ORIGIN_GENERATED = 1

internal const val KEY_REF_PIN = 0x80

// Minimal YubiKey PIV client: just what is needed to generate an ECC P-256 key and sign with it.
// Reference: NIST SP 800-73-4 and https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/
internal class PivSession(private val channel: CardChannel) {

    private class Response(val data: ByteArray, val sw: Int)

    var version = intArrayOf(0, 0, 0)
        private set

    // GET METADATA was added in firmware 5.3
    val metadataSupported: Boolean
        get() = version[0] > 5 || (version[0] == 5 && version[1] >= 3)

    // Model, serial and form factor from the Management application; null before firmware 5
    var deviceInfo: DeviceInfo? = null
        private set

    fun select() {
        // Read before selecting PIV: switching applications later would drop the PIN verification state
        if (transmit(INS_SELECT, 0x04, 0x00, MANAGEMENT_AID).sw == SW_OK) {
            val info = transmit(INS_READ_DEVICE_INFO, 0x00, 0x00, null)
            if (info.sw == SW_OK) deviceInfo = DeviceInfo.parse(info.data)
        }
        val r = transmit(INS_SELECT, 0x04, 0x00, PIV_AID)
        if (r.sw != SW_OK) throw YubiKeyException("The PIV application is not available on this device (${sw(r.sw)})")
        val v = transmit(INS_GET_VERSION, 0x00, 0x00, null)
        if (v.sw == SW_OK && v.data.size >= 3) {
            version = intArrayOf(v.data[0].u(), v.data[1].u(), v.data[2].u())
        }
    }

    // The serial number printed on the YubiKey; null before firmware 5.0
    fun serial(): Long? {
        val r = transmit(INS_GET_SERIAL, 0x00, 0x00, null)
        if (r.sw != SW_OK || r.data.size != 4) return null
        return r.data.fold(0L) { acc, b -> (acc shl 8) or b.u().toLong() }
    }

    fun verifyPin(pin: CharArray) {
        if (pin.size < 6 || pin.size > 8) throw YubiKeyException("The PIV PIN must be 6 to 8 characters long")
        val buffer = ByteArray(8) { 0xFF.toByte() }
        try {
            for (i in pin.indices) {
                if (pin[i].code > 0x7F) throw YubiKeyException("The PIV PIN must contain ASCII characters only")
                buffer[i] = pin[i].code.toByte()
            }
            val r = transmit(INS_VERIFY, 0x00, 0x80, buffer, expectResponse = false)
            when {
                r.sw == SW_OK -> {}
                r.sw == 0x63C0 || r.sw == SW_AUTH_BLOCKED ->
                    throw YubiKeyException("The PIV PIN is blocked, unblock it with the PUK")
                (r.sw and 0xFFF0) == 0x63C0 ->
                    throw WrongPinException("Wrong PIV PIN, ${r.sw and 0x0F} retries left" + defaultPinHint(), r.sw and 0x0F)
                else -> throw failure("PIN verification", r.sw)
            }
        } finally {
            buffer.fill(0)
        }
    }

    // The PIV PIN is separate from the FIDO2 PIN and is often never changed from the factory default
    private fun defaultPinHint(): String {
        val isDefault = try {
            metadataSupported && getMetadata(KEY_REF_PIN)?.isDefault == true
        } catch (e: YubiKeyException) {
            false
        }
        return if (isDefault) " (the PIV PIN of this YubiKey is still the factory default; it is not the FIDO2 PIN)" else ""
    }

    fun authenticateManagementKey(key: ByteArray) {
        val algorithm = if (metadataSupported) getMetadata(KEY_REF_MANAGEMENT)?.algorithm ?: ALG_3DES else ALG_3DES
        val (cipherName, keyLength) = when (algorithm) {
            ALG_3DES -> "DESede" to 24
            ALG_AES128 -> "AES" to 16
            ALG_AES192 -> "AES" to 24
            ALG_AES256 -> "AES" to 32
            else -> throw YubiKeyException("Unsupported management key algorithm ${"%02X".format(algorithm)}")
        }
        if (key.size != keyLength) {
            throw YubiKeyException("The management key of this YubiKey is $cipherName and must be $keyLength bytes long")
        }
        val keySpec = SecretKeySpec(key, cipherName)
        fun crypt(mode: Int, data: ByteArray): ByteArray =
            Cipher.getInstance("$cipherName/ECB/NoPadding").run {
                init(mode, keySpec)
                doFinal(data)
            }

        // Mutual authentication: decrypt the card's witness, then check the card encrypts our challenge
        val step1 = transmit(INS_AUTHENTICATE, algorithm, KEY_REF_MANAGEMENT, tlv(TAG_DYN_AUTH, tlv(TAG_WITNESS, ByteArray(0))))
        if (step1.sw != SW_OK) throw failure("management key authentication", step1.sw)
        val witness = dynamicAuthValue(step1.data, TAG_WITNESS)
        val challenge = ByteArray(witness.size).also { SecureRandom().nextBytes(it) }
        val step2 = transmit(
            INS_AUTHENTICATE, algorithm, KEY_REF_MANAGEMENT,
            tlv(TAG_DYN_AUTH, tlv(TAG_WITNESS, crypt(Cipher.DECRYPT_MODE, witness)) + tlv(TAG_CHALLENGE, challenge))
        )
        if (step2.sw == SW_SECURITY_STATUS || step2.sw == SW_INCORRECT_DATA) throw YubiKeyException("Wrong PIV management key")
        if (step2.sw != SW_OK) throw failure("management key authentication", step2.sw)
        val response = dynamicAuthValue(step2.data, TAG_RESPONSE)
        if (!MessageDigest.isEqual(response, crypt(Cipher.ENCRYPT_MODE, challenge))) {
            throw YubiKeyException("The YubiKey failed to prove it knows the management key")
        }
    }

    // Returns null when the slot holds no key
    fun getMetadata(keyRef: Int): PivMetadata? {
        val r = transmit(INS_GET_METADATA, 0x00, keyRef, null)
        if (r.sw == SW_REFERENCE_NOT_FOUND) return null
        if (r.sw != SW_OK) throw failure("reading key metadata", r.sw)
        val fields = Tlv.parse(r.data)
        val policy = fields[0x02]
        return PivMetadata(
            algorithm = fields[0x01]?.firstOrNull()?.u() ?: 0,
            pinPolicy = policy?.getOrNull(0)?.u(),
            touchPolicy = policy?.getOrNull(1)?.u(),
            origin = fields[0x03]?.firstOrNull()?.u(),
            isDefault = fields[0x05]?.firstOrNull()?.let { it.u() == 1 },
            publicKey = fields[0x04]?.let { Tlv.parse(it)[0x86] }
        )
    }

    // Requires management key authentication. Returns the raw 65 byte public key.
    fun generateEcP256(keyRef: Int, pinPolicy: Int, touchPolicy: Int): ByteArray {
        var template = tlv(0x80, byteArrayOf(ALG_ECCP256.toByte()))
        if (pinPolicy != 0) template += tlv(0xAA, byteArrayOf(pinPolicy.toByte()))
        if (touchPolicy != 0) template += tlv(0xAB, byteArrayOf(touchPolicy.toByte()))
        val r = transmit(INS_GENERATE, 0x00, keyRef, tlv(0xAC, template))
        when (r.sw) {
            SW_OK -> {}
            SW_SECURITY_STATUS -> throw SecurityStatusException("Management key authentication is required to generate a key")
            SW_INCORRECT_DATA, SW_INCORRECT_P1P2 -> throw YubiKeyException(
                if (pinPolicy != 0 || touchPolicy != 0) "This YubiKey does not support ECC P-256 keys with the requested PIN/touch policy"
                else "This YubiKey does not support ECC P-256 keys in PIV (YubiKey 4 or 5 is required)"
            )
            else -> throw failure("key generation", r.sw)
        }
        val publicKey = Tlv.parse(Tlv.parse(r.data)[0x7F49] ?: malformed())[0x86] ?: malformed()
        if (publicKey.size != 65 || publicKey[0] != 0x04.toByte()) malformed()
        return publicKey
    }

    // Signs a SHA-256 digest with the slot's P-256 key. Returns a DER-encoded ECDSA signature.
    fun signEcP256(keyRef: Int, digest: ByteArray): ByteArray =
        generalAuthenticate(keyRef, TAG_CHALLENGE, digest, "signing")

    // ECDH with the slot's P-256 key. Returns the shared secret (the X coordinate, 32 bytes).
    fun ecdhP256(keyRef: Int, peerPublicKey: ByteArray): ByteArray =
        generalAuthenticate(keyRef, TAG_EXPONENTIATION, peerPublicKey, "key agreement")

    private fun generalAuthenticate(keyRef: Int, tag: Int, value: ByteArray, operation: String): ByteArray {
        val r = transmit(
            INS_AUTHENTICATE, ALG_ECCP256, keyRef,
            tlv(TAG_DYN_AUTH, tlv(TAG_RESPONSE, ByteArray(0)) + tlv(tag, value))
        )
        when (r.sw) {
            SW_OK -> {}
            SW_SECURITY_STATUS -> throw SecurityStatusException("PIN verification is required for $operation")
            SW_INCORRECT_DATA, SW_INCORRECT_P1P2, SW_REFERENCE_NOT_FOUND ->
                throw YubiKeyException("The slot ${"%02X".format(keyRef)} does not hold an ECC P-256 key")
            else -> throw failure(operation, r.sw)
        }
        return dynamicAuthValue(r.data, TAG_RESPONSE)
    }

    fun hasCertificate(objectId: Int): Boolean = readObject(objectId)?.isNotEmpty() == true

    // The DER certificate in the slot's object; null when absent or not in the PIV certificate format
    fun getCertificate(objectId: Int): ByteArray? {
        val value = readObject(objectId) ?: return null
        return try {
            Tlv.parse(value)[0x70]
        } catch (e: YubiKeyException) {
            null
        }
    }

    // Requires management key authentication
    fun putCertificate(objectId: Int, certificate: ByteArray) {
        // 70: certificate, 71: not compressed, FE: error detection code (empty)
        val value = tlv(0x70, certificate) + tlv(0x71, byteArrayOf(0)) + tlv(0xFE, ByteArray(0))
        val r = transmit(INS_PUT_DATA, 0x3F, 0xFF, tlv(0x5C, objectIdBytes(objectId)) + tlv(0x53, value), expectResponse = false)
        if (r.sw != SW_OK) throw failure("writing the certificate", r.sw)
    }

    // The value of the data object (tag 53); null when the object does not exist
    private fun readObject(objectId: Int): ByteArray? {
        val r = transmit(INS_GET_DATA, 0x3F, 0xFF, tlv(0x5C, objectIdBytes(objectId)))
        return when (r.sw) {
            SW_OK -> if (r.data.isEmpty()) ByteArray(0) else Tlv.parse(r.data)[0x53] ?: malformed()
            SW_FILE_NOT_FOUND -> null
            else -> throw failure("reading the certificate", r.sw)
        }
    }

    // Requires management key authentication
    fun deleteCertificate(objectId: Int) {
        val r = transmit(INS_PUT_DATA, 0x3F, 0xFF, tlv(0x5C, objectIdBytes(objectId)) + tlv(0x53, ByteArray(0)), expectResponse = false)
        if (r.sw != SW_OK) throw failure("deleting the certificate", r.sw)
    }

    private fun transmit(ins: Int, p1: Int, p2: Int, data: ByteArray?, expectResponse: Boolean = true): Response {
        // Command chaining for data longer than a short APDU, e.g. certificates
        var offset = 0
        while (data != null && data.size - offset > 255) {
            val r = channel.transmit(CommandAPDU(0x10, ins, p1, p2, data.copyOfRange(offset, offset + 255)))
            if (r.sw != SW_OK) return Response(r.data, r.sw)
            offset += 255
        }
        val last = if (data == null || offset == 0) data else data.copyOfRange(offset, data.size)
        val apdu = when {
            last == null -> if (expectResponse) CommandAPDU(0x00, ins, p1, p2, 256) else CommandAPDU(0x00, ins, p1, p2)
            expectResponse -> CommandAPDU(0x00, ins, p1, p2, last, 256)
            else -> CommandAPDU(0x00, ins, p1, p2, last)
        }
        var response = channel.transmit(apdu)
        val out = ByteArrayOutputStream()
        out.write(response.data)
        // Response chaining: 61xx means more data is available
        while (response.sW1 == 0x61) {
            response = channel.transmit(CommandAPDU(0x00, INS_GET_RESPONSE, 0x00, 0x00, if (response.sW2 == 0) 256 else response.sW2))
            out.write(response.data)
        }
        return Response(out.toByteArray(), response.sw)
    }

    private fun dynamicAuthValue(data: ByteArray, tag: Int): ByteArray =
        Tlv.parse(Tlv.parse(data)[TAG_DYN_AUTH] ?: malformed())[tag] ?: malformed()

    private fun objectIdBytes(objectId: Int) =
        byteArrayOf((objectId shr 16).toByte(), (objectId shr 8).toByte(), objectId.toByte())

    private fun failure(operation: String, sw: Int) = YubiKeyException("YubiKey $operation failed (${sw(sw)})")

    private fun sw(sw: Int) = "SW=%04X".format(sw)
}

internal fun tlv(tag: Int, value: ByteArray) = Tlv.encode(tag, value)

internal fun malformed(): Nothing = throw YubiKeyException("Malformed response from the YubiKey")

internal fun Byte.u() = toInt() and 0xFF

// BER-TLV as used by PIV: 1 or 2 byte tags, definite lengths up to 0xFFFF
internal object Tlv {
    fun encode(tag: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        if (tag > 0xFF) out.write(tag shr 8)
        out.write(tag and 0xFF)
        when {
            value.size < 0x80 -> out.write(value.size)
            value.size <= 0xFF -> { out.write(0x81); out.write(value.size) }
            else -> { out.write(0x82); out.write(value.size shr 8); out.write(value.size and 0xFF) }
        }
        out.write(value)
        return out.toByteArray()
    }

    fun parse(data: ByteArray): Map<Int, ByteArray> {
        val result = LinkedHashMap<Int, ByteArray>()
        try {
            var i = 0
            while (i < data.size) {
                var tag = data[i++].u()
                if ((tag and 0x1F) == 0x1F) {
                    do {
                        val b = data[i++].u()
                        tag = (tag shl 8) or b
                    } while ((b and 0x80) != 0)
                }
                var length = data[i++].u()
                if (length > 0x80) {
                    val count = length and 0x7F
                    length = 0
                    repeat(count) { length = (length shl 8) or data[i++].u() }
                }
                if (i + length > data.size) malformed()
                result[tag] = data.copyOfRange(i, i + length)
                i += length
            }
        } catch (e: IndexOutOfBoundsException) {
            malformed()
        }
        return result
    }
}
