package com.keepersecurity.secretsManager.yubikey

import java.io.ByteArrayInputStream
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone
import javax.naming.ldap.LdapName

// Self-signed X.509 certificates that name a PIV slot's key. Tools such as ykman, Yubico Authenticator
// and the macOS Keychain show the certificate subject as the key's name.
internal object Certificates {

    private val OID_EC_PUBLIC_KEY = hex("06072A8648CE3D0201")
    private val OID_P256 = hex("06082A8648CE3D030107")
    private val OID_ECDSA_SHA256 = hex("06082A8648CE3D040302")
    private val OID_COMMON_NAME = hex("0603550403")
    private val OID_KEY_USAGE = hex("0603551D0F")

    // KeyUsage bit strings: digitalSignature (bit 0) and keyAgreement (bit 4)
    private val DIGITAL_SIGNATURE = hex("0780")
    private val KEY_AGREEMENT = hex("0308")

    /** [sign] signs the TBSCertificate with the key itself and returns a DER ECDSA signature */
    fun selfSigned(publicKey: ByteArray, commonName: String, keyAgreement: Boolean, sign: (ByteArray) -> ByteArray): ByteArray {
        val name = seq(tlv(0x31, seq(OID_COMMON_NAME, tlv(0x0C, commonName.toByteArray(Charsets.UTF_8)))))
        val serial = ByteArray(16).also { SecureRandom().nextBytes(it) }
        serial[0] = ((serial[0].toInt() and 0x3F) or 0x40).toByte()  // positive, minimal encoding
        val tbs = seq(
            tlv(0xA0, tlv(0x02, byteArrayOf(2))),  // v3
            tlv(0x02, serial),
            seq(OID_ECDSA_SHA256),
            name,
            // 99991231235959Z: no well-defined expiration (RFC 5280)
            seq(tlv(0x17, utcTime(Date(System.currentTimeMillis() - 60_000))), tlv(0x18, "99991231235959Z".toByteArray())),
            name,
            seq(seq(OID_EC_PUBLIC_KEY, OID_P256), tlv(0x03, byteArrayOf(0) + publicKey)),
            tlv(0xA3, seq(seq(
                OID_KEY_USAGE,
                tlv(0x01, byteArrayOf(0xFF.toByte())),  // critical
                tlv(0x04, tlv(0x03, if (keyAgreement) KEY_AGREEMENT else DIGITAL_SIGNATURE))
            )))
        )
        return seq(tbs, seq(OID_ECDSA_SHA256), tlv(0x03, byteArrayOf(0) + sign(tbs)))
    }

    /** The subject common name, or null if the data is not an X.509 certificate */
    fun commonName(certificate: ByteArray): String? = try {
        val x509 = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(certificate)) as X509Certificate
        LdapName(x509.subjectX500Principal.name).rdns.firstOrNull { it.type.equals("CN", ignoreCase = true) }?.value?.toString()
    } catch (e: Exception) {
        null
    }

    private fun seq(vararg parts: ByteArray) = tlv(0x30, parts.fold(ByteArray(0)) { acc, p -> acc + p })

    private fun utcTime(date: Date): ByteArray =
        SimpleDateFormat("yyMMddHHmmss'Z'").apply { timeZone = TimeZone.getTimeZone("UTC") }.format(date).toByteArray()

    private fun hex(value: String) = ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
