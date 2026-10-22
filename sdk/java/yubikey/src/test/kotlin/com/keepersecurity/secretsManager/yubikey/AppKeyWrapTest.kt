package com.keepersecurity.secretsManager.yubikey

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import kotlin.test.*

internal class AppKeyWrapTest {

    // Every SDK port must produce exactly these bytes for these inputs
    private val knownAnswer =
        "0201040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c6530" +
        "6e579404d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533f" +
        "ce9c912850102030405060708090a0b0ca2df340b1ca19012ceeba2a5ce0ec70daf007cfadd334a01212a8ce2db295294f7f625219921c5859470556be5e00245"

    private val appKey = ByteArray(32) { it.toByte() }
    private val iv = ByteArray(12) { (it + 1).toByte() }

    private fun fixedKeyPair(scalarByte: Int): KeyPair {
        val params = p256Params()
        val scalar = BigInteger(1, ByteArray(32) { scalarByte.toByte() })
        val kf = KeyFactory.getInstance("EC")
        return KeyPair(kf.generatePublic(ECPublicKeySpec(multiplyGenerator(scalar, params), params)), kf.generatePrivate(ECPrivateKeySpec(scalar, params)))
    }

    private fun ecdh(card: KeyPair, ephemeralPublicKey: ByteArray): ByteArray =
        KeyAgreement.getInstance("ECDH").run { init(card.private); doPhase(AppKeyWrap.p256PublicKey(ephemeralPublicKey), true); generateSecret() }

    private fun wrapKnownInputs(): Pair<KeyPair, ByteArray> {
        val card = fixedKeyPair(0x11)
        return card to AppKeyWrap.wrapWith(fixedKeyPair(0x22), iv, AppKeyWrap.rawPublicKey(card.public as ECPublicKey), appKey)
    }

    @Test
    fun matchesTheKnownAnswerVectorAndUnwraps() {
        val (card, blob) = wrapKnownInputs()
        assertEquals(knownAnswer, blob.joinToString("") { "%02x".format(it) })
        val wrapped = AppKeyWrap.parse(blob)
        assertContentEquals(appKey, AppKeyWrap.unwrap(wrapped, ecdh(card, wrapped.ephemeralPublicKey)))
    }

    @Test
    fun givesTheSameBytesUnderTheFipsProvider() {
        val provider = org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider()
        Security.addProvider(provider)
        try {
            val (_, blob) = wrapKnownInputs()
            assertEquals(knownAnswer, blob.joinToString("") { "%02x".format(it) })
        } finally {
            Security.removeProvider(provider.name)
        }
    }

    @Test
    fun anyAlteredByteIsRejected() {
        val (card, blob) = wrapKnownInputs()
        for (position in blob.indices) {
            val altered = blob.copyOf().also { it[position] = (it[position].toInt() xor 1).toByte() }
            assertFailsWith<YubiKeyException>("byte $position") {
                val wrapped = AppKeyWrap.parse(altered)
                AppKeyWrap.unwrap(wrapped, ecdh(card, wrapped.ephemeralPublicKey))
            }
        }
    }

    @Test
    fun pointsOffTheCurveAreRejected() {
        val (card, blob) = wrapKnownInputs()
        val offCurve = AppKeyWrap.rawPublicKey(card.public as ECPublicKey).also { it[64] = (it[64].toInt() xor 1).toByte() }
        assertFailsWith<YubiKeyException> { AppKeyWrap.wrap(offCurve, appKey) }
        assertFailsWith<YubiKeyException> { AppKeyWrap.parse(blob.copyOf().also { it[100] = (it[100].toInt() xor 1).toByte() }) }
    }
}

private fun p256Params(): ECParameterSpec =
    (KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public as ECPublicKey).params

// Affine P-256 scalar multiplication, only to derive a public key from a fixed private scalar for the vector
private fun multiplyGenerator(scalar: BigInteger, params: ECParameterSpec): ECPoint {
    val p = (params.curve.field as ECFieldFp).p
    fun add(p1: ECPoint, p2: ECPoint): ECPoint {
        if (p1 == ECPoint.POINT_INFINITY) return p2
        if (p2 == ECPoint.POINT_INFINITY) return p1
        val lambda = if (p1 == p2) {
            p1.affineX.pow(2).multiply(BigInteger.valueOf(3)).add(params.curve.a).multiply(p1.affineY.multiply(BigInteger.valueOf(2)).modInverse(p)).mod(p)
        } else {
            if (p1.affineX == p2.affineX) return ECPoint.POINT_INFINITY
            p2.affineY.subtract(p1.affineY).multiply(p2.affineX.subtract(p1.affineX).modInverse(p)).mod(p)
        }
        val x = lambda.pow(2).subtract(p1.affineX).subtract(p2.affineX).mod(p)
        return ECPoint(x, lambda.multiply(p1.affineX.subtract(x)).subtract(p1.affineY).mod(p))
    }
    var result = ECPoint.POINT_INFINITY
    var addend = params.generator
    var k = scalar
    while (k.signum() > 0) {
        if (k.testBit(0)) result = add(result, addend)
        addend = add(addend, addend)
        k = k.shiftRight(1)
    }
    return result
}
