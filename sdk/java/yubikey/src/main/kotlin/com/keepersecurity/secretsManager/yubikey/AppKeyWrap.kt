package com.keepersecurity.secretsManager.yubikey

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Provider
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// ECIES wrapping of the app key to a P-256 key on the YubiKey. Format version 2:
//   version(1) || curve(1) || wrapping public key(65) || ephemeral public key(65) || iv(12) || AES-256-GCM(app key) || tag(16)
// The AES key comes from the one-step KDF of NIST SP 800-56C: SHA-256(00000001 || ECDH secret || label || context).
// The context is everything before the iv. It is also the GCM additional data, so the version, the curve and both
// public keys are bound to the key and to the tag. The wrapping public key identifies the slot that unwraps.
// Do not change a byte of this without a new version number: every SDK port must produce identical bytes,
// and AppKeyWrapTest holds the known-answer vector they all check against.
internal object AppKeyWrap {
    private const val VERSION = 2
    private const val CURVE_P256 = 1
    private const val CONTEXT_SIZE = 2 + 65 + 65
    private const val HEADER_SIZE = CONTEXT_SIZE + 12
    private const val TAG_SIZE = 16
    private val KDF_COUNTER = byteArrayOf(0, 0, 0, 1)
    private val KDF_LABEL = "KSM app key wrap".toByteArray(Charsets.US_ASCII)

    class Wrapped(val wrappingPublicKey: ByteArray, val ephemeralPublicKey: ByteArray, val iv: ByteArray, val ciphertext: ByteArray) {
        val context: ByteArray
            get() = byteArrayOf(VERSION.toByte(), CURVE_P256.toByte()) + wrappingPublicKey + ephemeralPublicKey
    }

    fun wrap(wrappingPublicKey: ByteArray, appKey: ByteArray): ByteArray {
        val ephemeral = (provider()?.let { KeyPairGenerator.getInstance("EC", it) } ?: KeyPairGenerator.getInstance("EC")).run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        return wrapWith(ephemeral, ByteArray(12).also { SecureRandom().nextBytes(it) }, wrappingPublicKey, appKey)
    }

    // Separate from wrap so a test can fix the ephemeral key and the iv
    internal fun wrapWith(ephemeral: KeyPair, iv: ByteArray, wrappingPublicKey: ByteArray, appKey: ByteArray): ByteArray {
        requireOnCurve(wrappingPublicKey)
        val sharedSecret = ecdh(ephemeral.private, wrappingPublicKey)
        try {
            val wrapped = Wrapped(wrappingPublicKey, rawPublicKey(ephemeral.public as ECPublicKey), iv, ByteArray(0))
            val ciphertext = cipher(Cipher.ENCRYPT_MODE, sharedSecret, iv, wrapped.context).doFinal(appKey)
            return wrapped.context + iv + ciphertext
        } finally {
            sharedSecret.fill(0)
        }
    }

    // Checks the format and that both public keys are points on the curve, before the YubiKey is asked to use them
    fun parse(data: ByteArray): Wrapped {
        if (data.isEmpty() || data[0].toInt() != VERSION) {
            throw YubiKeyException("The wrapped app key uses format version ${data.firstOrNull()?.toInt()}, but this version of the YubiKey module reads version $VERSION")
        }
        if (data.size < HEADER_SIZE + TAG_SIZE || data[1].toInt() != CURVE_P256) {
            throw YubiKeyException("The wrapped app key is not in a supported format")
        }
        val wrapped = Wrapped(data.copyOfRange(2, 67), data.copyOfRange(67, 132), data.copyOfRange(132, HEADER_SIZE), data.copyOfRange(HEADER_SIZE, data.size))
        requireOnCurve(wrapped.wrappingPublicKey)
        requireOnCurve(wrapped.ephemeralPublicKey)
        return wrapped
    }

    fun unwrap(wrapped: Wrapped, sharedSecret: ByteArray): ByteArray = try {
        cipher(Cipher.DECRYPT_MODE, sharedSecret, wrapped.iv, wrapped.context).doFinal(wrapped.ciphertext)
    } catch (e: Exception) {
        throw YubiKeyException("The wrapped app key failed its integrity check. The config may have been altered or damaged.", e)
    }

    private fun cipher(mode: Int, sharedSecret: ByteArray, iv: ByteArray, context: ByteArray): Cipher {
        val key = kdf(sharedSecret, context)
        try {
            val transformation = "AES/GCM/NoPadding"
            return (provider()?.let { Cipher.getInstance(transformation, it) } ?: Cipher.getInstance(transformation)).apply {
                init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
                updateAAD(context)
            }
        } finally {
            key.fill(0)
        }
    }

    private fun kdf(sharedSecret: ByteArray, context: ByteArray): ByteArray =
        (provider()?.let { MessageDigest.getInstance("SHA-256", it) } ?: MessageDigest.getInstance("SHA-256"))
            .digest(KDF_COUNTER + sharedSecret + KDF_LABEL + context)

    private fun ecdh(privateKey: PrivateKey, peerPublicKey: ByteArray): ByteArray =
        (provider()?.let { KeyAgreement.getInstance("ECDH", it) } ?: KeyAgreement.getInstance("ECDH")).run {
            init(privateKey)
            doPhase(p256PublicKey(peerPublicKey), true)
            generateSecret()
        }

    // Same provider choice as the core SDK: the FIPS provider when the application registered one
    private fun provider(): Provider? = Security.getProvider("BCFIPS") ?: Security.getProvider("BC")

    private val p256: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
    }

    // The JDK key factory accepts points that are not on the curve, so check y^2 = x^3 + ax + b (mod p) here
    private fun requireOnCurve(raw: ByteArray) {
        if (raw.size != 65 || raw[0] != 0x04.toByte()) throw YubiKeyException("Not an uncompressed P-256 public key")
        val p = (p256.curve.field as ECFieldFp).p
        val x = BigInteger(1, raw.copyOfRange(1, 33))
        val y = BigInteger(1, raw.copyOfRange(33, 65))
        val onCurve = x < p && y < p && y.pow(2).mod(p) == x.pow(3).add(p256.curve.a.multiply(x)).add(p256.curve.b).mod(p)
        if (!onCurve) throw YubiKeyException("The public key is not a point on the P-256 curve")
    }

    fun p256PublicKey(raw: ByteArray): PublicKey {
        requireOnCurve(raw)
        val point = ECPoint(BigInteger(1, raw.copyOfRange(1, 33)), BigInteger(1, raw.copyOfRange(33, 65)))
        val keyFactory = provider()?.let { KeyFactory.getInstance("EC", it) } ?: KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(ECPublicKeySpec(point, p256))
    }

    fun rawPublicKey(key: ECPublicKey): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x04)
        out.write(fixed32(key.w.affineX))
        out.write(fixed32(key.w.affineY))
        return out.toByteArray()
    }

    private fun fixed32(value: BigInteger): ByteArray {
        val bytes = value.toByteArray().takeLast(32).toByteArray()
        return ByteArray(32 - bytes.size) + bytes
    }
}
