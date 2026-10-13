package com.keepersecurity.secretsManager.yubikey

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// ECIES wrapping of the app key to a P-256 key on the YubiKey:
// version(1) || wrapping public key(65) || ephemeral public key(65) || iv(12) || AES-256-GCM(app key) || tag(16)
// The AES key is SHA-256 of the ECDH shared secret, as in the core SDK. The wrapping public key
// identifies the slot to unwrap with, and both public keys are authenticated as AAD.
internal object AppKeyWrap {
    private const val VERSION = 1
    private const val HEADER = 1 + 65 + 65 + 12

    class Wrapped(val wrappingPublicKey: ByteArray, val ephemeralPublicKey: ByteArray, val iv: ByteArray, val ciphertext: ByteArray)

    fun wrap(wrappingPublicKey: ByteArray, appKey: ByteArray): ByteArray {
        val ephemeral = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        val sharedSecret = KeyAgreement.getInstance("ECDH").run {
            init(ephemeral.private)
            doPhase(p256PublicKey(wrappingPublicKey), true)
            generateSecret()
        }
        val ephemeralPublicKey = rawPublicKey(ephemeral.public as ECPublicKey)
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val ciphertext = cipher(Cipher.ENCRYPT_MODE, sharedSecret, iv, wrappingPublicKey + ephemeralPublicKey).doFinal(appKey)
        return byteArrayOf(VERSION.toByte()) + wrappingPublicKey + ephemeralPublicKey + iv + ciphertext
    }

    fun parse(data: ByteArray): Wrapped {
        if (data.size < HEADER + 16 || data[0].toInt() != VERSION) throw YubiKeyException("The wrapped app key is not in a supported format")
        return Wrapped(data.copyOfRange(1, 66), data.copyOfRange(66, 131), data.copyOfRange(131, HEADER), data.copyOfRange(HEADER, data.size))
    }

    fun unwrap(wrapped: Wrapped, sharedSecret: ByteArray): ByteArray = try {
        cipher(Cipher.DECRYPT_MODE, sharedSecret, wrapped.iv, wrapped.wrappingPublicKey + wrapped.ephemeralPublicKey)
            .doFinal(wrapped.ciphertext)
    } catch (e: Exception) {
        throw YubiKeyException("Cannot unwrap the app key: ${e.message}", e)
    }

    private fun cipher(mode: Int, sharedSecret: ByteArray, iv: ByteArray, aad: ByteArray): Cipher {
        val key = MessageDigest.getInstance("SHA-256").digest(sharedSecret)
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            updateAAD(aad)
        }
    }

    private val p256: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
    }

    fun p256PublicKey(raw: ByteArray): PublicKey {
        if (raw.size != 65 || raw[0] != 0x04.toByte()) throw YubiKeyException("Not an uncompressed P-256 public key")
        val point = ECPoint(BigInteger(1, raw.copyOfRange(1, 33)), BigInteger(1, raw.copyOfRange(33, 65)))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, p256))
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
