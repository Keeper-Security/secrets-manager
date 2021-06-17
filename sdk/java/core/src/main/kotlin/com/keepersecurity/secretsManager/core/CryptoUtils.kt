package com.keepersecurity.secretsManager.core

import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import java.math.BigInteger
import java.security.*
import java.security.spec.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object KeeperCryptoParameters {
    internal val provider: BouncyCastleFipsProvider = BouncyCastleFipsProvider()
    internal val keyFactory: KeyFactory
    internal val ecParameterSpec: ECParameterSpec

    init {
        Security.addProvider(provider)
        keyFactory = KeyFactory.getInstance("EC", provider)
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        ecParameterSpec = parameters.getParameterSpec(ECParameterSpec::class.java)
    }
}

internal fun bytesToBase64(data: ByteArray): String {
    return Base64.getEncoder().encodeToString(data)
}

internal fun base64ToBytes(data: String): ByteArray {
    return Base64.getDecoder().decode(data)
}

internal fun webSafe64ToBytes(data: String): ByteArray {
    return Base64.getUrlDecoder().decode(data)
}

internal fun webSafe64FromBytes(data: ByteArray): String {
    return Base64.getUrlEncoder().encodeToString(data)
}

internal fun bytesToString(data: ByteArray): String {
    return String(data)
}

internal fun stringToBytes(data: String): ByteArray {
    return data.encodeToByteArray()
}

internal fun getRandomBytes(length: Int): ByteArray {
    val secureRandom = SecureRandom.getInstanceStrong()
    val bytes = ByteArray(length)
    secureRandom.nextBytes(bytes)
    return bytes
}

internal fun generateKeyPair(): Pair<ByteArray, ByteArray> {
    val keyGen = KeyPairGenerator.getInstance("EC", KeeperCryptoParameters.provider)
    keyGen.initialize(ECGenParameterSpec("secp256r1"))
    val keyPair = keyGen.genKeyPair()
    val publicRaw = with(keyPair.public.encoded) { copyOfRange(26, size) }
    val privateRaw = keyPair.private.encoded.copyOfRange(36, 68)
    return Pair(publicRaw, privateRaw)
}

internal fun hash(data: ByteArray, tag: String): ByteArray {
    val mac = Mac.getInstance("HmacSHA512", KeeperCryptoParameters.provider)
    mac.init(SecretKeySpec(data, "HmacSHA512"))
    return mac.doFinal(stringToBytes(tag))
}

internal fun getCipher(mode: Int, iv: ByteArray, key: ByteArray): Cipher {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding", KeeperCryptoParameters.provider)
    val keySpec = SecretKeySpec(key, "AES")
    val gcmParameterSpec = GCMParameterSpec(16 * 8, iv)
    cipher.init(mode, keySpec, gcmParameterSpec)
    return cipher
}

internal fun encrypt(data: ByteArray, key: ByteArray): ByteArray {
    val iv = getRandomBytes(12)
    val cipher = getCipher(Cipher.ENCRYPT_MODE, iv, key)
    val encryptedData = cipher.doFinal(data)
    return iv + encryptedData
}

internal fun decrypt(data: ByteArray, key: ByteArray): ByteArray {
    val iv = data.copyOfRange(0, 12)
    val cipher = getCipher(Cipher.DECRYPT_MODE, iv, key)
    return cipher.doFinal(data, iv.size, data.size - iv.size)
}

internal fun decrypt(data: String, key: ByteArray): ByteArray {
    return decrypt(base64ToBytes(data), key)
}

internal fun importPrivateKey(rawBytes: ByteArray): PrivateKey {
    val privateKeySpec = ECPrivateKeySpec(BigInteger(1, rawBytes), KeeperCryptoParameters.ecParameterSpec)
    return KeeperCryptoParameters.keyFactory.generatePrivate(privateKeySpec)
}

internal fun importPublicKey(rawBytes: ByteArray): PublicKey {
    val x = rawBytes.copyOfRange(1, 33)
    val y = rawBytes.copyOfRange(33, 65)
    val w = ECNamedCurveTable
        .getByName("secp256r1")
        .curve
        .createPoint(BigInteger(1, x), BigInteger(1, y))
    val pubKeySpec = ECPublicKeySpec(
        ECPoint(w.xCoord.toBigInteger(), w.yCoord.toBigInteger()), KeeperCryptoParameters.ecParameterSpec
    )
    return KeeperCryptoParameters.keyFactory.generatePublic(pubKeySpec)
}

internal fun getEciesSymmetricKey(privateKey: Key, publicKey: Key): ByteArray {
    val ka = KeyAgreement.getInstance("ECDH", KeeperCryptoParameters.provider)
    ka.init(privateKey)
    ka.doPhase(publicKey, true)
    val commonSecret = ka.generateSecret()
    return MessageDigest.getInstance("SHA-256", KeeperCryptoParameters.provider).digest(commonSecret)
}

internal fun publicEncrypt(data: ByteArray, key: ByteArray): ByteArray {
    val keyGen = KeyPairGenerator.getInstance("EC", KeeperCryptoParameters.provider)
    keyGen.initialize(ECGenParameterSpec("secp256r1"))
    val ephemeralKeyPair = keyGen.genKeyPair()
    val recipientPublicKey = importPublicKey(key)
    val symmetricKey = getEciesSymmetricKey(ephemeralKeyPair.private, recipientPublicKey)
    val encryptedData = encrypt(data, symmetricKey)
    with(ephemeralKeyPair.public.encoded) {
        val ephemeralPublicRaw = copyOfRange(26, size)
        return ephemeralPublicRaw + encryptedData
    }
}

internal fun privateDecrypt(data: ByteArray, key: ByteArray): ByteArray {
    val privateKey = importPrivateKey(key)
    val publicKey = importPublicKey(data.copyOfRange(0, 65))
    val symmetricKey = getEciesSymmetricKey(privateKey, publicKey)
    return decrypt(data.copyOfRange(65, data.size), symmetricKey)
}

internal fun sign(data: ByteArray, key: ByteArray): ByteArray {
    val privateKey = importPrivateKey(key)
    val sig = Signature.getInstance("SHA256withECDSA", KeeperCryptoParameters.provider)
    sig.initSign(privateKey)
    sig.update(data)
    return sig.sign()
}