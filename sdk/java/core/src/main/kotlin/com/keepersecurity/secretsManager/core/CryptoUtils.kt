package com.keepersecurity.secretsManager.core

import java.math.BigInteger
import java.net.URL
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.security.*
import java.security.interfaces.ECPrivateKey
import java.security.spec.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

class GenericCryptoProvider(override val provider: Provider) : CryptoProvider {
    override fun multiplyG(s: BigInteger): ByteArray {
        throw NotImplementedError("Need to provide the implementation for public key export")
    }
}

internal object KeeperCryptoParameters {

    init {
        val providers = Security.getProviders()
        var provider = Security.getProvider("BCFIPS")
        if (provider == null) {
            provider = Security.getProvider("BC")
        }
        if (provider != null) {
            setProvider(GenericCryptoProvider(provider))
        }
    }

    fun setProvider(cryptoProvider: CryptoProvider) {
        provider = cryptoProvider.provider
        Security.addProvider(provider)
        keyFactory = KeyFactory.getInstance("EC", provider)
        val ecGenParameterSpec = ECGenParameterSpec("secp256r1")
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ecGenParameterSpec)
        ecParameterSpec = parameters.getParameterSpec(ECParameterSpec::class.java)
        keyGen = KeyPairGenerator.getInstance("EC", provider)
        keyGen.initialize(ecGenParameterSpec)
        multiplyG = cryptoProvider::multiplyG
    }

    internal lateinit var provider: Provider
    internal lateinit var keyFactory: KeyFactory
    internal lateinit var keyGen: KeyPairGenerator
    internal lateinit var ecParameterSpec: ECParameterSpec
    internal lateinit var multiplyG: (s: BigInteger) -> ByteArray
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

internal fun generateKeyPair(): ByteArray {
    val keyPair = KeeperCryptoParameters.keyGen.genKeyPair()
    return keyPair.private.encoded
}

internal fun exportPublicKey(privateKeyDer: ByteArray): ByteArray {
    val privateKey = importPrivateKey(privateKeyDer)
    return KeeperCryptoParameters.multiplyG(privateKey.s)
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

internal fun importPrivateKey(privateKeyDer: ByteArray): ECPrivateKey {
    val privateKeySpec =
        ECPrivateKeySpec(BigInteger(1, privateKeyDer.copyOfRange(36, 68)), KeeperCryptoParameters.ecParameterSpec)
    return KeeperCryptoParameters.keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey
}

internal fun importPublicKey(rawBytes: ByteArray): PublicKey {
    val pubKeySpec = ECPublicKeySpec(
        ECPoint(
            BigInteger(1, rawBytes, 1, 32),
            BigInteger(1, rawBytes, 33, 32)
        ),
        KeeperCryptoParameters.ecParameterSpec
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

internal fun extractPublicRaw(publicKey: PublicKey): ByteArray {
    fun adjustTo32Bytes(bytes: ByteArray) = when {
        bytes.size > 32 -> bytes.sliceArray(bytes.size - 32 until bytes.size)
        else -> bytes
    }

    val w = KeeperCryptoParameters.keyFactory.getKeySpec(publicKey, ECPublicKeySpec::class.java).w
    return byteArrayOf(4) + adjustTo32Bytes(w.affineX.toByteArray()) + adjustTo32Bytes(w.affineY.toByteArray())
}

internal fun publicEncrypt(data: ByteArray, key: ByteArray): ByteArray {
    val ephemeralKeyPair = KeeperCryptoParameters.keyGen.genKeyPair()
    val recipientPublicKey = importPublicKey(key)
    val symmetricKey = getEciesSymmetricKey(ephemeralKeyPair.private, recipientPublicKey)
    val encryptedData = encrypt(data, symmetricKey)
    return extractPublicRaw(ephemeralKeyPair.public) + encryptedData
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

// TOTP code generation
const val DEFAULT_TIME_STEP = 30
const val DEFAULT_DIGITS = 6
//const val DEFAULT_T0 = 0
// T0 is the Unix time to start counting time steps (default value is 0, i.e., the Unix epoch)

const val base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
internal val rxBase32Alphabet = Regex("^[A-Z2-7]+$")

private fun base32ToBytes(base32Text: String): ByteArray {
    var output: ByteArray = byteArrayOf()
    // The padding specified in RFC 3548 section 2.2 is not required and should be omitted.
    val base32: String = base32Text.trim().trimEnd('=')
    if (base32.isEmpty() || !rxBase32Alphabet.matches(base32))
        return output

    val bytes: CharArray = base32.toCharArray()
    for (bitIndex: Int in 0 until (base32.length * 5) step 8) {
        var dualByte: Int = base32Alphabet.indexOf(bytes[bitIndex / 5]) shl 10
        if (bitIndex / 5 + 1 < bytes.size)
            dualByte = dualByte.or(base32Alphabet.indexOf(bytes[bitIndex / 5 + 1]) shl 5)
        if (bitIndex / 5 + 2 < bytes.size)
            dualByte = dualByte.or(base32Alphabet.indexOf(bytes[bitIndex / 5 + 2]))
        dualByte = (dualByte shr (15 - bitIndex % 5 - 8)).and(0xff)
        output += dualByte.toByte()
    }
    return output
}

data class TotpCode(val code: String, val timeLeft: Int, val period: Int)

fun getTotpCode(url: String, unixTimeSeconds: Long = 0): TotpCode? {
    // java.net.MalformedURLException: unknown protocol: otpauth
    val protocol: String = if (url.startsWith("otpauth://", true)) "otpauth" else ""
    if (protocol != "otpauth")
        return null

    val totpUrl = URL("http://" + url.substring(10))
    val queryPairs = mutableMapOf<String, String>()
    val pairs: List<String> = totpUrl.query.split("&")
    for (pair in pairs) {
        val idx: Int = pair.indexOf("=")
        val key = URLDecoder.decode(pair.substring(0, idx), "UTF-8")
        val value = URLDecoder.decode(pair.substring(idx + 1), "UTF-8")
        if (!value.isNullOrBlank())
            queryPairs[key] = value
    }

    val secret: String = queryPairs.getOrDefault("secret", "").uppercase()
    val algorithm: String = queryPairs.getOrDefault("algorithm", "SHA1").uppercase()
    var digits = queryPairs.getOrDefault("digits", "").toIntOrNull() ?: DEFAULT_DIGITS
    var period = queryPairs.getOrDefault("period", "").toIntOrNull() ?: DEFAULT_TIME_STEP

    if (digits == 0) digits = DEFAULT_DIGITS
    if (period == 0) period = DEFAULT_TIME_STEP
    if (secret.isEmpty())
        return null

    val tmBase = if (unixTimeSeconds != 0L) unixTimeSeconds else System.currentTimeMillis() / 1000L
    val tm = tmBase / period
    val msg: ByteArray = ByteBuffer.allocate(8).putLong(tm).array()

    val secretBytes: ByteArray = base32ToBytes(secret)
    if (secretBytes.isEmpty())
        return null

    var hmac: Mac? = null
    when (algorithm) {
        // although once part of Google Key Uri Format - https://github.com/google/google-authenticator/wiki/Key-Uri-Format/_history
        // removed MD5 as unreliable - only digests of length >= 20 can be used (MD5 has a digest length of 16)
        //"MD5" -> hmac = Mac.getInstance("MD5")
        "SHA1" -> hmac = Mac.getInstance("HmacSHA1")
        "SHA256" -> hmac = Mac.getInstance("HmacSHA256")
        "SHA512" -> hmac = Mac.getInstance("HmacSHA512")
    }
    if (hmac == null)
        return null

    var digest: ByteArray = byteArrayOf()
    try {
        val spec = SecretKeySpec(secretBytes, "RAW")
        hmac.init(spec)
        digest = hmac.doFinal(msg)
    } catch (e: Exception) {
        e.printStackTrace()
    }

    val offset: Int = digest[digest.size - 1].toInt() and 0x0f
    val codeBytes: ByteArray = digest.copyOfRange(offset, offset + 4)
    codeBytes[0] = (codeBytes[0].toInt() and 0x7f).toByte()
    var codeInt: Int = ByteBuffer.wrap(codeBytes).int
    codeInt %= 10.0.pow(digits.toDouble()).toInt()
    val codeStr: String = codeInt.toString().padStart(digits, '0')
    val elapsed: Int = (tmBase % period).toInt() // time elapsed in current period in seconds
    val ttl: Int = period - elapsed // time to live in seconds

    return TotpCode(codeStr, ttl, period)
}

// password generation
const val AsciiLowercase = "abcdefghijklmnopqrstuvwxyz"
const val AsciiUppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const val AsciiDigits = "0123456789"
const val AsciiSpecialCharacters = "\"!@#$%()+;<>=?[]{}^.,"

internal fun randomSample(sampleLength: Int = 0, sampleString: String = ""): String {
    var result = ""
    val sampleLen = if (sampleLength < 0) 0 else sampleLength
    if (sampleLen > 0 && sampleString.isNotEmpty()) {
        val secureRandom = SecureRandom.getInstanceStrong()
        val bytes = CharArray(sampleLen)
        result = (bytes.indices)
            .map {
                sampleString[secureRandom.nextInt(sampleString.length)]
            }.joinToString("")

    }
    return result
}

@JvmOverloads
fun generatePassword(
    length: Int = 64,
    lowercase: Int = 0,
    uppercase: Int = 0,
    digits: Int = 0,
    specialCharacters: Int = 0
): String {
    val totalLength: Int = if (length <= 0) 64 else length
    var numLowercase: Int = lowercase
    var numUppercase: Int = uppercase
    var numDigits: Int = digits
    var numSpecialCharacters: Int = specialCharacters

    if (lowercase == 0 && uppercase == 0 && digits == 0 && specialCharacters == 0) {
        val increment: Int = totalLength / 4
        val lastIncrement: Int = increment + totalLength % 4
        numLowercase = increment
        numUppercase = increment
        numDigits = increment
        numSpecialCharacters = lastIncrement
    }
    var passwordCharacters = ""
    if (numLowercase > 0)
        passwordCharacters += randomSample(numLowercase, AsciiLowercase)
    if (numUppercase > 0)
        passwordCharacters += randomSample(numUppercase, AsciiUppercase)
    if (numDigits > 0)
        passwordCharacters += randomSample(numDigits, AsciiDigits)
    if (numSpecialCharacters > 0)
        passwordCharacters += randomSample(numSpecialCharacters, AsciiSpecialCharacters)

    val pCharArray = passwordCharacters.toCharArray()
    pCharArray.shuffle()
    return String(pCharArray)
}
