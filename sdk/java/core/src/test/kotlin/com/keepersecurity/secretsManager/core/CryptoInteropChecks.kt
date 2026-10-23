package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread

// The SDK's ECIES, AES-GCM and ECDSA code written again here with the plain JCA. A round trip from the SDK to the
// SDK passes even if the SDK derives the wrong key, so these checks compare the SDK with an implementation of
// the documented format that does not share its code or its provider. The providers the SDK may capture (BC,
// BCFIPS) are added at the end of the JCA provider list, so these calls use the JDK's own.
internal object IndependentCrypto {
    private val curve: ECParameterSpec = AlgorithmParameters.getInstance("EC")
        .apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun generateKeyPair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun fixed32(value: BigInteger): ByteArray {
        val bytes = value.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return ByteArray(32 - bytes.size) + bytes
    }

    fun rawPublic(key: PublicKey): ByteArray {
        val point = (key as ECPublicKey).w
        return byteArrayOf(4) + fixed32(point.affineX) + fixed32(point.affineY)
    }

    fun publicKey(raw: ByteArray): PublicKey {
        val point = ECPoint(BigInteger(1, raw.copyOfRange(1, 33)), BigInteger(1, raw.copyOfRange(33, 65)))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, curve))
    }

    fun gcmEncrypt(key: ByteArray, data: ByteArray): ByteArray {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return iv + cipher.doFinal(data)
    }

    fun gcmDecrypt(key: ByteArray, blob: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
        return cipher.doFinal(blob, 12, blob.size - 12)
    }

    private fun agreedKey(own: PrivateKey, peer: PublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(own)
        agreement.doPhase(peer, true)
        return sha256(agreement.generateSecret())
    }

    // Wire format: ephemeral public key (65 bytes), then AES-GCM(iv 12 bytes || ciphertext || tag) under SHA-256(ECDH secret).
    fun eciesEncrypt(data: ByteArray, recipientRaw: ByteArray): ByteArray {
        val ephemeral = generateKeyPair()
        return rawPublic(ephemeral.public) + gcmEncrypt(agreedKey(ephemeral.private, publicKey(recipientRaw)), data)
    }

    fun eciesDecrypt(blob: ByteArray, own: PrivateKey): ByteArray =
        gcmDecrypt(agreedKey(own, publicKey(blob.copyOfRange(0, 65))), blob.copyOfRange(65, blob.size))

    fun verify(publicRaw: ByteArray, data: ByteArray, signature: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run { initVerify(publicKey(publicRaw)); update(data); verify(signature) }
}

@ExperimentalSerializationApi
internal object CryptoInteropChecks {

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    // NIST FIPS 180-4 example messages.
    private val sha256Vectors = listOf(
        "" to "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "abc" to "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" to "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    )

    // Runs under whichever provider the SDK captured. Returns the problems found, empty when everything agrees.
    fun run(): List<String> {
        val problems = ArrayList<String>()
        for ((message, expected) in sha256Vectors) {
            val actual = hex(KeeperCryptoParameters.sha256.digest(message.toByteArray(Charsets.US_ASCII)))
            if (actual != expected) problems.add("SHA-256 of \"${message.take(12)}\" was $actual")
        }
        val recipient = IndependentCrypto.generateKeyPair()
        val recipientRaw = IndependentCrypto.rawPublic(recipient.public)
        val secret = getRandomBytes(32)
        if (!runCatching { IndependentCrypto.eciesDecrypt(publicEncrypt(secret, recipientRaw), recipient.private) }.getOrNull().contentEquals(secret)) {
            problems.add("an independent ECIES implementation cannot read publicEncrypt output")
        }
        if (!runCatching { privateDecrypt(IndependentCrypto.eciesEncrypt(secret, recipientRaw), recipient.private.encoded) }.getOrNull().contentEquals(secret)) {
            problems.add("privateDecrypt cannot read independent ECIES output")
        }
        val data = getRandomBytes(64)
        if (!runCatching { IndependentCrypto.verify(recipientRaw, data, sign(data, recipient.private.encoded)) }.getOrDefault(false)) {
            problems.add("the JCA rejects a signature made by sign()")
        }
        return problems
    }

    // Eight threads call getSecrets on one bound client against a fake server that has its own key pair and uses only
    // the independent implementation. The server sees what Keeper would see (the encrypted transmission key, the
    // payload and the signature), never the SDK's transmission key. A shared digest or key object shows up here as a
    // transmission key the server cannot open or a response the SDK cannot open. Run it in a fresh JVM: the stub for
    // the transmission key is a global that other tests set.
    fun concurrentBoundGetSecrets(threads: Int = 8, callsPerThread: Int = 200): List<String> {
        val server = IndependentCrypto.generateKeyPair()
        val storage = InMemoryStorage()
        initializeStorage(storage, "YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c", "fake.keepersecurity.com")
        storage.saveBytes(KEY_APP_KEY, ByteArray(32))
        storage.saveString(KEY_SERVER_PUBLIC_KEY, webSafe64FromBytes(IndependentCrypto.rawPublic(server.public)))
        val clientPublic = storage.getBytes(KEY_PUBLIC_KEY)!!
        val problems = ConcurrentLinkedQueue<String>()
        val body = """{"records":[],"folders":[],"encryptedAppKey":null}""".toByteArray()
        val mock: QueryFunction = { _, tk, payload ->
            try {
                val key = IndependentCrypto.eciesDecrypt(tk.encryptedKey, server.private)
                if (!IndependentCrypto.verify(clientPublic, tk.encryptedKey + payload.payload, payload.signature)) problems.add("server: signature rejected")
                IndependentCrypto.gcmDecrypt(key, payload.payload)
                KeeperHttpResponse(200, IndependentCrypto.gcmEncrypt(key, body))
            } catch (e: Exception) {
                problems.add("server: ${e.javaClass.simpleName}")
                KeeperHttpResponse(500, ByteArray(0))
            }
        }
        val options = SecretsManagerOptions(storage, mock, loggingEnabled = false)
        // A barrier before every round puts all threads in getSecrets at the same moment, which is what makes a shared object fail.
        val barrier = CyclicBarrier(threads)
        val workers = List(threads) {
            thread {
                repeat(callsPerThread) {
                    try {
                        barrier.await(30, TimeUnit.SECONDS)
                        getSecrets(options)
                    } catch (e: Exception) {
                        problems.add("client: ${e.javaClass.simpleName}")
                    }
                }
            }
        }
        workers.forEach { it.join() }
        return problems.groupingBy { it }.eachCount().map { "${it.value}x ${it.key}" }
    }
}
