package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.math.BigInteger
import java.net.InetAddress
import java.net.ServerSocket
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import kotlin.test.*

// Retry behaviour of the shared request loop for the calls a real application makes after a throttle: a key
// rotation in between, a write, an attachment registration, a response that fails authentication, and an
// interruption. Requests are checked with the JCA directly (signature, transmission key selection, decrypted
// payload), so the checks do not depend on the SDK helpers that produced them.
@ExperimentalSerializationApi
internal class ThrottleRetryTest {

    private val throttled = """{"error":"throttled","message":"throttled"}""".toByteArray()
    private val keyRotation = """{"error":"key","key_id":10}""".toByteArray()
    private val emptySecrets = """{"records":[],"folders":[],"encryptedAppKey":null}"""
    private val transmissionKey = ByteArray(32) { (it + 1).toByte() }
    private var previousKeyStub: (() -> ByteArray)? = null

    @BeforeTest
    fun setUp() {
        previousKeyStub = if (TestStubs.transmissionKeyStubReady()) TestStubs.transmissionKeyStub else null
        TestStubs.transmissionKeyStub = { transmissionKey }
    }

    @AfterTest
    fun tearDown() {
        // A lateinit cannot be unset, so with no previous stub the deterministic one stays.
        previousKeyStub?.let { TestStubs.transmissionKeyStub = it }
    }

    private class Attempt(val publicKeyId: Int, val signatureValid: Boolean, val payloadJson: String, val envelope: ByteArray, val url: String)

    // Records what the server would see, verified without the SDK's own crypto helpers.
    private class Recorder(private val clientPublicKey: ByteArray, private val key: ByteArray) {
        val attempts = ArrayList<Attempt>()
        fun record(url: String, tk: TransmissionKey, payload: EncryptedPayload): Attempt {
            val valid = Signature.getInstance("SHA256withECDSA").run {
                initVerify(ecPublicKey(clientPublicKey))
                update(tk.encryptedKey + payload.payload)
                verify(payload.signature)
            }
            return Attempt(tk.publicKeyId, valid, bytesToString(decrypt(payload.payload, key)), tk.encryptedKey.copyOf(), url)
                .also { attempts.add(it) }
        }
    }

    private fun boundStorage(): InMemoryStorage {
        val storage = InMemoryStorage()
        initializeStorage(storage, "YyIhK5wXFHj36wGBAOmBsxI3v5rIruINrC8KXjyM58c", "fake.keepersecurity.com")
        storage.saveBytes(KEY_APP_KEY, ByteArray(32))
        storage.saveBytes(KEY_OWNER_PUBLIC_KEY, extractPublicRaw(generateKeyPair().public))
        return storage
    }

    private fun ok(body: String, tk: TransmissionKey) = KeeperHttpResponse(200, encrypt(stringToBytes(body), tk.key))

    private fun record() = KeeperRecord(
        getRandomBytes(32), "RECORD-UID-0123456789",
        data = KeeperRecordData("Title", "login", mutableListOf(Login(value = mutableListOf("user"))), mutableListOf()),
        revision = 5
    )

    @Test
    fun throttleThenKeyRotationThenAcceptedKeepsTheRequestAndSwitchesTheKey() {
        val storage = boundStorage()
        val recorder = Recorder(storage.getBytes(KEY_PUBLIC_KEY)!!, transmissionKey)
        var calls = 0
        val sleeps = ArrayList<Long>()
        val mock: QueryFunction = { url, tk, payload ->
            check(++calls <= 20) { "retry loop did not stop" }
            recorder.record(url, tk, payload)
            when (calls) {
                1 -> KeeperHttpResponse(429, throttled)
                2 -> KeeperHttpResponse(400, keyRotation)
                else -> ok(emptySecrets, tk)
            }
        }

        getSecrets(SecretsManagerOptions(storage, mock, throttleSleepMillis = { sleeps.add(it) }))

        val attempts = recorder.attempts
        assertEquals(3, attempts.size)
        assertTrue(attempts.all { it.signatureValid }, "every attempt needs its own valid signature: ${attempts.map { it.signatureValid }}")
        assertEquals(listOf(7, 7, 10), attempts.map { it.publicKeyId }, "the throttle keeps the key, the rotation switches to key 10")
        assertEquals(1, attempts.map { it.payloadJson }.toSet().size, "the logical request must not change between attempts")
        assertEquals(3, attempts.map { it.envelope.toList() }.toSet().size, "each attempt needs a fresh transmission key envelope")
        assertEquals(1, sleeps.size, "only the throttle sleeps")
        assertEquals("10", storage.getString(KEY_SERVER_PUBLIC_KEY_ID))
    }

    @Test
    fun aThrottledWriteIsRetriedWithTheSameRecordData() {
        val storage = boundStorage()
        val recorder = Recorder(storage.getBytes(KEY_PUBLIC_KEY)!!, transmissionKey)
        val record = record()
        var calls = 0
        val mock: QueryFunction = { url, tk, payload ->
            check(++calls <= 20) { "retry loop did not stop" }
            recorder.record(url, tk, payload)
            if (calls == 1) KeeperHttpResponse(429, throttled) else KeeperHttpResponse(200, ByteArray(0))
        }

        updateSecret(SecretsManagerOptions(storage, mock, throttleSleepMillis = { }), record)

        val attempts = recorder.attempts
        assertEquals(2, attempts.size)
        assertTrue(attempts.all { it.url.endsWith("/update_secret") }, "both attempts must be the write: ${attempts.map { it.url }}")
        assertTrue(attempts.all { it.signatureValid })
        assertEquals(attempts[0].payloadJson, attempts[1].payloadJson, "the write must carry the same record data and revision on the retry")
        assertNotEquals(attempts[0].envelope.toList(), attempts[1].envelope.toList())
        val sentRecord = Json.parseToJsonElement(attempts[1].payloadJson).let { (it as kotlinx.serialization.json.JsonObject)["data"] }
        assertNotNull(sentRecord, "the payload must carry the encrypted record")
        val decryptedRecord = bytesToString(decrypt(webSafe64ToBytes((sentRecord as kotlinx.serialization.json.JsonPrimitive).content), record.recordKey))
        assertEquals(Json.encodeToString(record.data), decryptedRecord)
    }

    @Test
    fun aThrottledAttachmentRegistrationIsRetriedOnceWithTheSameFileAndOwnerReference() {
        val storage = boundStorage()
        val recorder = Recorder(storage.getBytes(KEY_PUBLIC_KEY)!!, transmissionKey)
        val owner = record()
        val closedPort = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
        var calls = 0
        val mock: QueryFunction = { url, tk, payload ->
            check(++calls <= 20) { "retry loop did not stop" }
            recorder.record(url, tk, payload)
            if (calls == 1) KeeperHttpResponse(429, throttled)
            else ok("""{"url":"https://127.0.0.1:$closedPort/upload","parameters":"{}","successStatusCode":201}""", tk)
        }

        // The registration succeeds on the second attempt. The upload that follows goes to a closed local port and fails.
        assertFails {
            uploadFile(SecretsManagerOptions(storage, mock, throttleSleepMillis = { }, connectTimeoutMillis = 2_000, readTimeoutMillis = 2_000),
                owner, KeeperFileUpload("note.txt", "Note", "text/plain", "contents".toByteArray()))
        }

        val attempts = recorder.attempts
        assertEquals(2, attempts.size, "the registration is sent twice and the upload step is reached once")
        assertTrue(attempts.all { it.url.endsWith("/add_file") && it.signatureValid })
        assertEquals(attempts[0].payloadJson, attempts[1].payloadJson, "the file record uid and the owner data must not change between attempts")
        val fileRecordUid = Regex("\"fileRecordUid\":\"([^\"]+)\"").find(attempts[1].payloadJson)!!.groupValues[1]
        assertEquals(1, Json.encodeToString(owner.data).split(fileRecordUid).size - 1, "the owner record must reference the new file exactly once")
    }

    @Test
    fun aResponseThatFailsAuthenticationAfterARetryIsRejectedAndNotRetried() {
        val storage = boundStorage()
        var calls = 0
        val mock: QueryFunction = { _, tk, _ ->
            check(++calls <= 20) { "retry loop did not stop" }
            if (calls == 1) KeeperHttpResponse(429, throttled)
            else KeeperHttpResponse(200, ok(emptySecrets, tk).data.also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() })
        }

        assertFails { getSecrets(SecretsManagerOptions(storage, mock, throttleSleepMillis = { })) }

        assertEquals(2, calls, "an unauthenticated response must fail the call, not trigger another attempt")
    }

    @Test(timeout = 30_000)
    fun anInterruptedThrottleSleepStopsTheCallWithoutAnotherRequest() {
        val storage = boundStorage()
        var calls = 0
        val mock: QueryFunction = { _, _, _ ->
            check(++calls <= 20) { "retry loop did not stop" }
            KeeperHttpResponse(429, throttled)
        }
        // The same sequence a real Thread.sleep follows when the thread is interrupted: the exception is thrown and the flag cleared.
        val interruptedSleep: (Long) -> Unit = { Thread.currentThread().interrupt(); Thread.sleep(it) }

        assertFailsWith<InterruptedException> { getSecrets(SecretsManagerOptions(storage, mock, throttleSleepMillis = interruptedSleep)) }

        assertEquals(1, calls, "no request may follow an interrupted sleep")
    }

    @Test(timeout = 30_000)
    fun anInterruptDuringTheFetchAfterBindingKeepsTheBindingAndTheInterruptStatus() {
        // A call that binds a new client runs a second, best-effort fetch. If the thread is interrupted while that
        // fetch waits out a throttle, the first result still stands and the interrupt must stay visible to the caller.
        val calls = listOf<(SecretsManagerOptions) -> KeeperSecrets>({ getSecrets(it) }, { getSecrets2(it) })
        for ((index, call) in calls.withIndex()) {
            val label = if (index == 0) "getSecrets" else "getSecrets2"
            val appKey = getRandomBytes(32)
            val storage = InMemoryStorage()
            val clientKey = Base64.getUrlEncoder().withoutPadding().encodeToString(getRandomBytes(32))
            initializeStorage(storage, "US:$clientKey", null)
            val bind = """{"encryptedAppKey":"${bytesToBase64(encrypt(appKey, storage.getBytes(KEY_CLIENT_KEY)!!))}","folders":null,"records":[]}"""
            var requests = 0
            val mock: QueryFunction = { _, tk, _ ->
                check(++requests <= 20) { "retry loop did not stop" }
                if (requests == 1) ok(bind, tk) else KeeperHttpResponse(429, throttled)
            }
            val interruptedSleep: (Long) -> Unit = { Thread.currentThread().interrupt(); Thread.sleep(it) }

            val secrets = call(SecretsManagerOptions(storage, mock, throttleSleepMillis = interruptedSleep))

            assertTrue(secrets.records.isEmpty(), "$label: the binding result must be returned")
            assertTrue(Thread.interrupted(), "$label: the caller's interrupt status was cleared")
            assertEquals(2, requests, "$label: one binding request and one throttled follow-up, nothing after the interrupt")
            assertContentEquals(appKey, storage.getBytes(KEY_APP_KEY), "$label: the binding must be stored")
        }
    }
}

private fun ecPublicKey(raw: ByteArray): java.security.PublicKey {
    val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
        .getParameterSpec(ECParameterSpec::class.java)
    val point = ECPoint(BigInteger(1, raw.copyOfRange(1, 33)), BigInteger(1, raw.copyOfRange(33, 65)))
    return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, parameters))
}
