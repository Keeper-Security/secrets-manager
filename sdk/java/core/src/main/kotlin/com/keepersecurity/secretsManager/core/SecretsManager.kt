@file:JvmName("SecretsManager")

package com.keepersecurity.secretsManager.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.net.HttpURLConnection.HTTP_OK
import java.net.URL
import java.security.*
import java.security.cert.X509Certificate
import java.util.jar.Manifest
import javax.net.ssl.*

private const val KEY_URL = "url" // base url for the Secrets Manager service
private const val KEY_SERVER_PUBIC_KEY_ID = "serverPublicKeyId"
private const val KEY_CLIENT_ID = "clientId"
private const val KEY_CLIENT_KEY = "clientKey" // The key that is used to identify the client before public key
private const val KEY_APP_KEY = "appKey" // The application key with which all secrets are encrypted
private const val KEY_PRIVATE_KEY = "privateKey" // The client's private key
private const val KEY_PUBLIC_KEY = "publicKey" // The client's public key
private const val CLIENT_ID_HASH_TAG = "KEEPER_SECRETS_MANAGER_CLIENT_ID" // Tag for hashing the client key to client id

interface KeyValueStorage {
    fun getString(key: String): String?
    fun saveString(key: String, value: String)
    fun getBytes(key: String): ByteArray?
    fun saveBytes(key: String, value: ByteArray)
    fun delete(key: String)
}

data class SecretsManagerOptions @JvmOverloads constructor(
    val storage: KeyValueStorage,
    val queryFunction: QueryFunction? = null
)

typealias QueryFunction = (url: String, transmissionKey: TransmissionKey, payload: EncryptedPayload) -> KeeperHttpResponse

data class TransmissionKey(var publicKeyId: Int, var key: ByteArray, val encryptedKey: ByteArray)
data class KeeperHttpResponse(val statusCode: Int, val data: ByteArray)

@Serializable
data class KeeperError(val key_id: Int, val error: String)

@Serializable
private data class GetPayload(
    val clientVersion: String,
    val clientId: String,
    var publicKey: String? = null,
    var requestedRecords: List<String>? = null
)

@Serializable
private data class UpdatePayload(
    val clientVersion: String,
    val clientId: String,
    val recordUid: String,
    val data: String
)

data class EncryptedPayload(val payload: ByteArray, val signature: ByteArray)

@Serializable
private data class SecretsManagerResponseFolder(
    val folderUid: String,
    val folderKey: String,
    val records: List<SecretsManagerResponseRecord>
)

@Serializable
private data class SecretsManagerResponseRecord(
    val recordUid: String,
    val recordKey: String,
    val data: String,
    val isEditable: Boolean,
    val files: List<SecretsManagerResponseFile>?
)

@Serializable
private data class SecretsManagerResponseFile(
    val fileUid: String,
    val fileKey: String,
    val data: String,
    val url: String,
    val thumbnailUrl: String?
)

@Serializable
private data class SecretsManagerResponse(
    val encryptedAppKey: String?,
    val folders: List<SecretsManagerResponseFolder>?,
    val records: List<SecretsManagerResponseRecord>?
)

data class KeeperSecrets(val records: List<KeeperRecord>)

data class KeeperRecord(
    val recordKey: ByteArray,
    val recordUid: String,
    var folderUid: String?,
    val data: KeeperRecordData,
    var files: List<KeeperFile>?
)

data class KeeperFile(
    val fileKey: ByteArray,
    val fileUid: String,
    val data: KeeperFileData,
    val url: String,
    val thumbnailUrl: String?
)

@Serializable
data class KeeperFileData(
    val title: String,
    val name: String,
    val type: String,
    val size: Long,
    val lastModified: Long
)

fun initializeStorage(storage: KeyValueStorage, clientKey: String, domain: String) {
    val clientKeyBytes = webSafe64ToBytes(clientKey)
    val clientKeyHash = hash(clientKeyBytes, CLIENT_ID_HASH_TAG)
    val clientId = bytesToBase64(clientKeyHash)
    val existingClientId = storage.getString(KEY_CLIENT_ID)
    if (existingClientId != null && clientId == existingClientId) {
        return   // the storage is already initialised
    }
    if (existingClientId != null) {
        throw Exception("The storage is already initialized with a different client Id (${existingClientId})")
    }
    storage.saveString(KEY_URL, "https://${domain}/api/rest/sm/v1")
    storage.saveString(KEY_CLIENT_ID, clientId)
    storage.saveBytes(KEY_CLIENT_KEY, clientKeyBytes)
    val keyPair = generateKeyPair()
    storage.saveBytes(KEY_PUBLIC_KEY, keyPair.first)
    storage.saveBytes(KEY_PRIVATE_KEY, keyPair.second)
}

internal object ManifestLoader {
    internal val version: String

    init {
        val clazz = javaClass
        val classPath: String = clazz.getResource(clazz.simpleName.toString() + ".class")!!.toString()
        val libPathEnd = classPath.lastIndexOf("!")
        val filePath = if (libPathEnd > 0) {
            val libPath = classPath.substring(0, libPathEnd)
            "$libPath!/META-INF/MANIFEST.MF"
        } else { // we might be testing
            val buildPath = classPath.substring(0, classPath.lastIndexOf("build/classes"))
            "${buildPath}build/tmp/jar/MANIFEST.MF"
        }
        val manifest = Manifest(URL(filePath).openStream())
        version = manifest.mainAttributes.getValue("Implementation-Version")
    }
}

@JvmOverloads
fun getSecrets(options: SecretsManagerOptions, recordsFilter: List<String> = emptyList()): KeeperSecrets {
    val (secrets, justBound) = fetchAndDecryptSecrets(options, recordsFilter)
    if (justBound) {
        try {
            fetchAndDecryptSecrets(options, recordsFilter)
        } catch (e: Exception) {
            println(e)
        }
    }
    return secrets
}

fun updateSecret(options: SecretsManagerOptions, record: KeeperRecord) {
    val transmissionKey = generateTransmissionKey(options.storage)
    val encryptedPayload = prepareUpdatePayload(options.storage, transmissionKey, record)
    postQuery(options, "update_secret", transmissionKey, encryptedPayload)
}

fun downloadFile(file: KeeperFile): ByteArray {
    return downloadFile(file, file.url)
}

fun downloadThumbnail(file: KeeperFile): ByteArray {
    if (file.thumbnailUrl == null) {
        throw Exception("Thumbnail does not exist for the file ${file.fileUid}")
    }
    return downloadFile(file, file.thumbnailUrl)
}

private fun downloadFile(file: KeeperFile, url: String): ByteArray {
    with(URL(url).openConnection() as HttpsURLConnection) {
        requestMethod = "GET"
        val statusCode = responseCode
        val data = when {
            errorStream != null -> errorStream.readBytes()
            else -> inputStream.readBytes()
        }
        if (statusCode != HTTP_OK) {
            throw Exception(String(data))
        }
        return decrypt(data, file.fileKey)
    }
}

private fun fetchAndDecryptSecrets(
    options: SecretsManagerOptions,
    recordsFilter: List<String>
): Pair<KeeperSecrets, Boolean> {
    val transmissionKey = generateTransmissionKey(options.storage)
    val storage = options.storage
    val encryptedPayload = prepareGetPayload(storage, transmissionKey, recordsFilter)
    val responseData = postQuery(options, "get_secret", transmissionKey, encryptedPayload)
    val decryptedResponse = decrypt(responseData, transmissionKey.key)
    val jsonString = bytesToString(decryptedResponse)
    val response = Json.decodeFromString<SecretsManagerResponse>(jsonString)
    var justBound = false
    val appKey: ByteArray
    if (response.encryptedAppKey != null) {
        justBound = true
        val clientKey = storage.getBytes(KEY_CLIENT_KEY) ?: throw Exception("Client key is missing from the storage")
        appKey = decrypt(response.encryptedAppKey, clientKey)
        storage.saveBytes(KEY_APP_KEY, appKey)
        storage.delete(KEY_CLIENT_KEY)
    } else {
        appKey = storage.getBytes(KEY_APP_KEY) ?: throw Exception("App key is missing from the storage")
    }
    val records: MutableList<KeeperRecord> = mutableListOf()
    if (response.records != null) {
        response.records.forEach {
            val recordKey = decrypt(it.recordKey, appKey)
            val decryptedRecord = decryptRecord(it, recordKey)
            records.add(decryptedRecord)
        }
    }
    if (response.folders != null) {
        response.folders.forEach { folder ->
            val folderKey = decrypt(folder.folderKey, appKey)
            folder.records.forEach { record ->
                val recordKey = decrypt(record.recordKey, folderKey)
                val decryptedRecord = decryptRecord(record, recordKey)
                decryptedRecord.folderUid = folder.folderUid
                records.add(decryptedRecord)
            }
        }
    }
    val secrets = KeeperSecrets(records)
    return Pair(secrets, justBound)
}

private fun decryptRecord(record: SecretsManagerResponseRecord, recordKey: ByteArray): KeeperRecord {
    val decryptedRecord = decrypt(record.data, recordKey)

    val files: MutableList<KeeperFile> = mutableListOf()

    if (record.files != null) {
        record.files.forEach {
            val fileKey = decrypt(it.fileKey, recordKey)
            val decryptedFile = decrypt(it.data, fileKey)
            files.add(
                KeeperFile(
                    fileKey,
                    it.fileUid,
                    Json.decodeFromString(bytesToString(decryptedFile)),
                    it.url,
                    it.thumbnailUrl
                )
            )
        }
    }
    return KeeperRecord(recordKey, record.recordUid, null, Json.decodeFromString(bytesToString(decryptedRecord)), files)
}

private fun prepareGetPayload(
    storage: KeyValueStorage,
    transmissionKey: TransmissionKey,
    recordsFilter: List<String>
): EncryptedPayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw Exception("Client Id is missing from the configuration")
    val payload = GetPayload(
        "mj${ManifestLoader.version}",
        clientId,
        null,
        null
    )
    val appKey = storage.getBytes(KEY_APP_KEY)
    if (appKey == null) {
        val publicKey = storage.getBytes(KEY_PUBLIC_KEY) ?: throw Exception("Public key is missing from the storage")
        payload.publicKey = bytesToBase64(publicKey)
    }
    if (recordsFilter.isNotEmpty()) {
        payload.requestedRecords = recordsFilter
    }
    return encryptAndSignPayload(storage, transmissionKey, payload)
}

private fun prepareUpdatePayload(
    storage: KeyValueStorage,
    transmissionKey: TransmissionKey,
    record: KeeperRecord
): EncryptedPayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw Exception("Client Id is missing from the configuration")
    val recordBytes = stringToBytes(Json.encodeToString(record.data))
    val encryptedRecord = encrypt(recordBytes, record.recordKey)
    val payload =
        UpdatePayload("mj${ManifestLoader.version}", clientId, record.recordUid, webSafe64FromBytes(encryptedRecord))
    return encryptAndSignPayload(storage, transmissionKey, payload)
}

private inline fun <reified T> encryptAndSignPayload(
    storage: KeyValueStorage,
    transmissionKey: TransmissionKey,
    payload: T
): EncryptedPayload {
    val payloadBytes = stringToBytes(Json.encodeToString(payload))
    val encryptedPayload = encrypt(payloadBytes, transmissionKey.key)
    val privateKey = storage.getBytes(KEY_PRIVATE_KEY) ?: throw Exception("Private key is missing from the storage")
    val signatureBase = transmissionKey.encryptedKey + encryptedPayload
    val signature = sign(signatureBase, privateKey)
    return EncryptedPayload(encryptedPayload, signature)
}

fun cachingPostFunction(url: String, transmissionKey: TransmissionKey, payload: EncryptedPayload): KeeperHttpResponse {
    return try {
        val response = postFunction(url, transmissionKey, payload, false)
        if (response.statusCode == HTTP_OK) {
            saveCachedValue(transmissionKey.key + response.data)
        }
        response
    } catch (e: Exception) {
        val cachedData = getCachedValue()
        val cachedTransmissionKey = cachedData.copyOfRange(0, 32)
        transmissionKey.key = cachedTransmissionKey
        val data = cachedData.copyOfRange(32, cachedData.size)
        KeeperHttpResponse(HTTP_OK, data)
    }
}

fun postFunction(
    url: String,
    transmissionKey: TransmissionKey,
    payload: EncryptedPayload,
    allowUnverifiedCertificate: Boolean
): KeeperHttpResponse {
    var statusCode: Int
    var data: ByteArray
    with(URL(url).openConnection() as HttpsURLConnection) {
        if (allowUnverifiedCertificate) {
            sslSocketFactory = trustAllSocketFactory()
        }
        requestMethod = "POST"
        doOutput = true
        setRequestProperty("PublicKeyId", transmissionKey.publicKeyId.toString())
        setRequestProperty("TransmissionKey", bytesToBase64(transmissionKey.encryptedKey))
        setRequestProperty("Authorization", "Signature ${bytesToBase64(payload.signature)}")
        outputStream.write(payload.payload)
        outputStream.flush()
        statusCode = responseCode
        data = when {
            errorStream != null -> errorStream.readBytes()
            else -> inputStream.readBytes()
        }
    }
    return KeeperHttpResponse(statusCode, data)
}

private val errorMsgJson = Json { ignoreUnknownKeys = true }

private fun postQuery(
    options: SecretsManagerOptions,
    path: String,
    transmissionKey: TransmissionKey,
    payload: EncryptedPayload
): ByteArray {
    val baseUrl = options.storage.getString(KEY_URL) ?: throw Exception("URL is missing from the storage")
    val url = "${baseUrl}/${path}"
    while (true) {
        val response = if (options.queryFunction == null) {
            postFunction(url, transmissionKey, payload, false)
        } else {
            options.queryFunction.invoke(url, transmissionKey, payload)
        }
        if (response.statusCode != HTTP_OK) {
            val errorMessage = String(response.data)
            try {
                val error = errorMsgJson.decodeFromString<KeeperError>(errorMessage)
                if (error.error == "key") {
                    transmissionKey.publicKeyId = error.key_id
                    options.storage.saveString(KEY_SERVER_PUBIC_KEY_ID, error.key_id.toString())
                    continue
                }
            } catch (e: Exception) {
            }
            throw Exception(errorMessage)
        }
        return response.data
    }
}

@Suppress("SpellCheckingInspection")
private val keeperPublicKeys = listOf(
    webSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
    webSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
    webSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
    webSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
    webSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"),
    webSafe64ToBytes("BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM")
)

private fun generateTransmissionKey(storage: KeyValueStorage): TransmissionKey {
    val transmissionKey = if (TestStubs.transmissionKeyStubReady()) {
        TestStubs.transmissionKeyStub()
    } else {
        getRandomBytes(32)
    }
    val keyNumber: Int = storage.getString(KEY_SERVER_PUBIC_KEY_ID)?.toInt() ?: 1
    val encryptedKey = publicEncrypt(transmissionKey, keeperPublicKeys[keyNumber - 1])
    return TransmissionKey(keyNumber, transmissionKey, encryptedKey)
}

private fun trustAllSocketFactory(): SSLSocketFactory {
    val trustAllCerts: Array<TrustManager> = arrayOf(
        object : X509TrustManager {
            private val AcceptedIssuers = arrayOf<X509Certificate>()
            override fun checkClientTrusted(
                certs: Array<X509Certificate?>?, authType: String?
            ) {
            }

            override fun checkServerTrusted(
                certs: Array<X509Certificate?>?, authType: String?
            ) {
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                return AcceptedIssuers
            }
        }
    )
    val sslContext = SSLContext.getInstance("TLS")
    try {
        sslContext.init(null, trustAllCerts, SecureRandom())
    } catch (e: NoSuchAlgorithmException) {
        e.printStackTrace()
    } catch (e: KeyManagementException) {
        e.printStackTrace()
    }
    return sslContext.socketFactory
}

internal object TestStubs {
    lateinit var transmissionKeyStub: () -> ByteArray

    fun transmissionKeyStubReady(): Boolean {
        return this::transmissionKeyStub.isInitialized
    }
}