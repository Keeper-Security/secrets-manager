@file:JvmName("SecretsManager")

package com.keepersecurity.secretsManager.core

import kotlinx.serialization.*
import kotlinx.serialization.json.*
import java.net.HttpURLConnection.HTTP_OK
import java.net.URL
import java.security.KeyManagementException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.*

private const val KEY_URL = "url" // base url for the Secrets Manager service
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

private data class TransmissionKey(val publicKeyId: Int, val key: ByteArray, val encryptedKey: ByteArray)
private data class KeeperHttpResponse(val statusCode: Int, val data: ByteArray)

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

private data class EncryptedPayload(val payload: ByteArray, val signature: ByteArray)

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
    val data: JsonObject,
    var files: List<KeeperFile>?
)

data class KeeperFile(
    val fileKey: ByteArray,
    val fileUid: String,
    val data: JsonObject,
    val url: String,
    val thumbnailUrl: String?
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

fun getSecrets(storage: KeyValueStorage, recordsFilter: List<String>? = null): KeeperSecrets {
    val (secrets, justBound) = fetchAndDecryptSecrets(storage, recordsFilter)
    if (justBound) {
        try {
            fetchAndDecryptSecrets(storage, recordsFilter)
        } catch (e: Exception) {
            println(e)
        }
    }
    return secrets
}

fun updateSecret(storage: KeyValueStorage, record: KeeperRecord) {
    val transmissionKey = generateTransmissionKey(1)
    val encryptedPayload = prepareUpdatePayload(storage, transmissionKey, record)
    postQuery(storage, "update_secret", transmissionKey, encryptedPayload)
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
            errorStream != null -> errorStream.readAllBytes()
            else -> inputStream.readAllBytes()
        }
        if (statusCode != HTTP_OK) {
            throw Exception(String(data))
        }
        return decrypt(data, file.fileKey)
    }
}

private fun fetchAndDecryptSecrets(
    storage: KeyValueStorage,
    recordsFilter: List<String>?
): Pair<KeeperSecrets, Boolean> {
    val transmissionKey = generateTransmissionKey(1)
    val encryptedPayload = prepareGetPayload(storage, transmissionKey, recordsFilter)
    val httpResponse = postQuery(storage, "get_secret", transmissionKey, encryptedPayload)
    val decryptedResponse = decrypt(httpResponse.data, transmissionKey.key)
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
    val keeperRecord =
        KeeperRecord(recordKey, record.recordUid, null, Json.decodeFromString(bytesToString(decryptedRecord)), null)
    if (record.files != null) {
        val files: MutableList<KeeperFile> = mutableListOf()
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
        keeperRecord.files = files
    }
    return keeperRecord
}

private fun prepareGetPayload(
    storage: KeyValueStorage,
    transmissionKey: TransmissionKey,
    recordsFilter: List<String>?
): EncryptedPayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw Exception("Client Id is missing from the configuration")
    val payload = GetPayload(
        "w15.0.0",
        clientId,
        null,
        null
    )
    val appKey = storage.getBytes(KEY_APP_KEY)
    if (appKey == null) {
        val publicKey = storage.getBytes(KEY_PUBLIC_KEY) ?: throw Exception("Public key is missing from the storage")
        payload.publicKey = bytesToBase64(publicKey)
    }
    if (recordsFilter != null) {
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
    val payload = UpdatePayload("w15.0.0", clientId, record.recordUid, webSafe64FromBytes(encryptedRecord))
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

private fun postQuery(
    storage: KeyValueStorage,
    path: String,
    transmissionKey: TransmissionKey,
    payload: EncryptedPayload
): KeeperHttpResponse {
    val baseUrl = storage.getString(KEY_URL) ?: throw Exception("URL is missing from the storage")
    with(URL("${baseUrl}/${path}").openConnection() as HttpsURLConnection) {
        sslSocketFactory = trustAllSocketFactory()
        requestMethod = "POST"
        doOutput = true
        setRequestProperty("PublicKeyId", transmissionKey.publicKeyId.toString())
        setRequestProperty("TransmissionKey", bytesToBase64(transmissionKey.encryptedKey))
        setRequestProperty("Authorization", "Signature ${bytesToBase64(payload.signature)}")
        outputStream.write(payload.payload)
        outputStream.flush()
        val statusCode = responseCode
        val data = when {
            errorStream != null -> errorStream.readAllBytes()
            else -> inputStream.readAllBytes()
        }
        if (statusCode != HTTP_OK) {
            throw Exception(String(data))
        }
        return KeeperHttpResponse(statusCode, data)
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

private fun generateTransmissionKey(keyNumber: Int): TransmissionKey {
    val transmissionKey = getRandomBytes(32)
    val encryptedKey = publicEncrypt(transmissionKey, keeperPublicKeys[keyNumber - 1])
    return TransmissionKey(keyNumber, transmissionKey, encryptedKey)
}

// TODO use only for local testing
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