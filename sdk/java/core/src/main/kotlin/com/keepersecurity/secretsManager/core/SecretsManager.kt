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

private data class EncryptedPayload(val payload: ByteArray, val signature: ByteArray)

@Serializable
private data class SecretsManagerResponseFolder(val folderUid: String, val folderKey: String, val records: List<SecretsManagerResponseRecord>)

@Serializable
private data class SecretsManagerResponseRecord(val recordUid: String, val recordKey: String, val data: String, val isEditable: Boolean, val files: List<SecretsManagerResponseFile>?)

@Serializable
private data class SecretsManagerResponseFile(val fileUid: String, val fileKey: String, val data: String, val url: String, val thumbnailUrl: String?)

@Serializable
private data class SecretsManagerResponse(val encryptedAppKey: String?, val folders: List<SecretsManagerResponseFolder>?, val records: List<SecretsManagerResponseRecord>?)

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

//export const getSecrets = async (storage: KeyValueStorage, recordsFilter?: string[]): Promise<KeeperSecrets> => {
//    const { secrets, justBound } = await fetchAndDecryptSecrets(storage, recordsFilter)
//    if (justBound) {
//        try {
//            await fetchAndDecryptSecrets(storage, recordsFilter)
//        }
//        catch (e) {
//            console.error(e)
//        }
//    }
//    return secrets
//}

fun getSecrets(storage: KeyValueStorage, recordsFilter: List<String>? = null) {
    fetchAndDecryptSecrets(storage, recordsFilter)
}

//
//    const records: KeeperRecord[] = []
//    let justBound = false
//    if (response.encryptedAppKey) {
//        justBound = true
//        await platform.unwrap(platform.base64ToBytes(response.encryptedAppKey), KEY_APP_KEY, KEY_CLIENT_KEY, storage)
//        await storage.delete(KEY_CLIENT_KEY)
//    }
//    if (response.records) {
//        for (const record of response.records) {
//            await platform.unwrap(platform.base64ToBytes(record.recordKey), record.recordUid, KEY_APP_KEY, storage, true)
//            const decryptedRecord = await decryptRecord(record)
//            records.push(decryptedRecord)
//        }
//    }
//    if (response.folders) {
//        for (const folder of response.folders) {
//            await platform.unwrap(platform.base64ToBytes(folder.folderKey), folder.folderUid, KEY_APP_KEY, storage, true)
//            for (const record of folder.records) {
//                await platform.unwrap(platform.base64ToBytes(record.recordKey), record.recordUid, folder.folderUid)
//                const decryptedRecord = await decryptRecord(record)
//                decryptedRecord.folderUid = folder.folderUid
//                records.push(decryptedRecord)
//            }
//        }
//    }
//    const secrets: KeeperSecrets = {
//        records: records
//    }
//    return { secrets, justBound }
//}

private fun fetchAndDecryptSecrets(storage: KeyValueStorage, recordsFilter: List<String>?) {
    val transmissionKey = generateTransmissionKey(1)
    val encryptedPayload = prepareGetPayload(storage, transmissionKey, recordsFilter)
    val httpResponse = postQuery(storage, "get_secret", transmissionKey, encryptedPayload)
    val decryptedResponse = decrypt(httpResponse.data, transmissionKey.key)
    val jsonString = bytesToString(decryptedResponse)
    val response = Json.decodeFromString<SecretsManagerResponse>(jsonString)
    println(response)
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

private fun encryptAndSignPayload(
    storage: KeyValueStorage,
    transmissionKey: TransmissionKey,
    payload: GetPayload
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

@Serializable
data class Project(val name: String, val language: String)

private fun doSomething(): Boolean {
    val data = Project("kotlinx.serialization", "Kotlin")
    val string = Json.encodeToString(data)
    println(string) // {"name":"kotlinx.serialization","language":"Kotlin"}
    // Deserializing back into objects
    val obj = Json.decodeFromString<JsonObject>(string)
    println(obj) // Project(name=kotlinx.serialization, language=Kotlin)
    return true
}