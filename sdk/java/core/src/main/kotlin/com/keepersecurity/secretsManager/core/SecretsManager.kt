@file:JvmName("SecretsManager")

package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.HttpURLConnection.HTTP_OK
import java.net.URL
import java.security.KeyManagementException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.*
import java.util.jar.Manifest
import javax.net.ssl.*

const val KEY_HOSTNAME = "hostname" // base url for the Secrets Manager service
const val KEY_SERVER_PUBIC_KEY_ID = "serverPublicKeyId"
const val KEY_CLIENT_ID = "clientId"
const val KEY_CLIENT_KEY = "clientKey" // The key that is used to identify the client before public key
const val KEY_APP_KEY = "appKey" // The application key with which all secrets are encrypted
const val KEY_OWNER_PUBLIC_KEY = "appOwnerPublicKey" // The application owner public key, to create records
const val KEY_PRIVATE_KEY = "privateKey" // The client's private key
const val KEY_PUBLIC_KEY = "publicKey" // The client's public key

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
    val queryFunction: QueryFunction? = null,
    val allowUnverifiedCertificate: Boolean = false
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
    val data: String,
    val revision: Long? = null
)

@Serializable
private data class CreatePayload(
    val clientVersion: String,
    val clientId: String,
    val recordUid: String,
    val recordKey: String,
    val folderUid: String,
    val folderKey: String,
    val data: String,
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
    val revision: Long? = null,
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
    val appData: String? = null,
    val encryptedAppKey: String?,
    val appOwnerPublicKey: String? = null,
    val folders: List<SecretsManagerResponseFolder>?,
    val records: List<SecretsManagerResponseRecord>?,
    val expiresOn: Long? = null,
    val warnings: List<String>? = null
)

data class KeeperSecrets(val appData: AppData, val records: List<KeeperRecord>, val expiresOn: Instant? = null, val warnings: List<String>? = null) {
    fun getRecordByUid(recordUid: String): KeeperRecord? {
        return records.find { it.recordUid == recordUid }
    }
}

@Serializable
data class AppData(val title: String, val type: String)

data class KeeperRecord(
    val recordKey: ByteArray,
    val recordUid: String,
    var folderUid: String? = null,
    var folderKey: ByteArray? = null,
    val data: KeeperRecordData,
    val revision: Long? = 0,
    val files: List<KeeperFile>? = null
) {
    fun getPassword(): String? {
        val passwordField = data.getField<Password>() ?: return null
        return if (passwordField.value.size > 0) passwordField.value[0] else null
    }

    fun updatePassword(newPassword: String) {
        val passwordField = data.getField<Password>() ?: throw Exception("Password field is not present on the record $recordUid")

        if (passwordField.value.size == 0)
            passwordField.value.add(newPassword)
        else
            passwordField.value[0] = newPassword
    }

    fun getFileByName(fileName: String): KeeperFile? {
        return files?.find { it.data.name == fileName }
    }

    fun getFileByUid(fileUid: String): KeeperFile? {
        return files?.find { it.fileUid == fileUid }
    }
}

data class KeeperFile(
    val fileKey: ByteArray,
    val fileUid: String,
    val data: KeeperFileData,
    val url: String,
    val thumbnailUrl: String?
)

@JvmOverloads
fun initializeStorage(storage: KeyValueStorage, oneTimeToken: String, hostName: String? = null) {
    val tokenParts = oneTimeToken.split(':')
    val host: String
    val clientKey: String
    if (tokenParts.size == 1) {
        host = hostName ?: throw Exception("The hostname must be present in the token or as a parameter")
        clientKey = oneTimeToken
    } else {
        host = when (tokenParts[0].uppercase(Locale.getDefault())) {
            "US" -> "keepersecurity.com"
            "EU" -> "keepersecurity.eu"
            "AU" -> "keepersecurity.com.au"
            "GOV" -> "govcloud.keepersecurity.us"
            else -> tokenParts[0]
        }
        clientKey = tokenParts[1]
    }
    val clientKeyBytes = webSafe64ToBytes(clientKey)
    val clientKeyHash = hash(clientKeyBytes, CLIENT_ID_HASH_TAG)
    val clientId = bytesToBase64(clientKeyHash)
    val existingClientId = storage.getString(KEY_CLIENT_ID)
    if (existingClientId != null) {
        if (clientId == existingClientId) {
            return   // the storage is already initialized
        }
        throw Exception("The storage is already initialized with a different client Id (${existingClientId})")
    }
    storage.saveString(KEY_HOSTNAME, host)
    storage.saveString(KEY_CLIENT_ID, clientId)
    storage.saveBytes(KEY_CLIENT_KEY, clientKeyBytes)
    val keyPair = generateKeyPair()
    storage.saveBytes(KEY_PRIVATE_KEY, keyPair.private.encoded) // private key is stored in DER, to be compatible with other SDK's
    storage.saveBytes(KEY_PUBLIC_KEY, extractPublicRaw(keyPair.public)) // public key stored raw
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
            var buildPathCoreIdx = classPath.lastIndexOf("build/classes")
            if (buildPathCoreIdx < 0) {
                buildPathCoreIdx = classPath.lastIndexOf("out/production/classes")
            }
            val buildPath = classPath.substring(0, buildPathCoreIdx)
            "${buildPath}build/tmp/jar/MANIFEST.MF"
        }
        val manifest = Manifest(URL(filePath).openStream())
        version = manifest.mainAttributes.getValue("Implementation-Version")
    }
}

fun toKeeperAppClientString(version: String): String {
    return "mj${version.replace("-SNAPSHOT", "")}"
}

@ExperimentalSerializationApi
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

@ExperimentalSerializationApi
fun updateSecret(options: SecretsManagerOptions, record: KeeperRecord) {
    val payload = prepareUpdatePayload(options.storage, record)
    postQuery(options, "update_secret", payload)
}

@ExperimentalSerializationApi
@JvmOverloads
fun createSecret(options: SecretsManagerOptions, folderUid: String, recordData: KeeperRecordData, secrets: KeeperSecrets = getSecrets(options)): String {

    val payload = prepareCreatePayload(options.storage, folderUid, recordData, secrets)
    postQuery(options, "create_secret", payload)
    return payload.recordUid
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

@ExperimentalSerializationApi
private fun fetchAndDecryptSecrets(
    options: SecretsManagerOptions,
    recordsFilter: List<String>
): Pair<KeeperSecrets, Boolean> {
    val storage = options.storage
    val payload = prepareGetPayload(storage, recordsFilter)
    val responseData = postQuery(options, "get_secret", payload)
    val jsonString = bytesToString(responseData)
    val response = nonStrictJson.decodeFromString<SecretsManagerResponse>(jsonString)
    var justBound = false
    val appKey: ByteArray
    if (response.encryptedAppKey != null) {
        justBound = true
        val clientKey = storage.getBytes(KEY_CLIENT_KEY) ?: throw Exception("Client key is missing from the storage")
        appKey = decrypt(response.encryptedAppKey, clientKey)
        storage.saveBytes(KEY_APP_KEY, appKey)
        storage.delete(KEY_CLIENT_KEY)
        storage.delete(KEY_PUBLIC_KEY)
        response.appOwnerPublicKey?.let {
            storage.saveString(KEY_OWNER_PUBLIC_KEY, it)
        }
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
                decryptedRecord.folderKey = folderKey
                records.add(decryptedRecord)
            }
        }
    }
    val appData = if (response.appData == null)
        AppData("", "") else
        nonStrictJson.decodeFromString(bytesToString(decrypt(webSafe64ToBytes(response.appData), appKey)))
    val warnings = if (response.warnings == null || response.warnings.isEmpty()) null else response.warnings
    val secrets = KeeperSecrets(
        appData,
        records,
        if (response.expiresOn != null && response.expiresOn > 0) Instant.ofEpochMilli(response.expiresOn) else null,
        warnings)
    return Pair(secrets, justBound)
}

@ExperimentalSerializationApi
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
    return KeeperRecord(recordKey, record.recordUid, null, null, Json.decodeFromString(bytesToString(decryptedRecord)), record.revision, files)
}

private fun prepareGetPayload(
    storage: KeyValueStorage,
    recordsFilter: List<String>
): GetPayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw Exception("Client Id is missing from the configuration")
    val payload = GetPayload(
        toKeeperAppClientString(ManifestLoader.version),
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
    return payload
}

@ExperimentalSerializationApi
private fun prepareUpdatePayload(
    storage: KeyValueStorage,
    record: KeeperRecord
): UpdatePayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw Exception("Client Id is missing from the configuration")
    val recordBytes = stringToBytes(Json.encodeToString(record.data))
    val encryptedRecord = encrypt(recordBytes, record.recordKey)
    return UpdatePayload(toKeeperAppClientString(ManifestLoader.version), clientId, record.recordUid, webSafe64FromBytes(encryptedRecord), record.revision)
}

@ExperimentalSerializationApi
private fun prepareCreatePayload(
    storage: KeyValueStorage,
    folderUid: String,
    recordData: KeeperRecordData,
    secrets: KeeperSecrets
): CreatePayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw Exception("Client Id is missing from the configuration")
    val ownerPublicKey = storage.getBytes(KEY_OWNER_PUBLIC_KEY) ?: throw Exception("Application owner public key is missing from the configuration")
    val recordFromFolder = secrets.records.find { it.folderUid == folderUid }
    if (recordFromFolder?.folderKey == null) {
        throw Exception("Unable to create record - folder key for $folderUid not found")
    }
    val recordBytes = stringToBytes(Json.encodeToString(recordData))
    val recordKey = getRandomBytes(32)
    val recordUid = getRandomBytes(16)
    val encryptedRecord = encrypt(recordBytes, recordKey)
    val encryptedRecordKey = publicEncrypt(recordKey, ownerPublicKey)
    val encryptedFolderKey = encrypt(recordKey, recordFromFolder.folderKey!!)
    return CreatePayload(toKeeperAppClientString(ManifestLoader.version), clientId,
        webSafe64FromBytes(recordUid),
        bytesToBase64(encryptedRecordKey),
        folderUid,
        bytesToBase64(encryptedFolderKey),
        webSafe64FromBytes(encryptedRecord))
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

private val nonStrictJson = Json { ignoreUnknownKeys = true }

var keyId = 7

@Suppress("SpellCheckingInspection")
private val keeperPublicKeys = listOf(
    "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM",
    "BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ",
    "BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g",
    "BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg",
    "BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk",
    "BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY",
    "BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI",
    "BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE",
    "BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8",
    "BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c",
    "BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU"
).associateBy({ keyId++ }, { webSafe64ToBytes(it) })

private fun generateTransmissionKey(storage: KeyValueStorage): TransmissionKey {
    val transmissionKey = if (TestStubs.transmissionKeyStubReady()) {
        TestStubs.transmissionKeyStub()
    } else {
        getRandomBytes(32)
    }
    val keyNumber: Int = storage.getString(KEY_SERVER_PUBIC_KEY_ID)?.toInt() ?: 7
    val keeperPublicKey = keeperPublicKeys[keyNumber] ?: throw Exception("Key number $keyNumber is not supported")
    val encryptedKey = publicEncrypt(transmissionKey, keeperPublicKey)
    return TransmissionKey(keyNumber, transmissionKey, encryptedKey)
}

@ExperimentalSerializationApi
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

@ExperimentalSerializationApi
private inline fun <reified T> postQuery(
    options: SecretsManagerOptions,
    path: String,
    payload: T
): ByteArray {
    val hostName = options.storage.getString(KEY_HOSTNAME) ?: throw Exception("hostname is missing from the storage")
    val url = "https://${hostName}/api/rest/sm/v1/${path}"
    while (true) {
        val transmissionKey = generateTransmissionKey(options.storage)
        val encryptedPayload = encryptAndSignPayload(options.storage, transmissionKey, payload)
        val response = if (options.queryFunction == null) {
            postFunction(url, transmissionKey, encryptedPayload, options.allowUnverifiedCertificate)
        } else {
            options.queryFunction.invoke(url, transmissionKey, encryptedPayload)
        }
        if (response.statusCode != HTTP_OK) {
            val errorMessage = String(response.data)
            try {
                val error = nonStrictJson.decodeFromString<KeeperError>(errorMessage)
                if (error.error == "key") {
                    options.storage.saveString(KEY_SERVER_PUBIC_KEY_ID, error.key_id.toString())
                    continue
                }
            } catch (e: Exception) {
            }
            throw Exception(errorMessage)
        }
        if (response.data.isEmpty()) {
            return response.data
        }
        return decrypt(response.data, transmissionKey.key)
    }
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