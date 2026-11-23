@file:JvmName("SecretsManager")

package com.keepersecurity.secretsManager.core

import kotlinx.serialization.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.IOException
import java.net.HttpURLConnection.HTTP_FORBIDDEN
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.doubleOrNull
import java.net.HttpURLConnection.HTTP_OK
import java.net.URI
import java.security.SecureRandom
import java.time.Instant
import java.util.*
import java.util.concurrent.*
import kotlin.random.Random

const val KEEPER_CLIENT_VERSION = "mj18.0.0"

// Throttle retry. The backend throttles HTTP 403 {"error":"throttled"}
// per clientId+endpoint (100 requests / 10s window; memcached TTL 10s that resets on every
// request, so the counter only clears after 10s of silence).
const val MAX_THROTTLE_RETRIES = 5
const val BASE_THROTTLE_DELAY_SEC = 11 // 1s safety margin over the backend's 10s memcached TTL
const val MAX_THROTTLE_DELAY_SEC = 176 // caps a backend-supplied retry_after from forcing an excessive wait
const val MAX_KEY_ROTATION_RETRIES = 3 // parity with JS SDK open PR #1078

// Connection timeouts. Single source for both the SecretsManagerOptions defaults and the
// overloads that take a KeeperFile without options, so the two cannot drift apart.
private const val DEFAULT_CONNECT_TIMEOUT_MS = 5_000
private const val DEFAULT_READ_TIMEOUT_MS = 30_000
private const val DRIVE_FOLDER_CREATE_REFUSED =
    "Unable to create folder - the SDK cannot create a folder in an NSF (Keeper Drive) folder."
private const val DRIVE_FOLDER_UPDATE_REFUSED =
    "Unable to update folder - the SDK cannot update an NSF (Keeper Drive) folder."
private const val DRIVE_FOLDER_HINT =
    "An NSF (Keeper Drive) folder must be shared directly to the application and hold at least one record."

const val KEY_HOSTNAME = "hostname" // base url for the Secrets Manager service
const val KEY_SERVER_PUBLIC_KEY_ID = "serverPublicKeyId"
@Deprecated("Typo; use KEY_SERVER_PUBLIC_KEY_ID", ReplaceWith("KEY_SERVER_PUBLIC_KEY_ID"))
const val KEY_SERVER_PUBIC_KEY_ID = KEY_SERVER_PUBLIC_KEY_ID
const val KEY_SERVER_PUBLIC_KEY = "serverPublicKey" // custom server public key bytes (base64url), overrides embedded table
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
    val allowUnverifiedCertificate: Boolean = false,
    val loggingEnabled: Boolean = true,
    val serverPublicKey: String? = null,
    val serverPublicKeyId: String? = null,
    // Override the sleep between throttle retries (primarily for tests). Defaults to Thread.sleep.
    val throttleSleepMillis: ((Long) -> Unit)? = null,
    val connectTimeoutMillis: Int = DEFAULT_CONNECT_TIMEOUT_MS,
    val readTimeoutMillis: Int = DEFAULT_READ_TIMEOUT_MS,
    val proxyUrl: String? = null
) {
    companion object {
        // Static factory for Java callers — preferred over the 8-arg @JvmOverloads form.
        // Adding proxyUrl to the primary constructor changed the copy() binary signature;
        // callers compiled against 17.3.0 must recompile against 17.4.0.
        @JvmStatic
        fun withProxy(storage: KeyValueStorage, proxyUrl: String) =
            SecretsManagerOptions(storage = storage, proxyUrl = proxyUrl)
    }

    init {
        testSecureRandom()
        serverPublicKey?.let { storage.saveString(KEY_SERVER_PUBLIC_KEY, it) }
        serverPublicKeyId?.let { storage.saveString(KEY_SERVER_PUBLIC_KEY_ID, it) }
    }

    override fun toString(): String =
        "SecretsManagerOptions(storage=$storage, queryFunction=$queryFunction, " +
        "allowUnverifiedCertificate=$allowUnverifiedCertificate, loggingEnabled=$loggingEnabled, " +
        "serverPublicKey=$serverPublicKey, serverPublicKeyId=$serverPublicKeyId, " +
        "throttleSleepMillis=$throttleSleepMillis, connectTimeoutMillis=$connectTimeoutMillis, " +
        "readTimeoutMillis=$readTimeoutMillis, proxyUrl=${if (proxyUrl != null) "<redacted>" else null})"
}

data class QueryOptions @JvmOverloads constructor(
    val recordsFilter: List<String> = emptyList(),
    val foldersFilter: List<String> = emptyList(),
    val requestLinks: Boolean? = null
)

data class CreateOptions @JvmOverloads constructor(
    val folderUid: String,
    val subFolderUid: String? = null,
)

data class UpdateOptions @JvmOverloads constructor(
    val transactionType: UpdateTransactionType? = null,
    val linksToRemove: List<String>? = null,
)

typealias QueryFunction = (url: String, transmissionKey: TransmissionKey, payload: EncryptedPayload) -> KeeperHttpResponse

data class TransmissionKey(var publicKeyId: Int, var key: ByteArray, val encryptedKey: ByteArray)
data class KeeperHttpResponse(val statusCode: Int, val data: ByteArray)

@Serializable
data class KeeperError(val key_id: Int, val error: String)

abstract class CommonPayload {
    abstract val clientVersion: String
    abstract val clientId: String
}

@Serializable
private data class GetPayload(
    override val clientVersion: String,
    override val clientId: String,
    var publicKey: String? = null,
    var requestedRecords: List<String>? = null,
    var requestedFolders: List<String>? = null,
    var requestLinks: Boolean? = null
): CommonPayload()

@Serializable
enum class UpdateTransactionType(printableName: String) {
    @SerialName("general") GENERAL("general"),
    @SerialName("rotation") ROTATION("rotation")
}

@Serializable
private data class UpdatePayload(
    override val clientVersion: String,
    override val clientId: String,
    val recordUid: String,
    val data: String,
    val revision: Long,
    val transactionType: UpdateTransactionType? = null,
    val links2Remove: List<String>? = null
): CommonPayload()

@Serializable
private data class CompleteTransactionPayload(
    val clientVersion: String,
    val clientId: String,
    val recordUid: String
)

@Serializable
private data class CreatePayload(
    override val clientVersion: String,
    override val clientId: String,
    val recordUid: String,
    val recordKey: String,
    val folderUid: String,
    val folderKey: String?,
    val data: String,
    val subFolderUid: String?
): CommonPayload()

@Serializable
private data class DeletePayload(
    override val clientVersion: String,
    override val clientId: String,
    val recordUids: List<String>? = null,
): CommonPayload()

@Serializable
private data class DeleteFolderPayload(
    override val clientVersion: String,
    override val clientId: String,
    val folderUids: List<String>? = null,
    val forceDeletion: Boolean
): CommonPayload()

@Serializable
private data class CreateFolderPayload(
    override val clientVersion: String,
    override val clientId: String,
    val folderUid: String,
    val sharedFolderUid: String,
    val sharedFolderKey: String,
    val data: String,
    val parentUid: String?
): CommonPayload()

@Serializable
private data class UpdateFolderPayload(
    override val clientVersion: String,
    override val clientId: String,
    val folderUid: String,
    val data: String
): CommonPayload()

@Serializable
private data class FileUploadPayload(
    override val clientVersion: String,
    override val clientId: String,
    val fileRecordUid: String,
    val fileRecordKey: String,
    val fileRecordData: String,
    val ownerRecordUid: String,
    val ownerRecordData: String,
    val ownerRecordRevision: Long,
    val linkKey: String,
    val fileSize: Int, // we will not allow upload size > 2GB due to memory constraints
): CommonPayload()

data class EncryptedPayload(val payload: ByteArray, val signature: ByteArray)

private data class FileUploadPayloadAndFile(val payload: FileUploadPayload, val encryptedFile: ByteArray)

@Serializable
private data class SecretsManagerResponseFolder(
    val folderUid: String,
    val folderKey: String,
    val data: String? = null,
    val parent: String? = null,
    val records: List<SecretsManagerResponseRecord>? = null
)

@Serializable
private data class SecretsManagerResponseRecord(
    val recordUid: String,
    val recordKey: String,
    val data: String,
    val revision: Long,
    val isEditable: Boolean,
    val files: List<SecretsManagerResponseFile>?,
    val innerFolderUid: String?,
    val links: List<KeeperRecordLink>? = null
)

/**
 * Typed view over a single linked-credential entry of a record (the entries in [KeeperRecord.links]).
 *
 * A link entry carries [recordUid], optional base64 [data], and an optional [path] discriminator.
 * Observed payload shapes (verified against the live backend):
 *
 * - path "meta" (self-link, recordUid == owning record): plain base64 JSON with `allowedSettings`
 *   (rotation, connections, portForwards, sessionRecording, typescriptRecording, aiEnabled,
 *   aiSessionTerminate, remoteBrowserIsolation), plus `rotateOnTermination`, `version` and
 *   `no_update_services`.
 * - path null (credential link to another record): plain base64 JSON with `is_admin`,
 *   `is_launch_credential`, `is_iam_user`, `belongs_to` and `rotation_settings`; or no data at all
 *   (a pure record reference).
 * - path "ai_settings" / "jit_settings" (self-links): data is AES-256-GCM encrypted under the
 *   owning record's key; see [getDecryptedData].
 *
 * Accessors never throw: parse, decode or decryption failures yield null/false. [getLinkData]
 * returns the complete parsed payload with nested objects and arrays preserved, so fields unknown
 * to this SDK version are retained.
 */
@Serializable
data class KeeperRecordLink(
    val recordUid: String,
    val data: String? = null,
    val path: String? = null
) {
    
    /**
     * Parse the link data as a JSON object, handling errors gracefully
     */
    private fun parseJsonData(): Map<String, Any?>? {
        if (data == null) return null
        
        return try {
            val decodedData = String(java.util.Base64.getDecoder().decode(data))

            // Check if the decoded data looks like JSON (starts with { or [)
            // If not, it's likely encrypted/binary data, so return null silently
            if (!decodedData.startsWith("{") && !decodedData.startsWith("[")) {
                return null
            }
            
            val jsonElement = Json.parseToJsonElement(decodedData)
            if (jsonElement is JsonObject) {
                jsonObjectToMap(jsonElement)
            } else {
                // Only log if it looked like JSON but wasn't a JSON object
                System.err.println("KeeperRecordLink: Link data is not a JSON object (was JSON array or primitive)")
                null
            }
        } catch (e: IllegalArgumentException) {
            // Base64 decoding failed - likely not base64 encoded
            null
        } catch (e: Exception) {
            // Only log parsing errors for data that looks like it should be JSON
            val decodedData = try {
                String(java.util.Base64.getDecoder().decode(data))
            } catch (_: Exception) {
                return null
            }
            
            if (decodedData.startsWith("{") || decodedData.startsWith("[")) {
                System.err.println("KeeperRecordLink: Failed to parse JSON data - ${e.message}")
            }
            null
        }
    }

    /**
     * Get a strict boolean value from the parsed JSON data; missing or non-boolean values are false.
     *
     * When [checkAllowedSettings] is true the nested `allowedSettings` object is consulted if the
     * key is absent at the top level; a top-level boolean wins. The backend nests permission flags
     * under `allowedSettings` in `path:"meta"` links.
     */
    private fun getBooleanValue(key: String, checkAllowedSettings: Boolean = false): Boolean {
        val parsed = parseJsonData() ?: return false
        (parsed[key] as? Boolean)?.let { return it }
        if (checkAllowedSettings) {
            val allowed = parsed["allowedSettings"] as? Map<*, *>
            (allowed?.get(key) as? Boolean)?.let { return it }
        }
        return false
    }

    /**
     * Get an integer value from the parsed JSON data  
     */
    private fun getIntValue(key: String): Int? {
        return parseJsonData()?.get(key) as? Int
    }

    /**
     * Get a string value from the parsed JSON data
     */
    private fun getStringValue(key: String): String? {
        return parseJsonData()?.get(key) as? String
    }

    /**
     * Recursively convert a [JsonElement] to a plain Kotlin value: objects become
     * `Map<String, Any?>`, arrays become `List<Any?>`, and primitives become typed scalars
     * (String/Boolean/Int/Long/Double). Strings are never coerced, so a quoted "3"/"true"
     * stays a String. JSON nulls become Kotlin null and are preserved on both branches.
     */
    private fun jsonElementToValue(element: JsonElement): Any? = when (element) {
        is JsonNull -> null
        is JsonObject -> jsonObjectToMap(element)
        is JsonArray -> element.map { jsonElementToValue(it) }
        is JsonPrimitive ->
            if (element.isString) element.content
            else element.booleanOrNull
                ?: element.intOrNull
                ?: element.longOrNull
                ?: element.doubleOrNull
                ?: element.content
    }

    /**
     * Convert a [JsonObject] to a nested `Map<String, Any?>`, preserving nested objects, arrays and
     * JSON null values (lossless, matching the Python reference).
     */
    private fun jsonObjectToMap(obj: JsonObject): Map<String, Any?> =
        obj.entries.associate { (key, value) -> key to jsonElementToValue(value) }

    /**
     * Check if the link data indicates admin status for a user
     */
    fun isAdminUser(): Boolean = getBooleanValue("is_admin")
    
    /**
     * Check if this is a launch credential link
     */
    fun isLaunchCredential(): Boolean = getBooleanValue("is_launch_credential")
    
    /**
     * Check if rotation is allowed based on link settings
     */
    fun allowsRotation(): Boolean = getBooleanValue("rotation", checkAllowedSettings = true)
    
    /**
     * Check if connections are allowed based on link settings
     */
    fun allowsConnections(): Boolean = getBooleanValue("connections", checkAllowedSettings = true)
    
    /**
     * Check if port forwards are allowed based on link settings
     */
    fun allowsPortForwards(): Boolean = getBooleanValue("portForwards", checkAllowedSettings = true)
    
    /**
     * Check if session recording is enabled
     */
    fun allowsSessionRecording(): Boolean = getBooleanValue("sessionRecording", checkAllowedSettings = true)
    
    /**
     * Check if TypeScript recording is enabled
     */
    fun allowsTypescriptRecording(): Boolean = getBooleanValue("typescriptRecording", checkAllowedSettings = true)
    
    /**
     * Check if remote browser isolation is enabled
     */
    fun allowsRemoteBrowserIsolation(): Boolean = getBooleanValue("remoteBrowserIsolation", checkAllowedSettings = true)
    
    /**
     * Check if rotation on termination is enabled
     */
    fun rotatesOnTermination(): Boolean = getBooleanValue("rotateOnTermination")

    /**
     * Whether the linked user is an IAM user (`is_iam_user`).
     */
    fun isIamUser(): Boolean = getBooleanValue("is_iam_user")

    /**
     * Whether the linked credential belongs to the record (`belongs_to`).
     */
    fun belongsTo(): Boolean = getBooleanValue("belongs_to")

    /**
     * Whether service updates are disabled for this link (`no_update_services`).
     */
    fun noUpdateServices(): Boolean = getBooleanValue("no_update_services")

    /**
     * Whether AI features are enabled (`aiEnabled`, top-level or in `allowedSettings`).
     */
    fun aiEnabled(): Boolean = getBooleanValue("aiEnabled", checkAllowedSettings = true)

    /**
     * Whether AI session termination is enabled (`aiSessionTerminate`, top-level or in `allowedSettings`).
     */
    fun aiSessionTerminate(): Boolean = getBooleanValue("aiSessionTerminate", checkAllowedSettings = true)

    /**
     * The `allowedSettings` object from the link data (empty map when absent).
     */
    fun getAllowedSettings(): Map<String, Any?> {
        val parsed = parseJsonData() ?: return emptyMap()
        @Suppress("UNCHECKED_CAST")
        return (parsed["allowedSettings"] as? Map<String, Any?>) ?: emptyMap()
    }

    /**
     * The `rotation_settings` object from the link data (schedule, pwd_complexity, disabled, noop,
     * saas_record_uid_list), or null when absent.
     */
    fun getRotationSettings(): Map<String, Any?>? {
        val parsed = parseJsonData() ?: return null
        @Suppress("UNCHECKED_CAST")
        return parsed["rotation_settings"] as? Map<String, Any?>
    }
    
    /**
     * Get the link data version (if available)
     */
    fun getLinkDataVersion(): Int? = getIntValue("version")
    
    /**
     * Get the decoded JSON data as a string (for debugging/advanced use)
     */
    fun getDecodedData(): String? {
        if (data == null) return null
        return try {
            String(java.util.Base64.getDecoder().decode(data))
        } catch (e: Exception) {
            System.err.println("KeeperRecordLink: Failed to decode Base64 data - ${e.message}")
            null
        }
    }
    
    /**
     * Check if the link has readable JSON data (vs. encrypted/binary data)
     */
    fun hasReadableData(): Boolean {
        val decoded = getDecodedData()
        return decoded != null && (decoded.startsWith("{") || decoded.startsWith("["))
    }

    /**
     * Check if this link's path indicates potentially encrypted data
     * Currently known encrypted paths: ai_settings, jit_settings
     * @return true if the path is known to potentially contain encrypted data
     */
    fun mightBeEncrypted(): Boolean {
        // Only return true for known encrypted paths
        // Don't assume all *_settings are encrypted
        return path != null && (path == "ai_settings" || path == "jit_settings")
    }
    
    /**
     * Check if this link contains encrypted data by examining the actual content, rather than
     * relying on path naming conventions (see [mightBeEncrypted]).
     * @return true if the data appears to be encrypted
     */
    fun hasEncryptedData(): Boolean {
        if (data == null) return false
        
        return try {
            val decodedData = String(java.util.Base64.getDecoder().decode(data))
            // If it doesn't start with JSON markers and isn't mostly printable, it's likely encrypted
            !decodedData.startsWith("{") && !decodedData.startsWith("[") && !isPrintableText(decodedData)
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Decrypt the link data using the provided record key.
     *
     * @param recordKey The record's encryption key
     * @return Decrypted string data, or null if decryption fails
     */
    @JvmOverloads
    fun getDecryptedData(recordKey: ByteArray? = null): String? {
        if (data == null || recordKey == null) return null
        
        return try {
            // Decode Base64 to get encrypted bytes
            val encryptedData = java.util.Base64.getDecoder().decode(data)
            
            // Decrypt using AES-256-GCM (false = use GCM mode)
            val decryptedBytes = decrypt(encryptedData, recordKey, false)
            
            // Convert to string
            String(decryptedBytes, Charsets.UTF_8)
        } catch (e: Exception) {
            // Decryption failed - could be wrong key or not encrypted
            null
        }
    }
    
    /**
     * Get link data - automatically handles both encrypted and plain JSON.
     *
     * Forward-compatible as Keeper evolves the data structures: returns a Map to preserve all
     * fields, even ones this SDK version doesn't know about yet.
     *
     * @param recordKey Optional key for decrypting encrypted link data
     * @return Parsed data as a Map, or null if parsing fails
     */
    @JvmOverloads
    fun getLinkData(recordKey: ByteArray? = null): Map<String, Any?>? {
        if (data == null) return null
        
        // First, try to decode and check if it's plain JSON
        val decodedData = try {
            String(java.util.Base64.getDecoder().decode(data))
        } catch (e: Exception) {
            return null
        }
        
        // If it looks like JSON, parse it directly; if that fails (coincidental ciphertext that
        // happens to start with { or [), fall through to decryption rather than giving up.
        if (decodedData.startsWith("{") || decodedData.startsWith("[")) {
            parseJsonToMap(decodedData)?.let { return it }
        }
        
        // If not JSON and we have a key, try decryption
        if (recordKey != null) {
            val decryptedData = getDecryptedData(recordKey) ?: return null
            return parseJsonToMap(decryptedData)
        }
        
        // Can't parse - not JSON and no key for decryption
        return null
    }
    
    /**
     * Helper method to parse JSON string to Map
     */
    private fun parseJsonToMap(jsonString: String): Map<String, Any?>? {
        return try {
            val jsonElement = Json.parseToJsonElement(jsonString)
            when (jsonElement) {
                is JsonObject -> jsonObjectToMap(jsonElement)
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Helper method to check if a string is mostly printable text
     */
    private fun isPrintableText(str: String): Boolean {
        if (str.isEmpty()) return false
        
        val printableCount = str.take(100).count { c ->
            c in ' '..'~' || c == '\n' || c == '\r' || c == '\t'
        }
        
        val sampleSize = minOf(str.length, 100)
        return (printableCount.toFloat() / sampleSize) > 0.9f
    }

    /**
     * Get AI settings data from this link
     * 
     * Encrypted under the owning record's key. Known fields (live-verified):
     * - version: String - settings schema version, e.g. "v1.0.0"
     * - riskLevels: Map - critical/high/medium/low, each with `tags` (allow/deny lists)
     *   and `aiSessionTerminate`
     * 
     * Note: Additional fields may be present in newer versions.
     * The returned Map will preserve all fields sent by the server.
     * 
     * @param recordKey The record's encryption key
     * @return Settings data as a Map, or null if not available
     */
    fun getAiSettingsData(recordKey: ByteArray): Map<String, Any?>? {
        if (path != "ai_settings") return null
        return getLinkData(recordKey)
    }
    
    /**
     * Get JIT (Just-In-Time) settings data from this link
     * 
     * Encrypted under the owning record's key. Known fields (live-verified):
     * - createEphemeral: Boolean
     * - elevate: Boolean
     * - elevationMethod: String
     * - elevationString: String
     * - baseDistinguishedName: String
     * 
     * Note: Additional fields may be present in newer versions.
     * The returned Map will preserve all fields sent by the server.
     * 
     * @param recordKey The record's encryption key
     * @return Settings data as a Map, or null if not available
     */
    fun getJitSettingsData(recordKey: ByteArray): Map<String, Any?>? {
        if (path != "jit_settings") return null
        return getLinkData(recordKey)
    }
    
    /**
     * Get settings data for any current or future settings path.
     *
     * @param settingsPath The path to check (e.g., "ai_settings", "security_settings")
     * @param recordKey The record's encryption key (required for encrypted data)
     * @return Settings data as a Map, or null if path doesn't match or parsing fails
     */
    @JvmOverloads
    fun getSettingsForPath(settingsPath: String, recordKey: ByteArray? = null): Map<String, Any?>? {
        if (path != settingsPath) return null
        return getLinkData(recordKey)
    }

    /**
     * Get PAM settings data from this link; only valid when [path] == "meta".
     *
     * Meta links are self-links (recordUid == owning record) carrying the record's own PAM settings:
     * `allowedSettings`, `rotateOnTermination`, `version`, `no_update_services`. Plain JSON today;
     * the key is accepted for forward compatibility.
     */
    @JvmOverloads
    fun getMetaData(recordKey: ByteArray? = null): Map<String, Any?>? = getSettingsForPath("meta", recordKey)
}

@Serializable
private data class SecretsManagerResponseFile(
    val fileUid: String,
    val fileKey: String,
    val data: String,
    val url: String?, // server may omit url; nullable prevents NPE on deserialization
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

@Serializable
data class SecretsManagerDeleteResponse(
    val records: List<SecretsManagerDeleteResponseRecord> = emptyList()
)

@Serializable
data class SecretsManagerDeleteResponseRecord(
    val errorMessage: String? = null,
    val recordUid: String,
    val responseCode: String
) {
    var folderUid: String? = null
}

@Serializable
data class SecretsManagerDeleteFolderResponseRecord(
    val errorMessage: String? = null,
    val folderUid: String,
    val responseCode: String
)

@Serializable
data class SecretsManagerDeleteFolderResponse(
    val folders: List<SecretsManagerDeleteFolderResponseRecord> = emptyList()
)

@Serializable
private data class SecretsManagerAddFileResponse(
    val url: String,
    val parameters: String,
    val successStatusCode: Int
)

data class KeeperSecrets(val appData: AppData, val records: List<KeeperRecord>, val expiresOn: Instant? = null, val warnings: List<String>? = null) {
    var folders: List<KeeperFolder> = emptyList()
        internal set
    internal var listedFolderUids: Set<String> = emptySet()
    internal var driveFolderUids: Set<String> = emptySet()

    fun getRecordByUid(recordUid: String): KeeperRecord? {
        return records.find { it.recordUid == recordUid }
    }

    fun getSecretsByTitle(recordTitle: String): List<KeeperRecord> {
        return records.filter { it.data.title == recordTitle }
    }

    fun getSecretByTitle(recordTitle: String): KeeperRecord? {
        return records.find { it.data.title == recordTitle }
    }
}

@Serializable
data class AppData(val title: String, val type: String)

data class KeeperRecord @JvmOverloads constructor(
    val recordKey: ByteArray,
    val recordUid: String,
    var folderUid: String? = null,
    var folderKey: ByteArray? = null,
    var innerFolderUid: String? = null,
    val data: KeeperRecordData,
    val revision: Long,
    val files: List<KeeperFile>? = null,
    val links: List<KeeperRecordLink>? = null,
    // Appended rather than inserted: Java sees no default arguments, so an interior
    // parameter would shift the constructor Java callers already compile against.
    /**
     * Write permission for this record, set by the backend from how the application's share was
     * configured: `true` when the application may call [updateSecret] on it, `false` when the
     * share is read-only. Informational only; the SDK does not enforce it before an update.
     *
     * The default applies only to direct construction. Records returned by [getSecrets] always
     * carry the server's value, because the field is required in the response envelope.
     */
    val isEditable: Boolean = false
) {
    /**
     * The SDK sets this property on records that it reads from NSF folders.
     * The default is `false`. [copy] does not retain this property.
     */
    @set:JvmSynthetic
    var isDrive: Boolean = false
        internal set

    fun getPassword(): String? {
        val passwordField = data.getField<Password>() ?: return null
        return if (passwordField.value.size > 0) passwordField.value[0] else null
    }

    fun getTitle(): String {
        return data.title
    }

    fun getType(): String {
        return data.type
    }

    fun updatePassword(newPassword: String) {
        val passwordField = data.getField<Password>() ?: throw SecretsManagerException("Password field is not present on the record $recordUid")

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

data class KeeperFolder(
    val folderKey: ByteArray,
    val folderUid: String,
    val parentUid: String? = null,
    val name: String,
    val useGcm: Boolean = false,
    val isDrive: Boolean = false
) {
    internal var data: JsonObject? = null

    // Keep the JVM signatures for callers compiled against earlier versions.
    constructor(
        folderKey: ByteArray,
        folderUid: String,
        parentUid: String? = null,
        name: String
    ) : this(folderKey, folderUid, parentUid, name, false, false)

    constructor(
        folderKey: ByteArray,
        folderUid: String,
        parentUid: String? = null,
        name: String,
        useGcm: Boolean = false
    ) : this(folderKey, folderUid, parentUid, name, useGcm, false)

    fun copy(
        folderKey: ByteArray = this.folderKey,
        folderUid: String = this.folderUid,
        parentUid: String? = this.parentUid,
        name: String = this.name
    ): KeeperFolder = copy(folderKey, folderUid, parentUid, name, useGcm)

    fun copy(
        folderKey: ByteArray = this.folderKey,
        folderUid: String = this.folderUid,
        parentUid: String? = this.parentUid,
        name: String = this.name,
        useGcm: Boolean = this.useGcm
    ): KeeperFolder = copy(folderKey, folderUid, parentUid, name, useGcm, isDrive).also {
        if (folderUid == this.folderUid && folderKey.contentEquals(this.folderKey) &&
            parentUid == this.parentUid && useGcm == this.useGcm) {
            it.data = data
        }
    }
}

@Serializable
data class KeeperFolderName(
    val name: String
)

data class KeeperFile(
    val fileKey: ByteArray,
    val fileUid: String,
    val data: KeeperFileData,
    val url: String?, // nullable; server may omit url for files without a download URL
    val thumbnailUrl: String?
)

data class KeeperFileUpload(
    val name: String,
    val title: String,
    val type: String?,
    val data: ByteArray
)

@JvmOverloads
fun initializeStorage(storage: KeyValueStorage, oneTimeToken: String, hostName: String? = null) {
    val tokenParts = oneTimeToken.split(':')
    val host: String
    val clientKey: String
    if (tokenParts.size == 1) {
        host = hostName ?: throw SecretsManagerException("The hostname must be present in the token or as a parameter")
        clientKey = oneTimeToken
    } else {
        host = when (tokenParts[0].uppercase(Locale.US)) {
            "US" -> "keepersecurity.com"
            "EU" -> "keepersecurity.eu"
            "AU" -> "keepersecurity.com.au"
            "GOV" -> "govcloud.keepersecurity.us"
            "JP" -> "keepersecurity.jp"
            "CA" -> "keepersecurity.ca"
            "IL5" -> "il5.keepersecurity.us"
            else -> tokenParts[0]
        }
        clientKey = tokenParts[1]
        // Layer 2: extended OTT format REGION:clientKey:keyId:serverPublicKey
        when (tokenParts.size) {
            2 -> {} // plain REGION:clientKey
            4 -> {
                val keyId = tokenParts[2]
                if (keyId.isEmpty() || !keyId.all { it.isDigit() }) {
                    throw SecretsManagerException("Extended OTT token: serverPublicKeyId '$keyId' must be a positive integer")
                }
                if (tokenParts[3].length < 80) {
                    throw SecretsManagerException("Extended OTT token: serverPublicKey appears malformed")
                }
                storage.saveString(KEY_SERVER_PUBLIC_KEY_ID, keyId)
                storage.saveString(KEY_SERVER_PUBLIC_KEY, tokenParts[3])
            }
            else -> throw SecretsManagerException("Extended OTT token has unexpected segment count (${tokenParts.size} parts, expected 2 or 4)")
        }
    }
    val clientKeyBytes = webSafe64ToBytes(clientKey)
    val clientKeyHash = hash(clientKeyBytes, CLIENT_ID_HASH_TAG)
    val clientId = bytesToBase64(clientKeyHash)
    val existingClientId = storage.getString(KEY_CLIENT_ID)
    if (existingClientId != null) {
        if (clientId == existingClientId) {
            return   // the storage is already initialized
        }
        throw SecretsManagerException("The storage is already initialized with a different client Id (${existingClientId})")
    }
    storage.saveString(KEY_HOSTNAME, host)
    storage.saveString(KEY_CLIENT_ID, clientId)
    storage.saveBytes(KEY_CLIENT_KEY, clientKeyBytes)
    val keyPair = generateKeyPair()
    storage.saveBytes(KEY_PRIVATE_KEY, keyPair.private.encoded) // private key is stored in DER, to be compatible with other SDK's
    storage.saveBytes(KEY_PUBLIC_KEY, extractPublicRaw(keyPair.public)) // public key stored raw
}

private const val FAST_SECURE_RANDOM_PREFIX = "Fast SecureRandom detected! "
private const val SLOW_SECURE_RANDOM_PREFIX = "Slow SecureRandom detected! "
private const val SLOW_SECURE_RANDOM_MESSAGE = " Install one of the following entropy sources to improve speed of random number generator on your platform: 'haveged' or 'rng-tools'"
private var SecureRandomTestResult = ""

private fun testSecureRandom() {
    if (SecureRandomTestResult.isNotBlank()) {
        if (SecureRandomTestResult.startsWith(SLOW_SECURE_RANDOM_PREFIX)) {
            println(SecureRandomTestResult)
        }
        return
    }
    val es = Executors.newSingleThreadExecutor()
    val future = es.submit(Callable {
        // on some Linux machines the default secure random provider is blocking
        // and waiting too long for entropy to accumulate.
        val secureRandom = SecureRandom.getInstanceStrong()
        secureRandom.nextInt() // could block for many seconds
        true
    })

    try {
        future.get(3, TimeUnit.SECONDS)
        SecureRandomTestResult = FAST_SECURE_RANDOM_PREFIX
    } catch (e: TimeoutException) {
        SecureRandomTestResult = SLOW_SECURE_RANDOM_PREFIX + SLOW_SECURE_RANDOM_MESSAGE
        println(SecureRandomTestResult)
        future.cancel(true)
        throw SecureRandomSlowGenerationException(SecureRandomTestResult)
    } catch (e: InterruptedException) {
        throw SecureRandomException(e.message ?: e.localizedMessage)
    } catch (e: ExecutionException) {
        throw SecureRandomException(e.message ?: e.localizedMessage)
    } catch (e: Exception) {
        throw SecureRandomException(e.message ?: e.localizedMessage)
    }

    es.shutdown()
}

@ExperimentalSerializationApi
@JvmOverloads
fun getSecrets(options: SecretsManagerOptions, recordsFilter: List<String> = emptyList()): KeeperSecrets {
    val queryOptions = QueryOptions(recordsFilter)
    val (secrets, justBound) = fetchAndDecryptSecrets(options, queryOptions)
    if (justBound) {
        try {
            fetchAndDecryptSecrets(options, queryOptions)
        } catch (e: Exception) {
            if (options.loggingEnabled) {
                println(e)
            }
        }
    }
    return secrets
}

@ExperimentalSerializationApi
@JvmOverloads
fun getSecrets2(options: SecretsManagerOptions, queryOptions: QueryOptions? = null): KeeperSecrets {
    val (secrets, justBound) = fetchAndDecryptSecrets(options, queryOptions)
    if (justBound) {
        try {
            fetchAndDecryptSecrets(options, queryOptions)
        } catch (e: Exception) {
            if (options.loggingEnabled) {
                println(e)
            }
        }
    }
    return secrets
}

@ExperimentalSerializationApi
@JvmOverloads
fun getFolders(options: SecretsManagerOptions, includeNsf: Boolean = false): List<KeeperFolder> {
    val folders = fetchAndDecryptFolders(options)
    if (!includeNsf) {
        return folders
    }
    return withDriveFolders(folders, getSecrets(options).folders)
}

// tryGetNotationResults returns a string list with all values specified by the notation or empty list on error.
// It simply logs any errors and continue returning an empty string list on error.
@ExperimentalSerializationApi
fun tryGetNotationResults(options: SecretsManagerOptions, notation: String): List<String> {
    try {
        return getNotationResults(options, notation)
    } catch (e: Exception) {
        if (options.loggingEnabled) {
            println(e.message)
        }
    }
    return emptyList()
}

// Notation:
// keeper://<uid|title>/<field|custom_field>/<type|label>[INDEX][PROPERTY]
// keeper://<uid|title>/file/<filename|fileUID>
// Record title, field label, filename sections need to escape the delimiters /[]\ -> \/ \[ \] \\
//
// GetNotationResults returns selection of the value(s) from a single field as a string list.
// Multiple records or multiple fields found results in error.
// Use record UID or unique record titles and field labels so that notation finds a single record/field.
//
// If field has multiple values use indexes - numeric INDEX specifies the position in the value list
// and PROPERTY specifies a single JSON object property to extract (see examples below for usage)
// If no indexes are provided - whole value list is returned (same as [])
// If PROPERTY is provided then INDEX must be provided too - even if it's empty [] which means all
//
// Extracting two or more but not all field values simultaneously is not supported - use multiple notation requests.
//
// Files are returned as URL safe base64 encoded string of the binary content
//
// Note: Integrations and plugins usually return single string value - result[0] or ""
//
// Examples:
//  RECORD_UID/file/filename.ext             => ["URL Safe Base64 encoded binary content"]
//  RECORD_UID/field/url                     => ["127.0.0.1", "127.0.0.2"] or [] if empty
//  RECORD_UID/field/url[]                   => ["127.0.0.1", "127.0.0.2"] or [] if empty
//  RECORD_UID/field/url[0]                  => ["127.0.0.1"] or error if empty
//  RECORD_UID/custom_field/name[first]      => Error, numeric index is required to access field property
//  RECORD_UID/custom_field/name[][last]     => ["Smith", "Johnson"]
//  RECORD_UID/custom_field/name[0][last]    => ["Smith"]
//  RECORD_UID/custom_field/phone[0][number] => "555-5555555"
//  RECORD_UID/custom_field/phone[1][number] => "777-7777777"
//  RECORD_UID/custom_field/phone[]          => ["{\"number\": \"555-555...\"}", "{\"number\": \"777...\"}"]
//  RECORD_UID/custom_field/phone[0]         => ["{\"number\": \"555-555...\"}"]

// GetNotationResults returns a string list with all values specified by the notation or throws an error.
// Use TryGetNotationResults to just log errors and continue returning an empty string list on error.
@ExperimentalSerializationApi
fun getNotationResults(options: SecretsManagerOptions, notation: String): List<String> {
    val result = mutableListOf<String>()

    val parsedNotation = parseNotation(notation) // prefix, record, selector, footer
    if (parsedNotation.size < 3)
        throw SecretsManagerException("Invalid notation '$notation'")

    val selector = parsedNotation[2].text?.first ?: // type|title|notes or file|field|custom_field
        throw SecretsManagerException("Invalid notation '$notation'")
    val recordToken = parsedNotation[1].text?.first ?: // UID or Title
        throw SecretsManagerException("Invalid notation '$notation'")

    // to minimize traffic - if it looks like a Record UID try to pull a single record
    var records = listOf<KeeperRecord>()
    if (recordToken.matches(Regex("""^[A-Za-z0-9_-]{22}$"""))) {
        val secrets = getSecrets(options, listOf<String>(recordToken))
        records = secrets.records
        // Remove duplicate UIDs - shortcuts/linked records both shared to same KSM App
        if (records.size > 1) {
            records = records.distinctBy { it.recordUid }
        }
    }

    // If RecordUID is not found - pull all records and search by title
    if (records.isEmpty()) {
        val secrets = getSecrets(options)
        records = secrets.records.filter { it.data.title == recordToken }
    }

    if (records.size > 1)
        throw SecretsManagerException("Notation error - multiple records match record '$recordToken'")
    if (records.isEmpty())
        throw SecretsManagerException("Notation error - no records match record '$recordToken'")

    val record = records[0]
    val parameter = parsedNotation[2].parameter?.first
    val index1 = parsedNotation[2].index1?.first
    //val index2 = parsedNotation[2].index2?.first

    when (selector.lowercase()) {
        "type" -> result.add(record.data.type)
        "title" -> result.add(record.data.title)
        "notes" -> if (record.data.notes != null) result.add(record.data.notes!!)
        "file" -> {
            if (parameter == null)
                throw SecretsManagerException("Notation error - Missing required parameter: filename or file UID for files in record '$recordToken'")
            if ((record.files?.size ?: 0) < 1)
                throw SecretsManagerException("Notation error - Record $recordToken has no file attachments.")
            val files = record.files!!.filter { parameter == it.data.name || parameter == it.data.title || parameter == it.fileUid }
            // file searches do not use indexes and rely on unique file names or fileUid
            if (files.size > 1)
                throw SecretsManagerException("Notation error - Record $recordToken has multiple files matching the search criteria '$parameter'")
            if (files.isEmpty())
                throw SecretsManagerException("Notation error - Record $recordToken has no files matching the search criteria '$parameter'")
            val contents = downloadFile(options, files[0])
            val text = webSafe64FromBytes(contents)
            result.add(text)
        }
        "field", "custom_field" -> {
            if (parameter == null)
                throw SecretsManagerException("Notation error - Missing required parameter for the field (type or label): ex. /field/type or /custom_field/MyLabel")

            val fields = when(selector.lowercase()) {
                "field" -> record.data.fields
                "custom_field" -> record.data.custom
                else -> throw SecretsManagerException("Notation error - Expected /field or /custom_field but found /$selector")
            }

            val flds = fields.filter { parameter == fieldType(it) || parameter == it.label }
            if (flds.size > 1)
                throw SecretsManagerException("Notation error - Record $recordToken has multiple fields matching the search criteria '$parameter'")
            if (flds.isEmpty())
                throw SecretsManagerException("Notation error - Record $recordToken has no fields matching the search criteria '$parameter'")
            val field = flds[0]
            //val fieldType = fieldType(field)

            val idx = index1?.toIntOrNull() ?: -1 // -1 full value
            // valid only if [] or missing - ex. /field/phone or /field/phone[]
            if (idx == -1 && !(parsedNotation[2].index1?.second.isNullOrEmpty() || parsedNotation[2].index1?.second == "[]"))
                throw SecretsManagerException("Notation error - Invalid field index $idx")

            val valuesCount = getFieldValuesCount(field)
            if (idx >= valuesCount)
                throw SecretsManagerException("Notation error - Field index out of bounds $idx >= $valuesCount for field $parameter")

            //val fullObjValue = (parsedNotation[2].index2?.second.isNullOrEmpty() || parsedNotation[2].index2?.second == "[]")
            // An empty property index selects the whole value: /url[0][] is the same as /url[0]
            val objPropertyName = parsedNotation[2].index2?.first?.takeIf { it.isNotEmpty() }

            val res = getFieldStringValues(field, idx, objPropertyName)
            val expectedSize = if (idx >= 0) 1 else valuesCount
            if (res.size != expectedSize && options.loggingEnabled)
                println("Notation warning - extracted ${res.size} out of $valuesCount values for '$objPropertyName' property.")
            if (res.isNotEmpty())
                result.addAll(res)
        }
        else -> throw SecretsManagerException("Invalid notation '$notation'")
    }
    return result
}

/**
 * Deletes the records with the specified UIDs.
 *
 * The result has one item for each record that the server matched. The server returns no item for a UID
 * that is not shared with the application, does not exist, or is already in the trash. A UID with no item
 * was not deleted by this request, and an empty result does not confirm a deletion. Compare the result
 * with the requested UIDs. When logging is on, the SDK writes each UID with no item to standard error.
 */
@ExperimentalSerializationApi
fun deleteSecret(options: SecretsManagerOptions, recordUids: List<String>): SecretsManagerDeleteResponse {
    val payload = prepareDeletePayload(options.storage, recordUids)
    val responseData = postQuery(options, "delete_secret", payload)
    val response = decodeDeleteResponse(responseData, SecretsManagerDeleteResponse())
    for (r in response.records) {
        if (r.responseCode != "ok" && options.loggingEnabled) {
            val folder = r.folderUid?.let { " in folder $it" } ?: ""
            System.err.println("Failed to delete record ${r.recordUid}$folder: ${r.responseCode} ${r.errorMessage ?: ""}")
        }
    }
    logMissingDeleteResults(options, "record", recordUids, response.records.map { it.recordUid })
    return response
}

/**
 * Deletes the classic subfolders with the specified UIDs.
 *
 * The SDK refuses a classic root folder, an NSF (Keeper Drive) folder, and an unknown folder before it sends
 * the request. It returns `access_denied` or `doesnt_exist` for each of these UIDs. Neither result confirms
 * a deletion. A UID with no item in the result was not confirmed as deleted. Compare the result with the
 * requested UIDs. When logging is on, the SDK writes each UID with no item to standard error.
 */
@ExperimentalSerializationApi
fun deleteFolder(options: SecretsManagerOptions, folderUids: List<String>, forceDeletion: Boolean = false): SecretsManagerDeleteFolderResponse {
    val requestedUids = folderUids.toList()
    val response = if (requestedUids.isEmpty()) {
        postDeleteFolders(options, requestedUids, forceDeletion)
    } else {
        val (rawResponse, appKey) = fetchFoldersResponse(options)
        val paths = readFolderRoots(rawResponse, requestedUids.toSet())
        val roots = requestedUids.mapNotNull { paths[it] }.toSet()
        val ambiguousRoots = roots - readCbcFolderRoots(rawResponse, appKey, roots)
        val types = fetchFolderTypes(options, ambiguousRoots)
        val unconfirmedRoots = ambiguousRoots.filterTo(mutableSetOf()) { types[it] != FolderType.CLASSIC }
        val allowed = requestedUids.filter { uid ->
            val root = paths[uid]
            root != null && root != uid && root !in unconfirmedRoots
        }
        if (allowed.size == requestedUids.size) {
            postDeleteFolders(options, requestedUids, forceDeletion)
        } else {
            val allowedUids = allowed.toSet()
            val localItems = requestedUids.distinct().filter { it !in allowedUids }.associateWith { uid ->
                if (paths[uid] == uid && uid !in unconfirmedRoots) {
                    SecretsManagerDeleteFolderResponseRecord(
                        "Folder [$uid] is a shared folder and cannot be deleted", uid, "access_denied"
                    )
                } else {
                    SecretsManagerDeleteFolderResponseRecord(
                        "Folder [$uid] is either not associated with this device, has already been deleted, or is an NSF (Keeper Drive) folder.",
                        uid, "doesnt_exist"
                    )
                }
            }
            val serverItems = if (allowed.isEmpty()) emptyList() else
                postDeleteFolders(options, allowed, forceDeletion).folders
            val firstItems = serverItems.withIndex().groupBy { it.value.folderUid }
            val placed = mutableSetOf<Int>()
            val results = requestedUids.distinct().mapNotNull { uid ->
                localItems[uid] ?: firstItems[uid]?.first()?.let {
                    placed.add(it.index)
                    it.value
                }
            } + serverItems.filterIndexed { index, _ -> index !in placed }
            SecretsManagerDeleteFolderResponse(results)
        }
    }
    for (f in response.folders) {
        if (f.responseCode != "ok" && options.loggingEnabled) {
            System.err.println("Failed to delete folder ${f.folderUid}: ${f.responseCode} ${f.errorMessage ?: ""}")
        }
    }
    logMissingDeleteResults(options, "folder", requestedUids, response.folders.map { it.folderUid })
    return response
}

private fun logMissingDeleteResults(
    options: SecretsManagerOptions,
    kind: String,
    requestedUids: List<String>,
    resultUids: List<String>
) {
    if (!options.loggingEnabled) return
    val answered = resultUids.toSet()
    for (uid in requestedUids.distinct()) {
        if (uid !in answered) {
            System.err.println("No delete result for $kind $uid. The server did not confirm the deletion.")
        }
    }
}

@ExperimentalSerializationApi
private fun postDeleteFolders(
    options: SecretsManagerOptions,
    folderUids: List<String>,
    forceDeletion: Boolean
): SecretsManagerDeleteFolderResponse {
    val payload = prepareDeleteFolderPayload(options.storage, folderUids, forceDeletion)
    val responseData = postQuery(options, "delete_folder", payload)
    return decodeDeleteResponse(responseData, SecretsManagerDeleteFolderResponse())
}

@ExperimentalSerializationApi
private inline fun <reified T> decodeDeleteResponse(responseData: ByteArray, emptyResponse: T): T {
    if (responseData.isEmpty()) return emptyResponse
    val response = nonStrictJson.parseToJsonElement(bytesToString(responseData))
    return if (response is JsonObject) nonStrictJson.decodeFromJsonElement(response) else emptyResponse
}

@ExperimentalSerializationApi
fun updateSecret(options: SecretsManagerOptions, record: KeeperRecord, transactionType: UpdateTransactionType? = null) {
    updateSecretWithOptions(options, record, UpdateOptions(transactionType, null))
}

@ExperimentalSerializationApi
fun updateSecretWithOptions(options: SecretsManagerOptions, record: KeeperRecord, updateOptions: UpdateOptions? = null) {
    val payload = prepareUpdatePayload(options.storage, record, updateOptions)
    postQuery(options, "update_secret", payload)
}

@ExperimentalSerializationApi
fun completeTransaction(options: SecretsManagerOptions, recordUid: String, rollback: Boolean = false) {
    val payload = prepareCompleteTransactionPayload(options.storage, recordUid)
    val path = if (rollback) "rollback_secret_update" else "finalize_secret_update"
    postQuery(options, path, payload)
}

@ExperimentalSerializationApi
fun addCustomField(record: KeeperRecord, field: KeeperRecordField) {
    if (field.javaClass.superclass == KeeperRecordField::class.java) {
        record.data.custom.add(field)
    }
}

@ExperimentalSerializationApi
@JvmOverloads
fun createSecret(
    options: SecretsManagerOptions,
    folderUid: String,
    recordData: KeeperRecordData,
    secrets: KeeperSecrets = getSecretsForRecordCreate(options, folderUid)
): String {
    val availableSecrets = if (folderUid in secrets.listedFolderUids || secrets.folders.any { it.folderUid == folderUid }) {
        secrets
    } else {
        getSecretsForRecordCreate(options, folderUid)
    }
    val folder = withDriveFolders(availableSecrets.folders, availableSecrets.folders).find { it.folderUid == folderUid }
    if (folder == null || folder.folderKey.isEmpty() || (!folder.isDrive && folderUid in availableSecrets.driveFolderUids)) {
        throw folderKeyNotFound("create record", folderUid)
    }
    val payload = prepareCreatePayload(
        options.storage, CreateOptions(folderUid), recordData, folder.folderKey, folder.isDrive
    )
    postQuery(options, "create_secret", payload)
    return payload.recordUid
}

@ExperimentalSerializationApi
@JvmOverloads
fun createSecret2(options: SecretsManagerOptions, createOptions: CreateOptions, recordData: KeeperRecordData, folders: List<KeeperFolder> = getFolders(options)): String {
    val available = getFoldersForWrite(options, folders, listOf(createOptions.folderUid, createOptions.subFolderUid))
    val targetUid = createOptions.subFolderUid?.takeIf { it.isNotEmpty() } ?: createOptions.folderUid
    val target = available.find { it.folderUid == targetUid }
    val sharedFolder = available.find { it.folderUid == createOptions.folderUid }
    val isDrive = target?.isDrive == true
    val folderKey = if (isDrive) {
        target!!.folderKey
    } else {
        if (sharedFolder?.isDrive == true) {
            throw folderKeyNotFound("create record", targetUid)
        }
        sharedFolder?.folderKey ?: throw folderKeyNotFound("create record", createOptions.folderUid)
    }
    if (folderKey.isEmpty()) {
        throw folderKeyNotFound("create record", if (isDrive) targetUid else createOptions.folderUid)
    }
    val payload = prepareCreatePayload(options.storage, createOptions, recordData, folderKey, isDrive)
    postQuery(options, "create_secret", payload)
    return payload.recordUid
}

private class FolderCreateLookup(
    folders: List<KeeperFolder>,
    val parents: Map<String, List<String?>>
) : List<KeeperFolder> by folders

@ExperimentalSerializationApi
private fun getFoldersForCreate(options: SecretsManagerOptions): FolderCreateLookup {
    val (response, appKey) = fetchFoldersResponse(options)
    // Keep parent links for folders with unreadable names or keys.
    return FolderCreateLookup(decryptFolders(options, response, appKey), readFolderParentLinks(response))
}

@ExperimentalSerializationApi
@JvmOverloads
fun createFolder(options: SecretsManagerOptions, createOptions: CreateOptions, folderName: String, folders: List<KeeperFolder> = getFoldersForCreate(options)): String {
    val sharedFolderUid = createOptions.folderUid
    if (sharedFolderUid.isBlank()) {
        throw SecretsManagerException("Unable to create folder - shared folder UID must not be empty")
    }
    val targetUid = createOptions.subFolderUid?.takeIf { it.isNotEmpty() } ?: sharedFolderUid
    val driveUids = folders.filter { it.isDrive }.map { it.folderUid }.toSet()
    if (sharedFolderUid in driveUids || targetUid in driveUids) {
        throw SecretsManagerException(DRIVE_FOLDER_CREATE_REFUSED)
    }
    var sharedFolder = requireCreateFolderRoot(folders, sharedFolderUid)
    val parents = if (folders is FolderCreateLookup) folders.parents
        else folders.groupBy({ it.folderUid }, { it.parentUid.orEmpty() })
    if (parents[sharedFolderUid]?.any { !it.isNullOrEmpty() } == true) {
        throw SecretsManagerException("Unable to create folder - folder $sharedFolderUid is not a shared root")
    }
    if (!hasClassicFolderPath(parents, driveUids, targetUid, sharedFolderUid)) {
        if (folders is FolderCreateLookup) {
            throw invalidCreateFolderParent(targetUid, sharedFolderUid)
        }
        val current = getFoldersForCreate(options)
        if (!hasClassicFolderPath(current.parents, driveUids, targetUid, sharedFolderUid)) {
            throw invalidCreateFolderParent(targetUid, sharedFolderUid)
        }
        sharedFolder = requireCreateFolderRoot(current, sharedFolderUid)
    }
    if (sharedFolder.useGcm) {
        when (fetchFolderTypes(options, setOf(sharedFolderUid))[sharedFolderUid]) {
            FolderType.CLASSIC -> Unit
            FolderType.DRIVE -> throw SecretsManagerException(DRIVE_FOLDER_CREATE_REFUSED)
            null -> throw invalidCreateFolderParent(targetUid, sharedFolderUid)
        }
    }
    val payload = prepareCreateFolderPayload(options.storage, createOptions, folderName, sharedFolder.folderKey)
    postQuery(options, "create_folder", payload)
    return payload.folderUid
}

private fun requireCreateFolderRoot(folders: List<KeeperFolder>, uid: String): KeeperFolder {
    val matches = folders.filter { it.folderUid == uid }
    val root = matches.firstOrNull()?.takeIf { it.folderKey.isNotEmpty() }
        ?: throw SecretsManagerException("Unable to create folder - folder key for $uid not found")
    if (matches.any { it.useGcm != root.useGcm || !it.folderKey.contentEquals(root.folderKey) }) {
        throw SecretsManagerException("Unable to create folder - inconsistent folder data for $uid")
    }
    return root
}

private fun invalidCreateFolderParent(targetUid: String, sharedFolderUid: String): SecretsManagerException =
    SecretsManagerException("Unable to create folder - parent $targetUid is not a verified classic folder under shared folder $sharedFolderUid")

private fun hasClassicFolderPath(
    parents: Map<String, List<String?>>,
    driveUids: Set<String>,
    targetUid: String,
    sharedFolderUid: String
): Boolean {
    val visited = mutableSetOf<String>()
    var uid = targetUid
    while (true) {
        if (uid in driveUids) {
            throw SecretsManagerException(DRIVE_FOLDER_CREATE_REFUSED)
        }
        if (!visited.add(uid)) {
            throw invalidCreateFolderParent(targetUid, sharedFolderUid)
        }
        val links = parents[uid] ?: return false
        val parent = links.distinct().singleOrNull()
            ?: throw invalidCreateFolderParent(targetUid, sharedFolderUid)
        if (uid == sharedFolderUid && parent.isEmpty()) return true
        if (uid == sharedFolderUid || parent.isEmpty()) {
            throw invalidCreateFolderParent(targetUid, sharedFolderUid)
        }
        uid = parent
    }
}

private fun readFolderParentLinks(response: JsonObject): Map<String, List<String?>> =
    (response["folders"] as? JsonArray).orEmpty().mapNotNull { entry ->
        val folder = entry as? JsonObject ?: return@mapNotNull null
        val uid = (folder["folderUid"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: return@mapNotNull null
        val parent = when (val value = folder["parent"]) {
            null, JsonNull -> ""
            is JsonPrimitive -> value.takeIf { it.isString }?.content
            else -> null
        }
        Pair(uid, parent)
    }.groupBy({ it.first }, { it.second })

@ExperimentalSerializationApi
@JvmOverloads
fun updateFolder(options: SecretsManagerOptions, folderUid: String, folderName: String, folders: List<KeeperFolder> = getFolders(options)) {
    var folder = editableFolder(folders, folderUid)
    if (folder.data == null) {
        folder = editableFolder(getFolders(options), folderUid)
    }
    val data = folder.data
        ?: throw SecretsManagerException("Unable to update folder - complete folder data for $folderUid not found")
    val payload = prepareUpdateFolderPayload(options.storage, folderUid, folderName, folder.folderKey, folder.useGcm, data)
    postQuery(options, "update_folder", payload)
}

private fun editableFolder(folders: List<KeeperFolder>, folderUid: String): KeeperFolder {
    val matches = folders.filter { it.folderUid == folderUid }
    if (matches.any { it.isDrive }) {
        throw SecretsManagerException(DRIVE_FOLDER_UPDATE_REFUSED)
    }
    val folder = matches.firstOrNull()
        ?: throw SecretsManagerException("Unable to update folder - folder key for $folderUid not found")
    if (folder.folderKey.isEmpty()) {
        throw SecretsManagerException("Unable to update folder - folder key for $folderUid not found")
    }
    val parents = matches.map { it.parentUid.orEmpty() }.toSet()
    if (parents.any { it.isEmpty() } || parents.size != 1) {
        throw SecretsManagerException("Error: access_denied, message=Folder $folderUid is not editable")
    }
    return folder
}

private fun withDriveFolders(folders: List<KeeperFolder>, responseFolders: List<KeeperFolder>): List<KeeperFolder> {
    val driveFolders = linkedMapOf<String, KeeperFolder>()
    responseFolders.filter { it.isDrive }.forEach { driveFolders[it.folderUid] = it }
    return folders.filter { it.folderUid !in driveFolders } + driveFolders.values
}

private fun writeLookupOptions(options: SecretsManagerOptions, folderUids: List<String?>): QueryOptions {
    // A custom query function can cache a full response.
    val filter = if (options.queryFunction == null) folderUids.filterNotNull().filter { it.isNotEmpty() }.distinct() else emptyList()
    return QueryOptions(foldersFilter = filter)
}

@ExperimentalSerializationApi
private fun getSecretsForWrite(options: SecretsManagerOptions, folderUids: List<String?>): KeeperSecrets {
    val queryOptions = writeLookupOptions(options, folderUids)
    val (secrets, justBound) = fetchAndDecryptSecrets(options, queryOptions)
    return if (justBound) fetchAndDecryptSecrets(options, queryOptions).first else secrets
}

@ExperimentalSerializationApi
private fun getSecretsForRecordCreate(options: SecretsManagerOptions, folderUid: String): KeeperSecrets {
    val secrets = getSecretsForWrite(options, listOf(folderUid))
    if (folderUid !in secrets.listedFolderUids) {
        throw folderKeyNotFound("create record", folderUid)
    }
    return secrets
}

@ExperimentalSerializationApi
private fun getFoldersForWrite(
    options: SecretsManagerOptions,
    folders: List<KeeperFolder>,
    folderUids: List<String?>
): List<KeeperFolder> {
    val uids = folderUids.filterNotNull().filter { it.isNotEmpty() }.distinct()
    fun openQuestion(folder: KeeperFolder): Boolean =
        folder.parentUid.isNullOrEmpty() && folder.useGcm && !folder.isDrive
    if (uids.all { uid -> folders.any { it.folderUid == uid && it.folderKey.isNotEmpty() && !openQuestion(it) } }) {
        return withDriveFolders(folders, folders)
    }
    val secrets = getSecretsForWrite(options, uids)
    val unavailableDriveFolders = uids.filter { uid ->
        uid in secrets.driveFolderUids && secrets.folders.none { it.folderUid == uid && it.isDrive }
    }.map { uid ->
        KeeperFolder(ByteArray(0), uid, null, "", useGcm = true, isDrive = true)
    }
    val emptyDriveFolders = folders.filter {
        it.folderUid in uids && openQuestion(it) && it.folderUid !in secrets.listedFolderUids
    }.map {
        KeeperFolder(it.folderKey, it.folderUid, null, it.name, useGcm = true, isDrive = true)
    }
    return withDriveFolders(folders, secrets.folders + unavailableDriveFolders + emptyDriveFolders)
}

private fun folderKeyNotFound(action: String, folderUid: String): SecretsManagerException =
    SecretsManagerException("Unable to $action - folder key for $folderUid not found. $DRIVE_FOLDER_HINT")

@ExperimentalSerializationApi
fun uploadFile(options: SecretsManagerOptions, ownerRecord: KeeperRecord, file: KeeperFileUpload): String {
    val payloadAndFile = prepareFileUploadPayload(options.storage, ownerRecord, file)
    val responseData = postQuery(options, "add_file", payloadAndFile.payload)
    val response = nonStrictJson.decodeFromString<SecretsManagerAddFileResponse>(bytesToString(responseData))
    val uploadResult = uploadFile(response.url, response.parameters, payloadAndFile.encryptedFile, options.proxyUrl, options.allowUnverifiedCertificate, options.connectTimeoutMillis, options.readTimeoutMillis)
    if (uploadResult.statusCode != response.successStatusCode) {
        throw SecretsManagerException("Upload failed (${bytesToString(uploadResult.data)}), code ${uploadResult.statusCode}")
    }
    return payloadAndFile.payload.fileRecordUid
}

fun downloadFile(options: SecretsManagerOptions, file: KeeperFile): ByteArray {
    val url = file.url ?: throw SecretsManagerException("File ${file.fileUid} has no download URL")
    return downloadFileFromUrl(file, url, options.proxyUrl, options.allowUnverifiedCertificate, options.connectTimeoutMillis, options.readTimeoutMillis)
}

@JvmOverloads
fun downloadFile(file: KeeperFile, proxyUrl: String? = null): ByteArray {
    val url = file.url ?: throw SecretsManagerException("File ${file.fileUid} has no download URL")
    return downloadFileFromUrl(file, url, proxyUrl, false)
}

fun downloadThumbnail(options: SecretsManagerOptions, file: KeeperFile): ByteArray {
    if (file.thumbnailUrl == null) {
        throw SecretsManagerException("Thumbnail does not exist for the file ${file.fileUid}")
    }
    return downloadFileFromUrl(file, file.thumbnailUrl, options.proxyUrl, options.allowUnverifiedCertificate, options.connectTimeoutMillis, options.readTimeoutMillis)
}

@JvmOverloads
fun downloadThumbnail(file: KeeperFile, proxyUrl: String? = null): ByteArray {
    if (file.thumbnailUrl == null) {
        throw SecretsManagerException("Thumbnail does not exist for the file ${file.fileUid}")
    }
    return downloadFileFromUrl(file, file.thumbnailUrl, proxyUrl, false)
}

private fun downloadFileFromUrl(file: KeeperFile, url: String, proxyUrl: String? = null, allowUnverifiedCertificate: Boolean = false, connectTimeoutMillis: Int = DEFAULT_CONNECT_TIMEOUT_MS, readTimeoutMillis: Int = DEFAULT_READ_TIMEOUT_MS): ByteArray {
    val connection = openProxiedConnection(url, proxyUrl, allowUnverifiedCertificate)
    try {
        connection.connectTimeout = connectTimeoutMillis
        connection.readTimeout = readTimeoutMillis
        connection.requestMethod = "GET"
        val statusCode = connection.checkedResponseCode(proxyUrl, url)
        val data = when {
            connection.errorStream != null -> connection.errorStream.readBytes()
            else -> connection.inputStream.readBytes()
        }
        if (statusCode != HTTP_OK) {
            throw SecretsManagerException(String(data))
        }
        return decrypt(data, file.fileKey)
    } finally {
        connection.disconnect()
    }
}

private fun uploadFile(url: String, parameters: String, fileData: ByteArray, proxyUrl: String?, allowUnverifiedCertificate: Boolean = false, connectTimeoutMillis: Int = DEFAULT_CONNECT_TIMEOUT_MS, readTimeoutMillis: Int = DEFAULT_READ_TIMEOUT_MS): KeeperHttpResponse {
    var statusCode: Int
    var data: ByteArray
    val boundary = String.format("----------%x", Instant.now().epochSecond)
    val boundaryBytes: ByteArray = stringToBytes("\r\n--$boundary")
    val paramJson = Json.parseToJsonElement(parameters) as JsonObject
    val connection = openProxiedConnection(url, proxyUrl, allowUnverifiedCertificate)
    try {
        connection.connectTimeout = connectTimeoutMillis
        connection.readTimeout = readTimeoutMillis
        connection.requestMethod = "POST"
        connection.useCaches = false
        connection.doInput = true
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
        try {
            connection.outputStream.use { os ->
                for (param in paramJson.entries) {
                    os.write(boundaryBytes)
                    os.write(stringToBytes("\r\nContent-Disposition: form-data; name=\"${param.key}\"\r\n\r\n${param.value.jsonPrimitive.content}"))
                }
                os.write(boundaryBytes)
                os.write(stringToBytes("\r\nContent-Disposition: form-data; name=\"file\"\r\nContent-Type: application/octet-stream\r\n\r\n"))
                os.write(fileData)
                os.write(boundaryBytes)
                os.write(stringToBytes("--\r\n"))
            }
        } catch (e: IOException) {
            // For tunneled HTTPS connections the JDK can throw here when the CONNECT tunnel fails.
            if (e.message?.contains("407") == true) {
                val resolved = resolveProxy(proxyUrl, url)
                if (resolved != null && resolved.hasCredentials) {
                    val isAmbientCredentials = !resolved.isExplicit
                    throw SecretsManagerException(proxyAuthFailureMessage(e.message, isAmbientCredentials), e)
                }
            }
            throw e
        }
        statusCode = connection.checkedResponseCode(proxyUrl, url)
        data = when {
            connection.errorStream != null -> connection.errorStream.readBytes()
            else -> connection.inputStream.readBytes()
        }
    } finally {
        connection.disconnect()
    }
    return KeeperHttpResponse(statusCode, data)
}

@ExperimentalSerializationApi
private fun fetchAndDecryptSecrets(
    options: SecretsManagerOptions,
    queryOptions: QueryOptions?
): Pair<KeeperSecrets, Boolean> {
    val storage = options.storage
    val payload = prepareGetPayload(storage, queryOptions)
    val responseData = postQuery(options, "get_secret", payload)
    val jsonString = bytesToString(responseData)
    val response = nonStrictJson.decodeFromString<SecretsManagerResponse>(jsonString)
    var justBound = false
    val appKey: ByteArray
    if (response.encryptedAppKey != null) {
        justBound = true
        val clientKey = storage.getBytes(KEY_CLIENT_KEY) ?: throw SecretsManagerException("Client key is missing from the storage")
        appKey = decrypt(response.encryptedAppKey, clientKey)
        storage.saveBytes(KEY_APP_KEY, appKey)
        storage.delete(KEY_CLIENT_KEY)
        storage.delete(KEY_PUBLIC_KEY)
        response.appOwnerPublicKey?.let {
            storage.saveString(KEY_OWNER_PUBLIC_KEY, it)
        }
    } else {
        appKey = storage.getBytes(KEY_APP_KEY) ?: throw SecretsManagerException("App key is missing from the storage")
    }
    val driveFolderUids = response.folders.orEmpty().filter { !it.data.isNullOrEmpty() }.map { it.folderUid }.toSet()
    val folderKeyMap = mutableMapOf<String, ByteArray>()
    val driveKeyUids = mutableSetOf<String>()
    response.folders.orEmpty().forEach { folder ->
        try {
            val folderKey = decrypt(folder.folderKey, appKey)
            val isDrive = !folder.data.isNullOrEmpty()
            if (isDrive || folder.folderUid !in driveKeyUids) {
                folderKeyMap[folder.folderUid] = folderKey
            }
            if (isDrive) driveKeyUids.add(folder.folderUid)
        } catch (_: Exception) {
        }
    }

    val records: MutableList<KeeperRecord> = mutableListOf()
    val folders: MutableList<KeeperFolder> = mutableListOf()
    val driveRecordUids = mutableSetOf<String>()
    response.records.orEmpty().filter { it.innerFolderUid in driveFolderUids }.forEach { driveRecordUids.add(it.recordUid) }
    response.folders.orEmpty().filter { it.folderUid in driveFolderUids }.forEach { folder ->
        folder.records.orEmpty().forEach { driveRecordUids.add(it.recordUid) }
    }
    if (response.records != null) {
        response.records.forEach {
            try {
                val decryptKey = if (it.innerFolderUid != null && folderKeyMap.containsKey(it.innerFolderUid)) {
                    folderKeyMap[it.innerFolderUid]!!
                } else {
                    appKey
                }
                val recordKey = decrypt(it.recordKey, decryptKey)
                val decryptedRecord = decryptRecord(it, recordKey, options)
                if (decryptedRecord != null) {
                    decryptedRecord.isDrive = it.recordUid in driveRecordUids
                    if (it.innerFolderUid != null && folderKeyMap.containsKey(it.innerFolderUid)) {
                        decryptedRecord.folderUid = it.innerFolderUid
                        decryptedRecord.folderKey = folderKeyMap[it.innerFolderUid]
                    }
                    records.add(decryptedRecord)
                }
            } catch (e: Exception) {
                if (options.loggingEnabled) {
                    System.err.println("Record ${it.recordUid} skipped due to error: ${e.javaClass.simpleName}, ${e.message}")
                }
            }
        }
    }
    if (response.folders != null) {
        response.folders.forEach { folder ->
            try {
                val folderKey = decrypt(folder.folderKey, appKey)
                val isDrive = !folder.data.isNullOrEmpty()
                val folderData = if (isDrive && !folder.data.isNullOrEmpty()) {
                    decryptGcmFolderData(folder.data, folderKey)?.let { parseFolderData(it) }
                } else null
                val decryptedFolder = KeeperFolder(
                    folderKey, folder.folderUid, null, folderName(folderData),
                    useGcm = isDrive, isDrive = isDrive
                )
                decryptedFolder.data = folderData
                folders.add(decryptedFolder)
                folder.records.orEmpty().forEach { record ->
                    try {
                        val recordKey = decrypt(record.recordKey, folderKey)
                        val decryptedRecord = decryptRecord(record, recordKey, options)
                        if (decryptedRecord != null) {
                            decryptedRecord.folderUid = folder.folderUid
                            decryptedRecord.folderKey = folderKey
                            decryptedRecord.isDrive = record.recordUid in driveRecordUids
                            records.add(decryptedRecord)
                        }
                    } catch (e: Exception) {
                        if (options.loggingEnabled) {
                            System.err.println("Record ${record.recordUid} in folder ${folder.folderUid} skipped due to error: ${e.javaClass.simpleName}, ${e.message}")
                        }
                    }
                }
            } catch (e: Exception) {
                if (options.loggingEnabled) {
                    System.err.println("Folder ${folder.folderUid} skipped due to error: ${e.javaClass.simpleName}, ${e.message}")
                }
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
    secrets.folders = folders
    secrets.listedFolderUids = response.folders.orEmpty().map { it.folderUid }.toSet()
    secrets.driveFolderUids = driveFolderUids
    return Pair(secrets, justBound)
}

// A JSON parse failure is an IllegalArgumentException (kotlinx-serialization) and its message
// carries the decrypted JSON, so the message is withheld for that family. Other failures here
// (decryption, null data) carry no payload and keep their message for diagnosis.
private fun skipReason(e: Throwable): String =
    if (e is IllegalArgumentException) "${e.javaClass.simpleName}, message withheld"
    else "${e.javaClass.simpleName}, ${e.message}"

@ExperimentalSerializationApi
private fun decryptRecord(record: SecretsManagerResponseRecord, recordKey: ByteArray, options: SecretsManagerOptions): KeeperRecord? {
    val decryptedRecord = decrypt(record.data, recordKey)

    val files: MutableList<KeeperFile> = mutableListOf()

    if (record.files != null) {
        record.files.forEach {
            try {
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
            } catch (e: Exception) {
                if (options.loggingEnabled) {
                    System.err.println("File ${it.fileUid} skipped due to error: ${skipReason(e)}")
                }
            }
        }
    }

    // When SDK is behind/ahead of record/field type definitions then
    // strict mapping between JSON attributes and object properties
    // will fail on any unknown field/key - currently just log the error
    // and continue without the field - NB! field will be lost on save
    var recordData: KeeperRecordData? = null
    try {
        recordData = Json.decodeFromString<KeeperRecordData>(bytesToString(decryptedRecord))
    } catch (e: Exception) {
        // The type comes from decrypted data and goes into a log line, so only a short identifier
        // is allowed through. A newline in it could otherwise forge a log entry.
        val recordType = try {
            val jsonElement = Json.parseToJsonElement(bytesToString(decryptedRecord))
            val type = jsonElement.jsonObject["type"]?.jsonPrimitive?.content
            if (type != null && Regex("[A-Za-z0-9_]{1,64}").matches(type)) type else "unknown"
        } catch (_: Exception) {
            "unknown"
        }

        // Only the exception class is logged. The kotlinx-serialization message holds the
        // decrypted JSON, and wording-based extraction of a safe part has leaked before.
        if (options.loggingEnabled) {
            System.err.println("""
            Record ${record.recordUid} (type: $recordType) parsing error: ${e.javaClass.simpleName}
            This may occur if the Keeper Secrets Manager (KSM) SDK version you're using is not compatible with the record's data schema.
            Please ensure that you are using the latest version of the KSM SDK. If the issue persists, contact support@keepersecurity.com for assistance.
            """.trimIndent()
            )
        }
        try {
            // Attempt to parse with non-strict JSON parser for recovery
            recordData = nonStrictJson.decodeFromString<KeeperRecordData>(bytesToString(decryptedRecord))
        } catch (e2: Exception) {
            if (options.loggingEnabled) {
                System.err.println("""
                Failed to parse record ${record.recordUid} (type: $recordType) even with non-strict parser: ${e2.javaClass.simpleName}
                Record will be skipped.
                """.trimIndent()
                )
            }
        }
    }

    return if (recordData != null) KeeperRecord(
        recordKey = recordKey,
        recordUid = record.recordUid,
        folderUid = null,
        folderKey = null,
        innerFolderUid = record.innerFolderUid,
        data = recordData,
        revision = record.revision,
        files = files,
        links = record.links,
        isEditable = record.isEditable
    ) else null
}

@ExperimentalSerializationApi
private fun fetchFoldersResponse(
    options: SecretsManagerOptions
): Pair<JsonObject, ByteArray> {
    val storage = options.storage
    fun read(): Pair<JsonObject, ByteArray> {
        val payload = prepareGetPayload(storage, null)
        val onAccessDenied: (() -> Unit)? = if (payload.publicKey != null && storage is LocalConfigStorage) {
            {
                if (storage.removeUnboundConfig()) {
                    throw SecretsManagerException(
                        "Initialization failed. The SDK removed the incomplete config file. " +
                            "Generate a new one-time token and try again."
                    )
                }
            }
        } else null
        val responseData = postQuery(options, "get_folders", payload, onAccessDenied)
        val response = nonStrictJson.parseToJsonElement(bytesToString(responseData)).jsonObject
        val encryptedAppKey = (response["encryptedAppKey"] as? JsonPrimitive)
            ?.takeIf { it.isString }?.content?.takeIf { it.isNotEmpty() }
        val appKey = if (encryptedAppKey != null) {
            val clientKey = storage.getBytes(KEY_CLIENT_KEY)
                ?: throw SecretsManagerException("Client key is missing from the storage")
            decrypt(encryptedAppKey, clientKey).also {
                storage.saveBytes(KEY_APP_KEY, it)
                storage.delete(KEY_CLIENT_KEY)
                storage.delete(KEY_PUBLIC_KEY)
                (response["appOwnerPublicKey"] as? JsonPrimitive)?.takeIf { key -> key.isString }?.content?.let { key ->
                    storage.saveString(KEY_OWNER_PUBLIC_KEY, key)
                }
            }
        } else {
            storage.getBytes(KEY_APP_KEY) ?: throw SecretsManagerException("App key is missing from the storage")
        }
        return Pair(response, appKey)
    }
    val binding = storage.getBytes(KEY_APP_KEY) == null
    val response = read()
    // The second read completes a new client's binding before a write.
    return if (binding) read() else response
}

private fun readFolderRoots(response: JsonObject, requestedUids: Set<String>): Map<String, String> {
    val parents = readFolderParentLinks(response).mapValues { (_, links) -> links.distinct().singleOrNull() }
    return requestedUids.mapNotNull { uid ->
        val visited = mutableSetOf<String>()
        var current = uid
        while (visited.add(current)) {
            val parent = parents[current] ?: break
            if (parent.isEmpty()) return@mapNotNull uid to current
            current = parent
        }
        null
    }.toMap()
}

@ExperimentalSerializationApi
private fun readCbcFolderRoots(response: JsonObject, appKey: ByteArray, rootUids: Set<String>): Set<String> {
    if (rootUids.isEmpty()) return emptySet()
    val candidates = (response["folders"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>()
        .groupBy { it.stringValue("folderUid") }
    return rootUids.filterTo(mutableSetOf()) { uid ->
        candidates[uid]?.all { entry ->
            val key = entry.stringValue("folderKey") ?: return@all false
            val data = entry.stringValue("data") ?: return@all false
            runCatching {
                val folderKey = decrypt(key, appKey)
                decryptGcmFolderData(data, folderKey) == null &&
                    parseFolderData(decrypt(data, folderKey, true)) != null
            }.getOrDefault(false)
        } == true
    }
}

private enum class FolderType { CLASSIC, DRIVE }

@ExperimentalSerializationApi
private fun fetchFolderTypes(options: SecretsManagerOptions, uids: Set<String>): Map<String, FolderType> {
    if (uids.isEmpty()) return emptyMap()
    // Both folder types can use GCM. Only NSF entries from get_secret include folder data.
    val payload = prepareGetPayload(options.storage, writeLookupOptions(options, uids.toList()))
    val response = nonStrictJson.parseToJsonElement(bytesToString(postQuery(options, "get_secret", payload))).jsonObject
    val entries = (response["folders"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>()
        .groupBy { it.stringValue("folderUid") }
    return uids.mapNotNull { uid ->
        val matches = entries[uid] ?: return@mapNotNull null
        when {
            matches.any { !it.stringValue("data").isNullOrEmpty() } -> uid to FolderType.DRIVE
            matches.all { it["data"] == null || it["data"] == JsonNull || it.stringValue("data") == "" } ->
                uid to FolderType.CLASSIC
            else -> null
        }
    }.toMap()
}

private fun JsonObject.stringValue(key: String): String? =
    (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

private fun decryptGcmFolderData(data: String, key: ByteArray): ByteArray? {
    val bytes = try {
        base64ToBytes(data)
    } catch (_: Exception) {
        return null
    }
    try {
        return decrypt(bytes, key)
    } catch (_: Exception) {
        var length = bytes.size
        while (length > 0 && bytes[length - 1] == 0.toByte()) {
            length--
        }
        // Keep real zero bytes in the tag. Authentication selects the length.
        for (candidate in length until bytes.size) {
            if (candidate < 28) continue
            try {
                return decrypt(bytes.copyOf(candidate), key)
            } catch (_: Exception) {
            }
        }
    }
    return null
}

@ExperimentalSerializationApi
private fun parseFolderData(bytes: ByteArray): JsonObject? = try {
    nonStrictJson.parseToJsonElement(bytesToString(bytes)) as? JsonObject
} catch (_: Exception) {
    null
}

private fun folderName(data: JsonObject?): String =
    (data?.get("name") as? JsonPrimitive)?.takeIf { it.isString }?.content.orEmpty()

@ExperimentalSerializationApi
private fun fetchAndDecryptFolders(options: SecretsManagerOptions): List<KeeperFolder> {
    val (response, appKey) = fetchFoldersResponse(options)
    return decryptFolders(options, response, appKey)
}

@ExperimentalSerializationApi
private fun decryptFolders(options: SecretsManagerOptions, response: JsonObject, appKey: ByteArray): List<KeeperFolder> {
    val responseFolders = (response["folders"] as? JsonArray).orEmpty().mapNotNull { entry ->
        try {
            nonStrictJson.decodeFromJsonElement<SecretsManagerResponseFolder>(entry)
        } catch (e: Exception) {
            if (options.loggingEnabled) {
                val uid = ((entry as? JsonObject)?.get("folderUid") as? JsonPrimitive)
                    ?.takeIf { it.isString }?.content.orEmpty()
                System.err.println("Folder $uid skipped due to error: ${e.javaClass.simpleName}, message withheld")
            }
            null
        }
    }
    val folders: MutableList<KeeperFolder> = mutableListOf()
    responseFolders.forEach { folder ->
        try {
            var useGcm = false
            val folderKey: ByteArray = if (folder.parent.isNullOrEmpty()) {
                decrypt(folder.folderKey, appKey)
            } else {
                val sharedFolderKey = getSharedFolderKey(folders, responseFolders, folder.parent) ?: throw SecretsManagerException("Folder data inconsistent - unable to locate shared folder")
                val folderKeyBytes = base64ToBytes(folder.folderKey)
                if (folderKeyBytes.size == 60) {
                    useGcm = true
                    decrypt(folderKeyBytes, sharedFolderKey)
                } else {
                    decrypt(folderKeyBytes, sharedFolderKey, true)
                }
            }
            val gcmData = if (folder.parent.isNullOrEmpty() && !folder.data.isNullOrEmpty()) {
                decryptGcmFolderData(folder.data, folderKey)
            } else null
            if (gcmData != null) useGcm = true
            val decryptedData = gcmData ?: decrypt(folder.data!!, folderKey, !useGcm)
            val data = if (gcmData != null) parseFolderData(decryptedData) else
                nonStrictJson.parseToJsonElement(bytesToString(decryptedData)).jsonObject
            if (gcmData == null) {
                val name = data?.get("name")
                if (name != null && name != JsonNull && (name !is JsonPrimitive || !name.isString)) {
                    throw SecretsManagerException("Folder data for ${folder.folderUid} has no readable name")
                }
            }
            val decryptedFolder = KeeperFolder(folderKey, folder.folderUid, folder.parent, folderName(data), useGcm)
            decryptedFolder.data = data
            folders.add(decryptedFolder)
        } catch (e: Exception) {
            if (options.loggingEnabled) {
                // Same shape as the skip diagnostics in fetchAndDecryptSecrets. The class name
                // matters because the common causes (a null data field, a tag mismatch) carry no
                // message, which would otherwise log "skipped due to error: null".
                System.err.println("Folder ${folder.folderUid} skipped due to error: ${skipReason(e)}")
            }
        }
    }
    return folders
}

private fun getSharedFolderKey(folders: List<KeeperFolder>, responseFolders: List<SecretsManagerResponseFolder>, parent: String): ByteArray? {
    val visited = HashSet<String>()
    var currentParent = parent
    while (visited.add(currentParent)) {
        val parentFolder = responseFolders.find { x -> x.folderUid == currentParent } ?: return null
        currentParent = parentFolder.parent?.takeIf { it.isNotEmpty() }
            ?: return folders.find { it.folderUid == parentFolder.folderUid }?.folderKey
    }
    throw SecretsManagerException("Folder data inconsistent - parent cycle detected at folder UID $currentParent")
}

private fun prepareGetPayload(
    storage: KeyValueStorage,
    queryOptions: QueryOptions?
): GetPayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw SecretsManagerException("Client Id is missing from the configuration")
    val payload = GetPayload(
        KEEPER_CLIENT_VERSION,
        clientId,
        null,
        null
    )
    val appKey = storage.getBytes(KEY_APP_KEY)
    if (appKey == null) {
        val publicKey = storage.getBytes(KEY_PUBLIC_KEY) ?: throw SecretsManagerException("Public key is missing from the storage")
        payload.publicKey = bytesToBase64(publicKey)
    }
    if (queryOptions != null) {
        if (queryOptions.recordsFilter.isNotEmpty()) {
            payload.requestedRecords = queryOptions.recordsFilter
        }
        if (queryOptions.foldersFilter.isNotEmpty()) {
            payload.requestedFolders = queryOptions.foldersFilter
        }
        if (queryOptions.requestLinks != null) {
            payload.requestLinks = queryOptions.requestLinks
        }
    }
    return payload
}

@ExperimentalSerializationApi
private fun prepareDeletePayload(
    storage: KeyValueStorage,
    recordUids: List<String>
): DeletePayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw SecretsManagerException("Client Id is missing from the configuration")
    return DeletePayload(KEEPER_CLIENT_VERSION, clientId, recordUids)
}

@ExperimentalSerializationApi
private fun prepareDeleteFolderPayload(
    storage: KeyValueStorage,
    folderUids: List<String>,
    forceDeletion: Boolean
): DeleteFolderPayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw SecretsManagerException("Client Id is missing from the configuration")
    return DeleteFolderPayload(KEEPER_CLIENT_VERSION, clientId, folderUids, forceDeletion)
}

@ExperimentalSerializationApi
private fun prepareUpdatePayload(
    storage: KeyValueStorage,
    record: KeeperRecord,
    updateOptions: UpdateOptions? = null
): UpdatePayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw SecretsManagerException("Client Id is missing from the configuration")

    updateOptions?.linksToRemove?.takeIf { it.isNotEmpty() }?.let {
        val frefs = record.data.getField<FileRef>()
        if (frefs?.value?.isNotEmpty() == true){
            frefs.value.removeAll(it)
        }
    }

    val recordBytes = stringToBytes(Json.encodeToString(record.data))
    val encryptedRecord = encrypt(recordBytes, record.recordKey)

    return UpdatePayload(
        clientVersion = KEEPER_CLIENT_VERSION,
        clientId = clientId,
        recordUid = record.recordUid,
        data = webSafe64FromBytes(encryptedRecord),
        revision = record.revision,
        transactionType = updateOptions?.transactionType,
        links2Remove = updateOptions?.linksToRemove
    )
}

@ExperimentalSerializationApi
private fun prepareCompleteTransactionPayload(
    storage: KeyValueStorage,
    recordUid: String
): CompleteTransactionPayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw SecretsManagerException("Client Id is missing from the configuration")
    return CompleteTransactionPayload(KEEPER_CLIENT_VERSION, clientId, recordUid)
}

@ExperimentalSerializationApi
private fun prepareCreatePayload(
    storage: KeyValueStorage,
    createOptions: CreateOptions,
    recordData: KeeperRecordData,
    folderKey: ByteArray,
    isDrive: Boolean = false
): CreatePayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw SecretsManagerException("Client Id is missing from the configuration")
    var recordBytes = stringToBytes(Json.encodeToString(recordData))
    if (isDrive) {
        val originalLength = recordBytes.size
        val paddedLength = (maxOf(384, recordBytes.size) + 15) / 16 * 16
        recordBytes = recordBytes.copyOf(paddedLength).also {
            java.util.Arrays.fill(it, originalLength, paddedLength, 0x20.toByte())
        }
    }
    val recordKey = getRandomBytes(32)
    val recordUid = generateUid()
    val encryptedRecord = encrypt(recordBytes, recordKey)
    val encryptedRecordKey = if (isDrive) {
        encrypt(recordKey, folderKey)
    } else {
        val ownerPublicKey = storage.getBytes(KEY_OWNER_PUBLIC_KEY)
            ?: throw SecretsManagerException("Application owner public key is missing from the configuration")
        publicEncrypt(recordKey, ownerPublicKey)
    }
    val encryptedFolderKey = if (isDrive) null else bytesToBase64(encrypt(recordKey, folderKey))
    return CreatePayload(KEEPER_CLIENT_VERSION, clientId,
        webSafe64FromBytes(recordUid),
        bytesToBase64(encryptedRecordKey),
        createOptions.folderUid,
        encryptedFolderKey,
        webSafe64FromBytes(encryptedRecord),
        createOptions.subFolderUid)
}

@ExperimentalSerializationApi
private fun prepareCreateFolderPayload(
    storage: KeyValueStorage,
    createOptions: CreateOptions,
    folderName: String,
    sharedFolderKey: ByteArray
): CreateFolderPayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw SecretsManagerException("Client Id is missing from the configuration")
    val folderDataBytes = stringToBytes(Json.encodeToString(KeeperFolderName(folderName)))
    val folderKey = getRandomBytes(32)
    val folderUid = generateUid()
    // Classic subfolders keep the format that older readers require.
    val encryptedFolderData = encrypt(folderDataBytes, folderKey, true)
    val encryptedFolderKey = encrypt(folderKey, sharedFolderKey, true)
    return CreateFolderPayload(KEEPER_CLIENT_VERSION, clientId,
        webSafe64FromBytes(folderUid),
        createOptions.folderUid,
        webSafe64FromBytes(encryptedFolderKey),
        webSafe64FromBytes(encryptedFolderData),
        createOptions.subFolderUid)
}

@ExperimentalSerializationApi
private fun prepareUpdateFolderPayload(
    storage: KeyValueStorage,
    folderUid: String,
    folderName: String,
    folderKey: ByteArray,
    useGcm: Boolean,
    folderData: JsonObject
): UpdateFolderPayload {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw SecretsManagerException("Client Id is missing from the configuration")
    val folderDataBytes = stringToBytes(JsonObject(folderData + ("name" to JsonPrimitive(folderName))).toString())
    val encryptedFolderData = encrypt(folderDataBytes, folderKey, !useGcm)
    return UpdateFolderPayload(KEEPER_CLIENT_VERSION, clientId,
        folderUid,
        webSafe64FromBytes(encryptedFolderData))
}

@ExperimentalSerializationApi
private fun prepareFileUploadPayload(
    storage: KeyValueStorage,
    ownerRecord: KeeperRecord,
    file: KeeperFileUpload
): FileUploadPayloadAndFile {
    val clientId = storage.getString(KEY_CLIENT_ID) ?: throw SecretsManagerException("Client Id is missing from the configuration")
    val ownerPublicKey = storage.getBytes(KEY_OWNER_PUBLIC_KEY) ?: throw SecretsManagerException("Application owner public key is missing from the configuration")

    val fileData = KeeperFileData(
        file.title,
        file.name,
        file.type,
        file.data.size.toLong(),
        Instant.now().toEpochMilli()
    )

    val fileRecordBytes = stringToBytes(Json.encodeToString(fileData))
    val fileRecordKey = getRandomBytes(32)
    val fileRecordUid = webSafe64FromBytes(getRandomBytes(16))
    val encryptedFileRecord = encrypt(fileRecordBytes, fileRecordKey)
    val encryptedFileRecordKey = publicEncrypt(fileRecordKey, ownerPublicKey)
    val encryptedLinkKey = encrypt(fileRecordKey, ownerRecord.recordKey)
    val encryptedFileData = encrypt(file.data, fileRecordKey)

    val fileRef = ownerRecord.data.getField<FileRef>()
    if (fileRef == null) {
        ownerRecord.data.fields.add(FileRef(value = mutableListOf(fileRecordUid)))
    } else {
        fileRef.value.add(fileRecordUid)
    }
    val ownerRecordBytes = stringToBytes(Json.encodeToString(ownerRecord.data))
    val encryptedOwnerRecord = encrypt(ownerRecordBytes, ownerRecord.recordKey)

    return FileUploadPayloadAndFile(
        FileUploadPayload(KEEPER_CLIENT_VERSION, clientId,
            fileRecordUid,
            bytesToBase64(encryptedFileRecordKey),
            webSafe64FromBytes(encryptedFileRecord),
            ownerRecord.recordUid,
            webSafe64FromBytes(encryptedOwnerRecord),
            ownerRecord.revision,
            bytesToBase64(encryptedLinkKey),
            encryptedFileData.size
        ),
        encryptedFileData
    )
}

fun cachingPostFunction(url: String, transmissionKey: TransmissionKey, payload: EncryptedPayload): KeeperHttpResponse {
    return try {
        val response = postFunction(url, transmissionKey, payload, false)
        if (response.statusCode == HTTP_OK) {
            saveCachedValue(transmissionKey.key + response.data)
        }
        response
    } catch (e: Exception) {
        val cachedData = try {
            getCachedValue()
        } catch (cacheE: Exception) {
            throw SecretsManagerException("KSM request failed and no cached data is available: ${e.message}", e)
        }
        System.err.println("WARNING: KSM request failed (${e.message}); serving stale cached secrets. " +
            "Note: cachingPostFunction cannot use SecretsManagerOptions.proxyUrl; ambient env proxies " +
            "(HTTPS_PROXY, https.proxyHost) still apply. To use an explicit proxyUrl, use the default " +
            "postFunction instead of cachingPostFunction.")
        val cachedTransmissionKey = cachedData.copyOfRange(0, 32)
        transmissionKey.key = cachedTransmissionKey
        val data = cachedData.copyOfRange(32, cachedData.size)
        KeeperHttpResponse(HTTP_OK, data)
    }
}

// Kept as an explicit overload rather than a default argument on the function below: this is the
// arity Java callers and cachingPostFunction already compile against. No @JvmOverloads, because
// there are no default arguments here for it to generate overloads from.
fun postFunction(
    url: String,
    transmissionKey: TransmissionKey,
    payload: EncryptedPayload,
    allowUnverifiedCertificate: Boolean
): KeeperHttpResponse = postFunction(url, transmissionKey, payload, allowUnverifiedCertificate, null)

fun postFunction(
    url: String,
    transmissionKey: TransmissionKey,
    payload: EncryptedPayload,
    allowUnverifiedCertificate: Boolean,
    proxyUrl: String? = null,
    connectTimeoutMillis: Int = DEFAULT_CONNECT_TIMEOUT_MS,
    readTimeoutMillis: Int = DEFAULT_READ_TIMEOUT_MS,
): KeeperHttpResponse {
    var statusCode: Int
    var data: ByteArray
    val connection = openProxiedConnection(url, proxyUrl, allowUnverifiedCertificate)
    try {
        connection.connectTimeout = connectTimeoutMillis
        connection.readTimeout = readTimeoutMillis
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.setRequestProperty("PublicKeyId", transmissionKey.publicKeyId.toString())
        connection.setRequestProperty("TransmissionKey", bytesToBase64(transmissionKey.encryptedKey))
        connection.setRequestProperty("Authorization", "Signature ${bytesToBase64(payload.signature)}")
        try {
            connection.outputStream.write(payload.payload)
            connection.outputStream.flush()
        } catch (e: IOException) {
            // For tunneled HTTPS connections the JDK throws here when the CONNECT tunnel fails.
            if (e.message?.contains("407") == true) {
                val resolved = resolveProxy(proxyUrl, url)
                if (resolved != null && resolved.hasCredentials) {
                    val isAmbientCredentials = !resolved.isExplicit
                    throw SecretsManagerException(proxyAuthFailureMessage(e.message, isAmbientCredentials), e)
                }
            }
            throw e
        }
        statusCode = connection.checkedResponseCode(proxyUrl, url)
        data = when {
            connection.errorStream != null -> connection.errorStream.readBytes()
            else -> connection.inputStream.readBytes()
        }
    } finally {
        connection.disconnect()
    }
    return KeeperHttpResponse(statusCode, data)
}

@ExperimentalSerializationApi
private val nonStrictJson = Json {
    ignoreUnknownKeys = true
    isLenient = true
    coerceInputValues = true
    allowTrailingComma = true
}

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
    "BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU",
    "BNhngQqTT1bPKxGuB6FhbPTAeNVFl8PKGGSGo5W06xWIReutm6ix6JPivqnbvkydY-1uDQTr-5e6t70G01Bb5JA"
).associateBy({ keyId++ }, { webSafe64ToBytes(it) })

private fun generateTransmissionKey(storage: KeyValueStorage): TransmissionKey {
    val transmissionKey = if (TestStubs.transmissionKeyStubReady()) {
        TestStubs.transmissionKeyStub()
    } else {
        getRandomBytes(32)
    }
    val keyNumber: Int = storage.getString(KEY_SERVER_PUBLIC_KEY_ID)?.toInt() ?: 7
    // Layer 1: serverPublicKey in storage (from config JSON, OTT, or constructor) takes priority
    val keeperPublicKey: ByteArray = storage.getString(KEY_SERVER_PUBLIC_KEY)?.let { webSafe64ToBytes(it) }
        ?: keeperPublicKeys[keyNumber]
        ?: throw SecretsManagerException("Key number $keyNumber is not supported")
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
    val privateKey = storage.getBytes(KEY_PRIVATE_KEY) ?: throw SecretsManagerException("Private key is missing from the storage")
    val signatureBase = transmissionKey.encryptedKey + encryptedPayload
    val signature = sign(signatureBase, privateKey)
    return EncryptedPayload(encryptedPayload, signature)
}

@ExperimentalSerializationApi
// Returns the throttle retry_after (>= 0) when [body] is a backend throttle error
// (result_code/error == "throttled"), otherwise null so the caller falls through to normal
// error handling. Non-JSON / non-object bodies return null.
internal fun parseThrottle(body: String): Double? {
    val obj = try {
        nonStrictJson.parseToJsonElement(body).jsonObject
    } catch (e: Exception) {
        return null
    }
    val resultCode = ((obj["result_code"] ?: obj["error"]) as? JsonPrimitive)?.content
    if (resultCode != "throttled") return null
    val retryAfter = (obj["retry_after"] as? JsonPrimitive)?.content?.toDoubleOrNull() ?: 0.0
    return retryAfter.coerceIn(0.0, MAX_THROTTLE_DELAY_SEC.toDouble())
}

// Backoff delay (milliseconds) for a 0-based [attempt]: retryAfter when > 0, otherwise
// exponential backoff (BASE_THROTTLE_DELAY_SEC * 2**attempt -> 11, 22, 44, 88, 176s). The
// [jitter] fraction (typically in [0, 0.25)) is then applied.
internal fun throttleDelayMillis(attempt: Int, retryAfter: Double, jitter: Double): Long {
    val baseSec = if (retryAfter > 0.0) retryAfter else BASE_THROTTLE_DELAY_SEC.toDouble() * (1L shl attempt)
    val sec = baseSec + baseSec * jitter
    return (sec * 1000).toLong()
}

// Random jitter multiplier in [0, 0.25); one-sided so a delay is only ever padded, never
// undercuts the server-requested (or exponential-backoff) floor. Kept separate so unit tests
// exercise throttleDelayMillis with a pinned jitter instead.
internal fun throttleJitter(): Double = Random.nextDouble(0.0, 0.25)

@ExperimentalSerializationApi
private inline fun <reified T> postQuery(
    options: SecretsManagerOptions,
    path: String,
    payload: T,
    noinline onAccessDenied: (() -> Unit)? = null
): ByteArray {
    val hostName = options.storage.getString(KEY_HOSTNAME) ?: throw SecretsManagerException("hostname is missing from the storage")
    val url = "https://${hostName}/api/rest/sm/v1/${path}"
    val throttleSleep = options.throttleSleepMillis ?: { ms -> Thread.sleep(ms) }
    var throttleAttempt = 0
    var keyRotationAttempt = 0
    while (true) {
        val transmissionKey = generateTransmissionKey(options.storage)
        val encryptedPayload = encryptAndSignPayload(options.storage, transmissionKey, payload)
        val response = if (options.queryFunction == null) {
            postFunction(url, transmissionKey, encryptedPayload, options.allowUnverifiedCertificate, options.proxyUrl, options.connectTimeoutMillis, options.readTimeoutMillis)
        } else {
            options.queryFunction.invoke(url, transmissionKey, encryptedPayload)
        }
        if (response.statusCode != HTTP_OK) {
            val errorMessage = String(response.data)
            // Throttle retry with exponential backoff + jitter. Checked before
            // key-rotation so that path (incl. the IL5 custom-key suppression) is untouched, and
            // gated on the 403 status so a non-403 response carrying a {"error":"throttled"} body
            // is not mistaken for a throttle and retried.
            if (response.statusCode == HTTP_FORBIDDEN) {
                val retryAfter = parseThrottle(errorMessage)
                if (retryAfter != null) {
                    if (throttleAttempt >= MAX_THROTTLE_RETRIES) {
                        throw KeeperThrottleException("Request throttled by Keeper backend; exhausted $MAX_THROTTLE_RETRIES retries")
                    }
                    val delayMs = throttleDelayMillis(throttleAttempt, retryAfter, throttleJitter())
                    if (options.loggingEnabled) {
                        System.err.println(
                            "WARNING: Request throttled (attempt ${throttleAttempt + 1}/$MAX_THROTTLE_RETRIES); " +
                                "retrying in ${"%.1f".format(Locale.US, delayMs / 1000.0)}s"
                        )
                    }
                    throttleSleep(delayMs)
                    throttleAttempt++
                    continue
                }
            }
            // Parse outside the bare catch so the actionable IL5 throw can escape.
            val error = try { nonStrictJson.decodeFromString<KeeperError>(errorMessage) } catch (_: Exception) { null }
            if (error?.error == "key") {
                val customKey = options.storage.getString(KEY_SERVER_PUBLIC_KEY)
                if (customKey != null) {
                    val currentKeyId = options.storage.getString(KEY_SERVER_PUBLIC_KEY_ID)
                    throw SecretsManagerException("Server rejected the custom server public key (id $currentKeyId). The server suggested key id ${error.key_id}. Please update your IL5 KSM configuration.")
                }
                if (!keeperPublicKeys.containsKey(error.key_id)) {
                    val ids = keeperPublicKeys.keys.sorted()
                    throw SecretsManagerException(
                        "Server suggested unsupported key id ${error.key_id}; this SDK version supports key ids ${ids.first()}-${ids.last()}"
                    )
                }
                if (keyRotationAttempt >= MAX_KEY_ROTATION_RETRIES) {
                    throw SecretsManagerException(
                        "Server key rotation exhausted $MAX_KEY_ROTATION_RETRIES retries; key id ${transmissionKey.publicKeyId} was not accepted"
                    )
                }
                keyRotationAttempt++
                options.storage.saveString(KEY_SERVER_PUBLIC_KEY_ID, error.key_id.toString())
                continue
            }
            if (onAccessDenied != null && response.statusCode == HTTP_FORBIDDEN) {
                val errorObject = runCatching { nonStrictJson.parseToJsonElement(errorMessage) as? JsonObject }.getOrNull()
                val code = errorObject?.stringValue("result_code") ?: errorObject?.stringValue("error")
                if (code == "access_denied") onAccessDenied()
            }
            throw SecretsManagerException(errorMessage)
        }
        if (response.data.isEmpty()) {
            return response.data
        }
        return decrypt(response.data, transmissionKey.key)
    }
}

internal object TestStubs {
    lateinit var transmissionKeyStub: () -> ByteArray

    fun transmissionKeyStubReady(): Boolean {
        return this::transmissionKeyStub.isInitialized
    }
}
