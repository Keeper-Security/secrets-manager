package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.*
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.*
import kotlin.collections.HashMap

fun saveCachedValue(data: ByteArray) {
    val targetPath = File("cache.dat").absoluteFile.toPath()
    val tmpPath = try {
        Files.createTempFile(targetPath.parent, "ksm_", ".tmp")
    } catch (e: IOException) {
        // Report what actually failed: createTempFile also fails on a full or read-only volume,
        // a missing parent, or an fd limit, none of which are a permission problem.
        throw SecretsManagerException(
            "Cannot write cache $targetPath: could not create a temporary file in ${targetPath.parent} " +
            "(${e.javaClass.simpleName}: ${e.message}). The directory must exist and be writable.",
            e
        )
    }
    try {
        try {
            Files.setPosixFilePermissions(tmpPath, PosixFilePermissions.fromString("rw-------"))
        } catch (_: UnsupportedOperationException) {
            tmpPath.toFile().let { f ->
                f.setReadable(false, false)
                f.setWritable(false, false)
                f.setReadable(true, true)
                f.setWritable(true, true)
            }
        }
        Files.write(tmpPath, data)
        try {
            Files.move(tmpPath, targetPath, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(tmpPath, targetPath, StandardCopyOption.REPLACE_EXISTING)
        }
    } catch (e: Exception) {
        try { Files.deleteIfExists(tmpPath) } catch (_: Exception) { }
        throw e
    }
}

fun getCachedValue(): ByteArray {
    try {
        return FileInputStream("cache.dat").use { it.readBytes() } // .use{} closes on exception
    } catch (e: Exception) {
        throw SecretsManagerException("Cached value does not exist")
    }
}

@ExperimentalSerializationApi
class InMemoryStorage(configJson: String? = null) : KeyValueStorage {

    @Serializable
    private data class LocalConfig(
        var hostname: String? = null,
        var clientId: String? = null,
        var privateKey: String? = null,
        var clientKey: String? = null,
        var appKey: String? = null,
        var appOwnerPublicKey: String? = null,
        var serverPublicKeyId: String? = null,
        var serverPublicKey: String? = null
    )

    private val strings: MutableMap<String, String> = HashMap()

    init {
        if (configJson != null) {
            val jsonStr: String = try {
                bytesToString(base64ToBytes(configJson))
            } catch(e: Exception) {
                configJson
            }
            val config = Json.decodeFromString<LocalConfig>(jsonStr)
            val optSetFn: (key: String, value: String?) -> Unit = { key, value -> if (value != null) strings[key] = value }
            optSetFn(KEY_HOSTNAME, config.hostname)
            optSetFn(KEY_CLIENT_ID, config.clientId)
            optSetFn(KEY_PRIVATE_KEY, config.privateKey)
            optSetFn(KEY_CLIENT_KEY, config.clientKey)
            optSetFn(KEY_APP_KEY, config.appKey)
            optSetFn(KEY_OWNER_PUBLIC_KEY, config.appOwnerPublicKey)
            optSetFn(KEY_SERVER_PUBLIC_KEY_ID, config.serverPublicKeyId)
            optSetFn(KEY_SERVER_PUBLIC_KEY, config.serverPublicKey)
        }
    }

    override fun getString(key: String): String? {
        return strings[key]
    }

    override fun saveString(key: String, value: String) {
        strings[key] = value
    }

    override fun getBytes(key: String): ByteArray? {
        val stringValue = getString(key) ?: return null
        return base64ToBytes(stringValue)
    }

    override fun saveBytes(key: String, value: ByteArray) {
        saveString(key, bytesToBase64(value))
    }

    override fun delete(key: String) {
        strings.remove(key)
    }
}

// LocalConfigStorage becomes in memory storage if config name is null
@ExperimentalSerializationApi
class LocalConfigStorage(configName: String? = null) : KeyValueStorage {

    @Serializable
    private data class LocalConfig(
        var hostname: String? = null,
        var clientId: String? = null,
        var privateKey: String? = null,
        var clientKey: String? = null,
        var appKey: String? = null,
        var appOwnerPublicKey: String? = null,
        var serverPublicKeyId: String? = null,
        var serverPublicKey: String? = null
    )

    private val file = configName?.let { File(it) }
    private var storage: InMemoryStorage = if (file != null && file.exists()) {
        val content = file.readText(Charsets.UTF_8)
        InMemoryStorage(content)
    } else {
        InMemoryStorage()
    }

    private val prettyJson = Json { prettyPrint = true }

    private fun saveToFile() {
        if (file == null) return
        val targetPath = file.absoluteFile.toPath()
        val tmpPath = try {
            Files.createTempFile(targetPath.parent, "ksm_", ".tmp")
        } catch (e: IOException) {
            // Report what actually failed: createTempFile also fails on a full or read-only volume,
            // a missing parent, or an fd limit, none of which are a permission problem.
            throw SecretsManagerException(
                "Cannot write config $targetPath: could not create a temporary file in ${targetPath.parent} " +
                "(${e.javaClass.simpleName}: ${e.message}). The directory must exist and be writable; " +
                "move the config to a writable directory or use InMemoryStorage with an injected config string.",
                e
            )
        }
        try {
            try {
                Files.setPosixFilePermissions(tmpPath, PosixFilePermissions.fromString("rw-------"))
            } catch (_: UnsupportedOperationException) {
                tmpPath.toFile().let { f ->
                    f.setReadable(false, false)
                    f.setWritable(false, false)
                    f.setReadable(true, true)
                    f.setWritable(true, true)
                }
            }
            val config = LocalConfig(
                hostname = storage.getString(KEY_HOSTNAME),
                clientId = storage.getString(KEY_CLIENT_ID),
                privateKey = storage.getString(KEY_PRIVATE_KEY),
                clientKey = storage.getString(KEY_CLIENT_KEY),
                appKey = storage.getString(KEY_APP_KEY),
                appOwnerPublicKey = storage.getString(KEY_OWNER_PUBLIC_KEY),
                serverPublicKeyId = storage.getString(KEY_SERVER_PUBLIC_KEY_ID),
                serverPublicKey = storage.getString(KEY_SERVER_PUBLIC_KEY)
            )
            Files.write(tmpPath, prettyJson.encodeToString(config).toByteArray())
            try {
                Files.move(tmpPath, targetPath, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(tmpPath, targetPath, StandardCopyOption.REPLACE_EXISTING)
            }
        } catch (e: Exception) {
            try { Files.deleteIfExists(tmpPath) } catch (_: Exception) { }
            throw e
        }
    }

    override fun getString(key: String): String? {
        return storage.getString(key)
    }

    override fun saveString(key: String, value: String) {
        storage.saveString(key, value)
        saveToFile()
    }

    override fun getBytes(key: String): ByteArray? {
        return storage.getBytes(key)
    }

    override fun saveBytes(key: String, value: ByteArray) {
        storage.saveBytes(key, value)
        saveToFile()
    }

    override fun delete(key: String) {
        storage.delete(key)
        saveToFile()
    }
}