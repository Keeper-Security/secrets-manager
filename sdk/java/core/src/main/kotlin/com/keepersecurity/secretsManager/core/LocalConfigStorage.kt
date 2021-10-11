package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.*
import java.util.*
import kotlin.collections.HashMap

fun saveCachedValue(data: ByteArray) {
    val fos = FileOutputStream("cache.dat")
    fos.write(data)
    fos.close()
}

fun getCachedValue(): ByteArray {
    try {
        val fis = FileInputStream("cache.dat")
        val bytes = fis.readBytes()
        fis.close()
        return bytes
    } catch (e: Exception) {
        throw Exception("Cached value does not exist")
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
        var serverPublicKeyId: String? = null
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
            optSetFn(KEY_SERVER_PUBIC_KEY_ID, config.serverPublicKeyId)
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
        var serverPublicKeyId: String? = null
    )

    private val file = configName?.let { File(it) }
    private var storage: InMemoryStorage = if (file != null && file.exists()) {
        val inputStream = BufferedReader(FileReader(file))
        InMemoryStorage(inputStream.readText())
    } else {
        InMemoryStorage()
    }

    private val prettyJson = Json { prettyPrint = true }

    private fun saveToFile() {
        if (file == null) return
        val config = LocalConfig()
        config.hostname = storage.getString(KEY_HOSTNAME)
        config.clientId = storage.getString(KEY_CLIENT_ID)
        config.privateKey = storage.getString(KEY_PRIVATE_KEY)
        config.clientKey = storage.getString(KEY_CLIENT_KEY)
        config.appKey = storage.getString(KEY_APP_KEY)
        config.serverPublicKeyId = storage.getString(KEY_SERVER_PUBIC_KEY_ID)
        val json = prettyJson.encodeToString(config)
        val outputStream = BufferedWriter(FileWriter(file))
        outputStream.write(json)
        outputStream.close()
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