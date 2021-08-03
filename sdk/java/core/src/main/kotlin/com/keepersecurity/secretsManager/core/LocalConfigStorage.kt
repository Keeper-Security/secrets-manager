package com.keepersecurity.secretsManager.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.*

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

// LocalConfigStorage becomes in memory storage if config name is null
class LocalConfigStorage(configName: String? = null) : KeyValueStorage {

    @Serializable
    private data class LocalConfig(
        var hostname: String? = null,
        var clientId: String? = null,
        var privateKey: String? = null,
        var publicKey: String? = null,
        var clientKey: String? = null,
        var appKey: String? = null,
        var serverPublicKeyId: String? = null
    )

    private val file = configName?.let { File(it) }
    private val strings: MutableMap<String, String> = HashMap()

    init {
        if (file != null && file.exists()) {
            val inputStream = BufferedReader(FileReader(file))
            val config = Json.decodeFromString<LocalConfig>(inputStream.readText())
            val optSetFn: (key: String, value: String?) -> Unit = { key, value -> if (value != null) strings[key] = value }
            optSetFn(KEY_HOSTNAME, config.hostname)
            optSetFn(KEY_CLIENT_ID, config.clientId)
            optSetFn(KEY_PRIVATE_KEY, config.privateKey)
            optSetFn(KEY_PUBLIC_KEY, config.publicKey)
            optSetFn(KEY_CLIENT_KEY, config.clientKey)
            optSetFn(KEY_APP_KEY, config.appKey)
            optSetFn(KEY_SERVER_PUBIC_KEY_ID, config.serverPublicKeyId)
        }
    }


    private fun saveToFile() {
        if (file == null) return
        val config = LocalConfig()
        config.hostname = strings[KEY_HOSTNAME]
        config.clientId = strings[KEY_CLIENT_ID]
        config.privateKey = strings[KEY_PRIVATE_KEY]
        config.publicKey = strings[KEY_PUBLIC_KEY]
        config.clientKey = strings[KEY_CLIENT_KEY]
        config.appKey = strings[KEY_APP_KEY]
        config.serverPublicKeyId = strings[KEY_SERVER_PUBIC_KEY_ID]
        val json = Json { prettyPrint = true }.encodeToString(config)
        val outputStream = BufferedWriter(FileWriter(file))
        outputStream.write(json);
        outputStream.close()
    }

    override fun getString(key: String): String? {
        return strings[key]
    }

    override fun saveString(key: String, value: String) {
        strings[key] = value
        saveToFile()
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
        saveToFile()
    }
}