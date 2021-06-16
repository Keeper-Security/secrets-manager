package com.keepersecurity.secretsManager.core

import java.io.*
import kotlin.test.Test

internal class SecretsManagerTest {

    @Test
    fun postQuery() {
        val storage = object : KeyValueStorage {
            val file = File("config.txt")
            val strings: MutableMap<String, String> = HashMap()
            val bytes: MutableMap<String, ByteArray> = HashMap()

            init {
                if (file.exists()) {
                    val inputStream = BufferedReader(FileReader(file))
                    inputStream.lines().forEach {
                        val kv = it.split(": ")
                        strings[kv[0]] = kv[1]
                    }
                }
            }

            fun store() {
                val outputStream = BufferedWriter(FileWriter(file))
                for (kv in strings) {
                    outputStream.write("${kv.key}: ${kv.value}\n")
                }
                outputStream.close()
            }

            override fun getString(key: String): String? {
                return strings[key]
            }

            override fun saveString(key: String, value: String) {
                strings[key] = value
                store()
            }

            override fun getBytes(key: String): ByteArray? {
                val stringValue = getString(key) ?: return null
                return base64ToBytes(stringValue)
            }

            override fun saveBytes(key: String, value: ByteArray) {
                saveString(key, bytesToBase64(value))
            }
        }
        initializeStorage(storage, "EvdTdbH1xbHuRcja7QG3wMOyLUbvoQgF9WkkrHTdkh8", "local.keepersecurity.com")
        getSecrets(storage)
    }
}