package com.keepersecurity.secretsManager.core

import kotlinx.serialization.*
import kotlinx.serialization.json.*
import java.io.OutputStreamWriter
import java.net.URL
import java.security.KeyManagementException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.*


//const postQuery = async (storage: KeyValueStorage, path: string, transmissionKey: TransmissionKey,
//payload: Uint8Array, signature: Uint8Array): Promise<KeeperHttpResponse> => {
//    const url = await storage.getString(KEY_URL)
//    if (!url) {
//        throw new Error('url is missing from the configuration')
//    }
//    const httpResponse = await platform.post(`${url}/${path}`, payload, {
//        PublicKeyId: transmissionKey.publicKeyId.toString(),
//        TransmissionKey: platform.bytesToBase64(transmissionKey.encryptedKey),
//        Authorization: `Signature ${platform.bytesToBase64(signature)}`
//    })
//    if (httpResponse.statusCode !== 200) {
//        throw new Error(platform.bytesToString(httpResponse.data))
//    }
//    return httpResponse
//}

data class KeeperHttpResponse(val statusCode: Int, val data: ByteArray?)

fun postQuery(path: String): KeeperHttpResponse {
    val baseUrl = "https://local.keepersecurity.com/api/rest/sm/v1/$path"
    with(URL(baseUrl).openConnection() as HttpsURLConnection) {
        sslSocketFactory = trustAllSocketFactory()
        requestMethod = "POST"
        doOutput = true

        with(OutputStreamWriter(outputStream)) {
            write("SSD")
            flush()
        }
        val statusCode = responseCode
        val bytes = when {
            errorStream != null -> errorStream.readAllBytes()
            else -> inputStream.readAllBytes()
        }
        return KeeperHttpResponse(statusCode, bytes)
    }
}

fun trustAllSocketFactory(): SSLSocketFactory {
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

class SecretsManager {
    fun doSomething(): Boolean {
        val data = Project("kotlinx.serialization", "Kotlin")
        val string = Json.encodeToString(data)
        println(string) // {"name":"kotlinx.serialization","language":"Kotlin"}
        // Deserializing back into objects
        val obj = Json.decodeFromString<Project>(string)
        println(obj) // Project(name=kotlinx.serialization, language=Kotlin)
        return true
    }
}
