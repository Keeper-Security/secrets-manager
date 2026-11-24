package com.keepersecurity.secretsManager.core

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import kotlinx.serialization.ExperimentalSerializationApi
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x509.Time
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.Signature
import java.security.cert.CertificateFactory
import java.util.Date
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@ExperimentalSerializationApi
internal class NsfFileDownloadTest {
    @Test
    fun downloadsFileFromNsfRecordInBothResponseForms() {
        val appKey = getRandomBytes(32)
        val folderKey = getRandomBytes(32)
        val recordKey = getRandomBytes(32)
        val fileKey = getRandomBytes(32)
        val contents = byteArrayOf(0, 10, 13, -1)
        val ciphertext = encrypt(contents, fileKey)
        val fileRequests = AtomicInteger()

        val fileServer = HttpsServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val proxyProperty = "http.nonProxyHosts"
        val previousNonProxyHosts = System.getProperty(proxyProperty)
        try {
            System.setProperty(proxyProperty, listOfNotNull(previousNonProxyHosts, "127.0.0.1").joinToString("|"))
            fileServer.httpsConfigurator = HttpsConfigurator(loopbackTlsContext())
            fileServer.createContext("/attachment") { exchange ->
                try {
                    if (exchange.requestMethod == "GET" && exchange.requestURI.path == "/attachment") {
                        fileRequests.incrementAndGet()
                        exchange.sendResponseHeaders(200, ciphertext.size.toLong())
                        exchange.responseBody.use { it.write(ciphertext) }
                    } else {
                        exchange.sendResponseHeaders(404, -1)
                    }
                } finally {
                    exchange.close()
                }
            }
            fileServer.start()

            val url = "https://127.0.0.1:${fileServer.address.port}/attachment"
            val fileData = """{"title":"Sample","name":"sample.txt","size":${contents.size},"type":"text/plain"}"""
            val file = """{"fileUid":"file-uid","fileKey":"${bytesToBase64(encrypt(fileKey, recordKey))}",
                "data":"${encryptedJson(fileData, fileKey)}","url":"$url","thumbnailUrl":null}"""
            val recordData = """{"title":"Owner","type":"login","fields":[{"type":"fileRef","value":["file-uid"]}]}"""

            for (nested in listOf(true, false)) {
                val record = """{"recordUid":"record-uid","recordKey":"${bytesToBase64(encrypt(recordKey, folderKey))}",
                    "data":"${encryptedJson(recordData, recordKey)}","revision":1,"isEditable":true,"files":[$file],
                    "innerFolderUid":${if (nested) "null" else "\"nsf-uid\""}}"""
                val folder = """{"folderUid":"nsf-uid","folderKey":"${bytesToBase64(encrypt(folderKey, appKey))}",
                    "data":"${encryptedJson("""{"name":"Drive"}""", folderKey)}","parent":null,
                    "records":[${if (nested) record else ""}]}"""
                val response = """{"encryptedAppKey":null,"folders":[$folder],"records":[${if (nested) "" else record}]}"""
                val storage = InMemoryStorage()
                initializeStorage(storage, "US:FAKE_CLIENT_KEY")
                storage.saveBytes(KEY_APP_KEY, appKey)
                val options = SecretsManagerOptions(
                    storage,
                    queryFunction = { requestUrl, transmissionKey, _ ->
                        assertTrue(requestUrl.endsWith("/get_secret"))
                        KeeperHttpResponse(200, encrypt(stringToBytes(response), transmissionKey.key))
                    },
                    allowUnverifiedCertificate = true,
                    loggingEnabled = false,
                    connectTimeoutMillis = 5_000,
                    readTimeoutMillis = 5_000
                )

                val owner = assertNotNull(getSecrets(options, listOf("record-uid")).getRecordByUid("record-uid"))
                assertTrue(owner.isDrive)
                assertEquals("nsf-uid", owner.folderUid)
                val attachment = assertNotNull(owner.getFileByUid("file-uid"))
                assertEquals("sample.txt", attachment.data.name)
                assertEquals(contents.size.toLong(), attachment.data.size)
                assertContentEquals(contents, downloadFile(options, attachment))
            }
            assertEquals(2, fileRequests.get())
        } finally {
            fileServer.stop(0)
            if (previousNonProxyHosts == null) System.clearProperty(proxyProperty)
            else System.setProperty(proxyProperty, previousNonProxyHosts)
        }
    }

    private fun encryptedJson(json: String, key: ByteArray): String =
        bytesToBase64(encrypt(stringToBytes(json), key))

    private fun loopbackTlsContext(): SSLContext {
        val keys = generateKeyPair()
        val name = X500Name("CN=127.0.0.1")
        val now = System.currentTimeMillis()
        val algorithm = AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)
        val extensions = ExtensionsGenerator().apply {
            addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.iPAddress, "127.0.0.1")))
        }
        val certificateBody = V3TBSCertificateGenerator().apply {
            setSerialNumber(ASN1Integer(1L))
            setSignature(algorithm)
            setIssuer(name)
            setSubject(name)
            setStartDate(Time(Date(now - 60_000)))
            setEndDate(Time(Date(now + 3_600_000)))
            setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keys.public.encoded))
            setExtensions(extensions.generate())
        }.generateTBSCertificate()
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(keys.private)
            update(certificateBody.encoded)
            sign()
        }
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(
            DERSequence(arrayOf(certificateBody, algorithm, DERBitString(signature))).encoded.inputStream()
        )
        val password = charArrayOf()
        val keyStore = KeyStore.getInstance("JKS").apply {
            load(null, password)
            setKeyEntry("loopback", keys.private, password, arrayOf(certificate))
        }
        val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(keyStore, password)
        }.keyManagers
        return SSLContext.getInstance("TLS").apply { init(keyManagers, null, null) }
    }
}
