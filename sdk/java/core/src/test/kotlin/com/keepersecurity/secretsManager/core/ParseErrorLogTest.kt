package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The SDK logs a line when it skips or recovers a record, file, folder, or link whose decrypted
 * JSON does not parse. These tests decode through the real kotlinx-serialization parser, because
 * its message wording is what put decrypted text into the log.
 */
@ExperimentalSerializationApi
internal class ParseErrorLogTest {

    private val canary = "S3cr3t-Pa55w0rd!"

    private class Captured(val out: String, val err: String) {
        val all: String get() = out + err
    }

    private fun capture(block: () -> Unit): Captured {
        val origOut = System.out
        val origErr = System.err
        val outBuf = ByteArrayOutputStream()
        val errBuf = ByteArrayOutputStream()
        System.setOut(PrintStream(outBuf, true, "UTF-8"))
        System.setErr(PrintStream(errBuf, true, "UTF-8"))
        try {
            block()
        } finally {
            System.setOut(origOut)
            System.setErr(origErr)
        }
        return Captured(outBuf.toString("UTF-8"), errBuf.toString("UTF-8"))
    }

    private val goodRecordJson = """{"title":"good","type":"login","fields":[{"type":"login","value":["ok"]}],"custom":[]}"""

    private fun recordsOptions(
        recordJsonByUid: Map<String, String>,
        filesByUid: Map<String, String> = emptyMap()
    ): SecretsManagerOptions {
        val transmissionKey = ByteArray(32) { it.toByte() }
        TestStubs.transmissionKeyStub = { transmissionKey }
        val appKey = getRandomBytes(32)
        val entries = recordJsonByUid.map { (uid, json) ->
            val recordKey = getRandomBytes(32)
            val encRecordKey = bytesToBase64(encrypt(recordKey, appKey))
            val encData = bytesToBase64(encrypt(stringToBytes(json), recordKey))
            val files = filesByUid[uid]?.let { fileJson ->
                val fileKey = getRandomBytes(32)
                val encFileKey = bytesToBase64(encrypt(fileKey, recordKey))
                val encFileData = bytesToBase64(encrypt(stringToBytes(fileJson), fileKey))
                """[{"fileUid":"file-$uid","fileKey":"$encFileKey","data":"$encFileData","url":null,"thumbnailUrl":null}]"""
            } ?: "null"
            """{"recordUid":"$uid","recordKey":"$encRecordKey","data":"$encData","revision":1,"isEditable":true,"files":$files,"innerFolderUid":null}"""
        }
        val response = encrypt(stringToBytes(
            """{"encryptedAppKey":null,"folders":null,"records":[${entries.joinToString(",")}]}"""
        ), transmissionKey)
        val storage = InMemoryStorage()
        initializeStorage(storage, "US:FAKE_CLIENT_KEY")
        storage.saveBytes(KEY_APP_KEY, appKey)
        return SecretsManagerOptions(storage, queryFunction = { _, _, _ -> KeeperHttpResponse(200, response) })
    }

    // Each entry is a field shape the parser rejects. The canary sits in a value, so any log text
    // built from the parser message would carry it. Cases differ in which kotlinx error path
    // produces the message: a type mismatch, a tree-decoder error (value before type), an
    // unknown key, an unknown field type, and a record long enough to be truncated in the message.
    private val badRecordShapes = mapOf(
        "bare string in array slot" to
            """{"title":"t","type":"login","fields":[{"type":"password","value":"$canary"}],"custom":[]}""",
        "string in boolean slot" to
            """{"title":"t","type":"login","fields":[{"type":"password","required":"$canary","value":[]}],"custom":[]}""",
        "value before type" to
            """{"title":"t","type":"login","fields":[{"value":"$canary","type":"password"}],"custom":[]}""",
        "unknown key" to
            """{"title":"t","type":"login","fields":[{"type":"password","value":["$canary"],"futureProp":"$canary"}],"custom":[]}""",
        "unknown field type" to
            """{"title":"t","type":"login","fields":[{"type":"futureType","value":["$canary"]}],"custom":[]}""",
        "long record" to
            """{"title":"${"x".repeat(400)}","type":"login","fields":[{"type":"password","value":"$canary"}],"custom":[]}"""
    )

    @Test
    fun testRecordParseFailureNeverLogsDecryptedJson() {
        val leaking = mutableListOf<String>()
        for ((name, json) in badRecordShapes) {
            val options = recordsOptions(mapOf("bad-uid" to json, "good-uid" to goodRecordJson))
            var uids = emptyList<String>()
            val logs = capture { uids = getSecrets(options).records.map { it.recordUid } }
            if (logs.all.contains(canary)) leaking.add(name)
            assertTrue(uids.contains("good-uid"), "[$name] the good record must still load")
        }
        assertTrue(leaking.isEmpty(), "these record shapes put decrypted text in the log: $leaking")
    }

    @Test
    fun testUnparseableRecordIsStillSkippedAndNamed() {
        val options = recordsOptions(mapOf(
            "bad-uid" to badRecordShapes.getValue("bare string in array slot"),
            "good-uid" to goodRecordJson
        ))
        var uids = emptyList<String>()
        val logs = capture { uids = getSecrets(options).records.map { it.recordUid } }
        assertEquals(listOf("good-uid"), uids)
        assertTrue(logs.all.contains("bad-uid"), "the log must name the record UID. Got: ${logs.all}")
        assertTrue(logs.all.contains("Record will be skipped"), "the log must say the record is skipped. Got: ${logs.all}")
    }

    @Test
    fun testFileMetadataParseFailureNeverLogsDecryptedJson() {
        val options = recordsOptions(
            mapOf("rec-uid" to goodRecordJson),
            mapOf("rec-uid" to """{"title":"f","name":"f.txt","size":"$canary"}""")
        )
        val logs = capture { getSecrets(options) }
        assertFalse(logs.all.contains(canary), "the log must not hold decrypted text. Got: ${logs.all}")
        assertTrue(logs.all.contains("file-rec-uid"), "the skipped file must be named. Got: ${logs.all}")
    }

    @Test
    fun testFolderNameParseFailureNeverLogsDecryptedJson() {
        val transmissionKey = ByteArray(32) { it.toByte() }
        TestStubs.transmissionKeyStub = { transmissionKey }
        val appKey = getRandomBytes(32)
        val folderKey = getRandomBytes(32)
        val encFolderKey = bytesToBase64(encrypt(folderKey, appKey))
        val encData = bytesToBase64(encrypt(stringToBytes("""{"name":["$canary"]}"""), folderKey, true))
        val response = encrypt(stringToBytes(
            """{"encryptedAppKey":null,"folders":[{"folderUid":"bad-folder","folderKey":"$encFolderKey","data":"$encData","parent":null,"records":null}],"records":null}"""
        ), transmissionKey)
        val storage = InMemoryStorage()
        initializeStorage(storage, "US:FAKE_CLIENT_KEY")
        storage.saveBytes(KEY_APP_KEY, appKey)
        val options = SecretsManagerOptions(storage, queryFunction = { _, _, _ -> KeeperHttpResponse(200, response) })

        val logs = capture { getFolders(options) }
        assertFalse(logs.all.contains(canary), "the log must not hold decrypted text. Got: ${logs.all}")
        assertTrue(logs.all.contains("bad-folder"), "the skipped folder must be named. Got: ${logs.all}")
    }

    // The skip logs in the getSecrets loop and in skipReason() print only the exception class.
    // The exceptions are synthetic because none of these catch blocks can be made to carry
    // decrypted text through the public API today. The test guards a future parser, serializer,
    // or library upgrade that does.
    @Test
    fun testSkipReasonNeverIncludesTheExceptionMessage() {
        val leaking = mutableListOf<String>()
        val thrown = listOf(
            IllegalArgumentException("JSON input: $canary"),
            IllegalStateException("JSON input: $canary"),
            RuntimeException("JSON input: $canary"),
            java.io.IOException("JSON input: $canary")
        )
        for (e in thrown) {
            val reason = skipReason(e)
            if (reason.contains(canary)) leaking.add(e.javaClass.simpleName)
            assertTrue(reason.contains(e.javaClass.simpleName), "the reason must name the class. Got: $reason")
        }
        assertTrue(leaking.isEmpty(), "skipReason put the exception message in the log for: $leaking")
    }

    private fun failureMessageOf(data: String, key: ByteArray): String =
        try {
            decrypt(data, key)
            ""
        } catch (e: Exception) {
            e.message.orEmpty()
        }

    // A record, a record inside a folder, and a folder each fail to decrypt. The decrypt failure
    // message (not decrypted text) is what the old log line printed after the class name, so its
    // absence shows the loop catch blocks no longer print e.message.
    @Test
    fun testLoopSkipLogsNameTheUidAndClassButNotTheMessage() {
        val transmissionKey = ByteArray(32) { it.toByte() }
        TestStubs.transmissionKeyStub = { transmissionKey }
        val appKey = getRandomBytes(32)
        val wrongKey = getRandomBytes(32)
        val goodKey = getRandomBytes(32)
        val folderKey = getRandomBytes(32)

        val recordKeyUnderWrongKey = bytesToBase64(encrypt(goodKey, wrongKey))
        val recordKeyUnderAppKey = bytesToBase64(encrypt(goodKey, appKey))
        val encData = bytesToBase64(encrypt(stringToBytes(goodRecordJson), goodKey))
        val encFolderKey = bytesToBase64(encrypt(folderKey, appKey))
        val folderKeyUnderWrongKey = bytesToBase64(encrypt(folderKey, wrongKey))

        fun record(uid: String, key: String) =
            """{"recordUid":"$uid","recordKey":"$key","data":"$encData","revision":1,"isEditable":true,"files":null,"innerFolderUid":null}"""

        val response = encrypt(stringToBytes(
            """{"encryptedAppKey":null,"records":[${record("bad-record", recordKeyUnderWrongKey)},${record("good-record", recordKeyUnderAppKey)}],""" +
            """"folders":[""" +
            """{"folderUid":"folder-with-bad-record","folderKey":"$encFolderKey","data":null,"parent":null,"records":[${record("bad-folder-record", recordKeyUnderWrongKey)}]},""" +
            """{"folderUid":"bad-folder","folderKey":"$folderKeyUnderWrongKey","data":null,"parent":null,"records":null}]}"""
        ), transmissionKey)
        val storage = InMemoryStorage()
        initializeStorage(storage, "US:FAKE_CLIENT_KEY")
        storage.saveBytes(KEY_APP_KEY, appKey)
        val options = SecretsManagerOptions(storage, queryFunction = { _, _, _ -> KeeperHttpResponse(200, response) })

        var uids = emptyList<String>()
        val logs = capture { uids = getSecrets(options).records.map { it.recordUid } }

        assertEquals(listOf("good-record"), uids)
        assertEquals("", logs.out, "skip diagnostics must go to standard error only")
        for (uid in listOf("bad-record", "bad-folder-record", "bad-folder")) {
            assertTrue(logs.err.contains(uid), "the log must name $uid. Got: ${logs.err}")
        }
        assertTrue(logs.err.contains("skipped due to error"), "the log must keep the skip phrase. Got: ${logs.err}")
        val messages = listOf(
            failureMessageOf(recordKeyUnderWrongKey, appKey),
            failureMessageOf(recordKeyUnderWrongKey, folderKey),
            failureMessageOf(folderKeyUnderWrongKey, appKey)
        )
        for (message in messages) {
            assertTrue(message.isNotBlank(), "the decrypt failure must have a message for this test to mean anything")
            assertFalse(logs.err.contains(message), "the log must not print the failure message '$message'. Got: ${logs.err}")
        }
    }
}
