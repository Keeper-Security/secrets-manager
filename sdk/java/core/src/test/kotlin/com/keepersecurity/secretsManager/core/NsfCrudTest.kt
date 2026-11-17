package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.*

@ExperimentalSerializationApi
internal class NsfCrudTest {

    private data class Request(val path: String, val body: JsonObject)

    private class Server {
        val appKey = getRandomBytes(32)
        val rootKey = getRandomBytes(32)
        val childKey = getRandomBytes(32)
        val driveKey = getRandomBytes(32)
        val ownerKeys = generateKeyPair()
        val storage = InMemoryStorage()
        val requests = mutableListOf<Request>()
        val responses = mutableMapOf<String, String>()
        var respond: ((Request) -> String?)? = null
        val options: SecretsManagerOptions

        init {
            initializeStorage(storage, "US:FAKE_CLIENT_KEY")
            storage.saveBytes(KEY_CLIENT_KEY, getRandomBytes(32))
            storage.saveBytes(KEY_APP_KEY, appKey)
            storage.saveBytes(KEY_OWNER_PUBLIC_KEY, extractPublicRaw(ownerKeys.public))
            options = SecretsManagerOptions(
                storage,
                queryFunction = { url, transmissionKey, payload ->
                    val request = Request(
                        url.substringAfterLast('/'),
                        Json.parseToJsonElement(bytesToString(decrypt(payload.payload, transmissionKey.key))).jsonObject
                    )
                    requests.add(request)
                    val response = respond?.invoke(request) ?: responses[request.path] ?: ""
                    KeeperHttpResponse(
                        200,
                        if (response.isEmpty()) ByteArray(0) else encrypt(stringToBytes(response), transmissionKey.key)
                    )
                },
                loggingEnabled = false
            )
            responses["get_folders"] = response()
            responses["get_secret"] = response()
            responses["delete_folder"] = """{"folders":[]}"""
            responses["delete_secret"] = """{"records":[]}"""
        }

        fun paths(): List<String> = requests.map { it.path }

        fun payload(path: String): JsonObject = requests.last { it.path == path }.body

        fun classicRoot(data: String = """{"name":"Classic"}""", useGcm: Boolean = false): String =
            folder("classic-root", rootKey, null, data, useGcm)

        fun classicChild(
            data: String = """{"name":"Child"}""",
            useGcm: Boolean = false,
            uid: String = "classic-child",
            parent: String = "classic-root",
            key: ByteArray = childKey
        ): String = folder(uid, key, parent, data, useGcm)

        fun folder(
            uid: String,
            key: ByteArray,
            parent: String?,
            data: String?,
            useGcm: Boolean,
            records: List<String> = emptyList(),
            wrappedKey: ByteArray? = null,
            encryptedData: ByteArray? = null
        ): String {
            val wrap = wrappedKey ?: encrypt(key, if (parent == null) appKey else rootKey, parent != null && !useGcm)
            val value = encryptedData ?: data?.let { encrypt(stringToBytes(it), key, !useGcm) }
            return buildJsonObject {
                put("folderUid", uid)
                put("folderKey", bytesToBase64(wrap))
                put("parent", parent?.let(::JsonPrimitive) ?: JsonNull)
                put("data", value?.let { JsonPrimitive(bytesToBase64(it)) } ?: JsonNull)
                put("records", JsonArray(records.map { Json.parseToJsonElement(it) }))
            }.toString()
        }

        fun driveFolder(
            data: String = """{"name":"Drive"}""",
            records: List<String> = emptyList(),
            padded: Boolean = true,
            uid: String = "nsf-root",
            key: ByteArray = driveKey
        ): String {
            val encrypted = encrypt(stringToBytes(data), key)
            return folder(
                uid, key, null, null, true, records,
                encryptedData = if (padded) encrypted.copyOf(255) else encrypted
            )
        }

        fun record(
            uid: String,
            recordKey: ByteArray,
            wrappingKey: ByteArray,
            innerFolderUid: String? = null
        ): String = buildJsonObject {
            put("recordUid", uid)
            put("recordKey", bytesToBase64(encrypt(recordKey, wrappingKey)))
            put("data", bytesToBase64(encrypt(
                stringToBytes("""{"title":"Existing","type":"login","fields":[],"custom":[]}"""),
                recordKey
            )))
            put("revision", 3)
            put("isEditable", true)
            put("files", JsonNull)
            put("innerFolderUid", innerFolderUid?.let(::JsonPrimitive) ?: JsonNull)
        }.toString()
    }

    private companion object {
        const val CREATE_REFUSED =
            "Unable to create folder - the SDK cannot create a folder in an NSF (Keeper Drive) folder."
        const val UPDATE_REFUSED =
            "Unable to update folder - the SDK cannot update an NSF (Keeper Drive) folder."

        fun response(folders: List<String> = emptyList(), records: List<String> = emptyList()): String =
            """{"encryptedAppKey":null,"folders":[${folders.joinToString(",")}],"records":[${records.joinToString(",")}]}"""

        fun item(uid: String, code: String = "ok", message: String? = null): String = buildJsonObject {
            put("folderUid", uid)
            put("responseCode", code)
            if (message != null) put("errorMessage", message)
        }.toString()

        fun deleteResponse(vararg items: String): String = """{"folders":[${items.joinToString(",")}]}"""
    }

    private fun recordData(title: String = "New record"): KeeperRecordData =
        KeeperRecordData(title, "login", mutableListOf(Password(value = mutableListOf("dummy-password"))))

    private fun driveFolder(server: Server, uid: String = "nsf-root"): KeeperFolder =
        KeeperFolder(server.driveKey, uid, null, "Private folder name", useGcm = true, isDrive = true)

    private fun content(body: JsonObject, name: String): String = body.getValue(name).jsonPrimitive.content

    private fun bytes(body: JsonObject, name: String): ByteArray = base64ToBytes(content(body, name))

    private fun webBytes(body: JsonObject, name: String): ByteArray = webSafe64ToBytes(content(body, name))

    private fun json(data: ByteArray): JsonObject = Json.parseToJsonElement(bytesToString(data)).jsonObject

    @Test
    fun gcmRootNamesReadWithAndWithoutColumnPadding() {
        for (padded in listOf(false, true)) {
            val server = Server()
            server.responses["get_folders"] = response(listOf(server.driveFolder(padded = padded)))

            val folder = getFolders(server.options).single()

            assertEquals("Drive", folder.name)
            assertTrue(folder.useGcm)
            assertFalse(folder.isDrive)
            assertNull(folder.parentUid)
            assertContentEquals(server.driveKey, folder.folderKey)
            assertEquals(listOf("get_folders"), server.paths())
        }
    }

    @Test
    fun gcmRootNamesKeepAuthenticatedTrailingZeroBytes() {
        val values = listOf(
            "AAAAAAAAAAAAAADu1UkrjsTrJ25pOfACOVL9rOzpLiVIr6kaR0WLmfqpcYT9QIgA",
            "AAAAAAAAAAAAAPZdtk91tK8g2OstudgS8ieElc5wPZ9ZHtF/qhqTm5l3Gs7mzAAA"
        )
        val key = ByteArray(32) { it.toByte() }
        for ((index, encoded) in values.withIndex()) {
            for (padded in listOf(false, true)) {
                val server = Server()
                val cipherText = base64ToBytes(encoded)
                assertTrue(cipherText.takeLast(index + 1).all { it == 0.toByte() })
                server.responses["get_folders"] = response(listOf(server.folder(
                    "zero-uid", key, null, null, true,
                    encryptedData = if (padded) cipherText.copyOf(255) else cipherText
                )))

                val folder = getFolders(server.options).single()

                assertEquals("zero-byte", folder.name)
                assertTrue(folder.useGcm)
            }
        }
    }

    @Test
    fun cbcRootAndBothSubfolderKeyFormatsRemainReadable() {
        val server = Server()
        val gcmKey = getRandomBytes(32)
        server.responses["get_folders"] = response(listOf(
            server.classicRoot(),
            server.classicChild(),
            server.classicChild("""{"name":"GCM child"}""", true, "gcm-child", key = gcmKey)
        ))

        val folders = getFolders(server.options)

        assertEquals(listOf("classic-root", "classic-child", "gcm-child"), folders.map { it.folderUid })
        assertFalse(folders[0].useGcm)
        assertFalse(folders[1].useGcm)
        assertTrue(folders[2].useGcm)
        assertTrue(folders.none { it.isDrive })
    }

    @Test
    fun invalidRootDataDoesNotAbortOtherFolders() {
        val server = Server()
        server.responses["get_folders"] = response(listOf(
            server.classicRoot(),
            server.folder("bad-uid", server.driveKey, null, null, true, encryptedData = ByteArray(19))
        ))

        assertEquals(listOf("classic-root"), getFolders(server.options).map { it.folderUid })
    }

    @Test
    fun includeNsfAddsMarkedFoldersFromOneUnfilteredSecretRequest() {
        val server = Server()
        val existing = server.record("nsf-record", getRandomBytes(32), server.driveKey)
        server.responses["get_folders"] = response(listOf(server.classicRoot(), server.driveFolder()))
        server.responses["get_secret"] = response(listOf(server.driveFolder(records = listOf(existing))))

        val folders = getFolders(server.options, true)

        assertEquals(listOf("classic-root", "nsf-root"), folders.map { it.folderUid })
        assertFalse(folders.first().isDrive)
        assertTrue(folders.last().isDrive)
        assertTrue(folders.last().useGcm)
        assertNull(folders.last().parentUid)
        assertEquals("Drive", folders.last().name)
        assertEquals(listOf("get_folders", "get_secret"), server.paths())
        val lookup = server.payload("get_secret")
        assertFalse(lookup.containsKey("requestedRecords"))
        assertFalse(lookup.containsKey("requestedFolders"))
    }

    @Test
    fun secretResponseMarksNsfFoldersAndEveryNsfRecord() {
        val server = Server()
        val nestedKey = getRandomBytes(32)
        val directKey = getRandomBytes(32)
        val classicKey = getRandomBytes(32)
        server.responses["get_secret"] = response(
            listOf(
                server.driveFolder(records = listOf(server.record("nested", nestedKey, server.driveKey))),
                server.folder("classic-root", server.rootKey, null, null, false,
                    listOf(server.record("classic", classicKey, server.rootKey)))
            ),
            listOf(server.record("direct", directKey, server.driveKey, "nsf-root"))
        )

        val secrets = getSecrets(server.options)

        assertTrue(secrets.records.first { it.recordUid == "nested" }.isDrive)
        assertTrue(secrets.records.first { it.recordUid == "direct" }.isDrive)
        assertFalse(secrets.records.first { it.recordUid == "classic" }.isDrive)
        assertTrue(secrets.folders.first { it.folderUid == "nsf-root" }.isDrive)
        assertEquals("Drive", secrets.folders.first { it.folderUid == "nsf-root" }.name)
    }

    @Test
    fun invalidNsfNameDoesNotRemoveTheRecordMarker() {
        val server = Server()
        server.responses["get_secret"] = response(listOf(server.driveFolder(
            data = """{"name":""",
            records = listOf(server.record("record-uid", getRandomBytes(32), server.driveKey))
        )))

        val secrets = getSecrets(server.options)

        assertTrue(secrets.records.single().isDrive)
        assertTrue(secrets.folders.single().isDrive)
    }

    @Test
    fun allCopiesOfAnNsfRecordCarryTheMarker() {
        val server = Server()
        val key = getRandomBytes(32)
        server.responses["get_secret"] = response(
            listOf(
                server.driveFolder(records = listOf(server.record("shared-uid", key, server.driveKey))),
                server.folder("classic-root", server.rootKey, null, null, false,
                    listOf(server.record("shared-uid", key, server.rootKey)))
            ),
            listOf(server.record("shared-uid", key, server.appKey))
        )

        val copies = getSecrets(server.options).records

        assertEquals(3, copies.size)
        assertTrue(copies.all { it.recordUid == "shared-uid" && it.isDrive })
    }

    @Test
    fun anUndecryptableNsfNameStillKeepsTheFolderAndRecordMarkers() {
        val server = Server()
        server.responses["get_secret"] = response(listOf(server.folder(
            "nsf-root", server.driveKey, null, null, true,
            records = listOf(server.record("record-uid", getRandomBytes(32), server.driveKey)),
            encryptedData = ByteArray(19)
        )))

        val secrets = getSecrets(server.options)

        assertTrue(secrets.records.single().isDrive)
        assertTrue(secrets.folders.single().isDrive)
        assertContentEquals(server.driveKey, secrets.folders.single().folderKey)
    }

    @Test
    fun emptySecretFolderDataDoesNotSetAnNsfMarker() {
        val server = Server()
        val folder = server.folder(
            "classic-root", server.rootKey, null, null, false,
            records = listOf(server.record("classic-record", getRandomBytes(32), server.rootKey))
        )
        val emptyData = JsonObject(Json.parseToJsonElement(folder).jsonObject + ("data" to JsonPrimitive("")))
        server.responses["get_secret"] = response(listOf(emptyData.toString()))

        val secrets = getSecrets(server.options)

        assertFalse(secrets.records.single().isDrive)
        assertFalse(secrets.folders.single().isDrive)
    }

    @Test
    fun includeNsfPropagatesASecretLookupFailure() {
        val server = Server()
        server.responses["get_folders"] = response(listOf(server.classicRoot()))
        val failure = java.io.IOException("Dummy secret lookup failure")
        server.respond = { request -> if (request.path == "get_secret") throw failure else null }

        assertSame(failure, assertFailsWith<java.io.IOException> { getFolders(server.options, true) })

        assertEquals(listOf("get_folders", "get_secret"), server.paths())
    }

    @Test
    fun aClassicGcmRootIsNotMarkedAsNsfByTheCipherFlag() {
        val server = Server()
        server.responses["get_folders"] = response(listOf(server.classicRoot(useGcm = true)))
        server.responses["get_secret"] = response(listOf(server.folder(
            "classic-root", server.rootKey, null, null, false,
            records = listOf(server.record("classic-record", getRandomBytes(32), server.rootKey))
        )))
        val folders = getFolders(server.options, true)

        assertTrue(folders.single().useGcm)
        assertFalse(folders.single().isDrive)
        createSecret2(server.options, CreateOptions("classic-root"), recordData(), folders)

        assertEquals(125, bytes(server.payload("create_secret"), "recordKey").size)
        assertEquals(listOf("get_folders", "get_secret", "get_secret", "create_secret"), server.paths())
    }

    @Test
    fun duplicateFolderUidsKeepTheMarkedNsfKeyForRecordsAndCreate() {
        val server = Server()
        val otherKey = getRandomBytes(32)
        val directKey = getRandomBytes(32)
        server.storage.delete(KEY_OWNER_PUBLIC_KEY)
        server.responses["get_secret"] = response(
            listOf(
                server.driveFolder(records = listOf(server.record("nsf-record", getRandomBytes(32), server.driveKey))),
                server.folder(
                    "nsf-root", otherKey, null, null, false,
                    records = listOf(server.record("shortcut-record", getRandomBytes(32), otherKey))
                )
            ),
            listOf(server.record("direct-record", directKey, server.driveKey, "nsf-root"))
        )

        val secrets = getSecrets(server.options)
        val folders = getFolders(server.options, true)
        val marked = folders.single()
        val directRecord = secrets.records.single { it.recordUid == "direct-record" }

        assertTrue(marked.isDrive)
        assertEquals("Drive", marked.name)
        assertContentEquals(server.driveKey, marked.folderKey)
        assertTrue(directRecord.isDrive)
        assertEquals("Existing", directRecord.data.title)
        assertEquals("nsf-root", directRecord.folderUid)
        assertEquals("nsf-root", directRecord.innerFolderUid)
        assertContentEquals(directKey, directRecord.recordKey)
        assertContentEquals(server.driveKey, directRecord.folderKey)
        val first = recordData("Legacy create")
        createSecret(server.options, "nsf-root", first, secrets)
        assertDriveCreate(server, first)
        val second = recordData("Options create")
        createSecret2(server.options, CreateOptions("nsf-root"), second, folders)
        assertDriveCreate(server, second)
    }

    private fun assertDriveCreate(server: Server, data: KeeperRecordData, key: ByteArray = server.driveKey) {
        val payload = server.payload("create_secret")
        val wrappedKey = bytes(payload, "recordKey")
        assertEquals(60, wrappedKey.size)
        val rawKey = decrypt(wrappedKey, key)
        assertEquals(32, rawKey.size)
        assertFalse(payload.toString().contains(bytesToBase64(rawKey)))
        assertFalse(payload.toString().contains(webSafe64FromBytes(rawKey)))
        val encryptedRecord = webBytes(payload, "data")
        assertTrue(encryptedRecord.size >= 412)
        val recordBytes = decrypt(encryptedRecord, rawKey)
        val serialized = stringToBytes(Json.encodeToString(data))
        val expectedSize = maxOf(384, ((serialized.size + 15) / 16) * 16)
        assertEquals(expectedSize, recordBytes.size)
        assertContentEquals(serialized, recordBytes.copyOf(serialized.size))
        assertTrue(recordBytes.drop(serialized.size).all { it == ' '.code.toByte() })
        assertEquals(data.title, content(json(recordBytes), "title"))
        assertTrue(payload["folderKey"] == null || payload["folderKey"] == JsonNull)
    }

    @Test
    fun createSecretUsesTheDriveRecordBodyWithoutAnOwnerKey() {
        val server = Server()
        server.storage.delete(KEY_OWNER_PUBLIC_KEY)
        val data = recordData()
        val secrets = KeeperSecrets(AppData("", ""), emptyList()).apply { folders = listOf(driveFolder(server)) }

        val uid = createSecret(server.options, "nsf-root", data, secrets)

        assertDriveCreate(server, data)
        assertEquals(uid, content(server.payload("create_secret"), "recordUid"))
        assertEquals("nsf-root", content(server.payload("create_secret"), "folderUid"))
        assertEquals(listOf("create_secret"), server.paths())
    }

    @Test
    fun createSecretRefreshesTheDriveFolderForLegacyRecordLists() {
        val server = Server()
        val existing = KeeperRecord(
            getRandomBytes(32), "existing", "nsf-root", server.driveKey, null,
            recordData(), 1, isDrive = true
        )
        val data = recordData()
        val secrets = KeeperSecrets(AppData("", ""), listOf(existing))
        server.responses["get_secret"] = response(listOf(server.driveFolder()))

        createSecret(server.options, "nsf-root", data, secrets)

        assertDriveCreate(server, data)
        assertEquals(listOf("get_secret", "create_secret"), server.paths())
    }

    @Test
    fun createSecretRefreshesTheClassicFolderWhenCopiedRecordsHaveAnNsfMarker() {
        val server = Server()
        val existingKey = getRandomBytes(32)
        server.responses["get_secret"] = response(listOf(
            server.folder(
                "classic-root", server.rootKey, null, null, false,
                records = listOf(server.record("shared-record", existingKey, server.rootKey))
            ),
            server.driveFolder(records = listOf(server.record("shared-record", existingKey, server.driveKey)))
        ))
        val secrets = getSecrets(server.options)
        assertEquals(2, secrets.records.size)
        assertTrue(secrets.records.all { it.recordUid == "shared-record" && it.isDrive })
        val copiedSecrets = secrets.copy()
        assertTrue(copiedSecrets.folders.isEmpty())
        server.requests.clear()
        val data = recordData("Classic record")

        createSecret(server.options, "classic-root", data, copiedSecrets)

        val payload = server.payload("create_secret")
        val wrapped = bytes(payload, "recordKey")
        assertEquals(125, wrapped.size)
        val rawKey = privateDecrypt(wrapped, server.ownerKeys.private.encoded)
        assertContentEquals(rawKey, decrypt(bytes(payload, "folderKey"), server.rootKey))
        assertContentEquals(stringToBytes(Json.encodeToString(data)), decrypt(webBytes(payload, "data"), rawKey))
        assertEquals("classic-root", content(payload, "folderUid"))
        assertEquals(listOf("get_secret", "create_secret"), server.paths())
    }

    @Test
    fun createSecretRefusesAnUnavailableNsfKeyEvenWithAnUnmarkedDuplicate() {
        for (mode in listOf("default", "supplied", "copy")) {
            val server = Server()
            val otherKey = getRandomBytes(32)
            server.responses["get_secret"] = response(listOf(
                server.folder(
                    "nsf-root", server.driveKey, null, """{"name":"Drive"}""", true,
                    wrappedKey = ByteArray(15)
                ),
                server.folder(
                    "nsf-root", otherKey, null, null, false,
                    records = listOf(server.record("shared-record", getRandomBytes(32), otherKey))
                )
            ))
            val secrets = getSecrets(server.options)
            assertFalse(secrets.folders.single().isDrive)
            assertContentEquals(otherKey, secrets.folders.single().folderKey)
            assertTrue(secrets.records.single().isDrive)
            val copiedSecrets = secrets.copy()
            assertTrue(copiedSecrets.folders.isEmpty())
            server.requests.clear()

            val failure = assertFailsWith<SecretsManagerException> {
                when (mode) {
                    "default" -> createSecret(server.options, "nsf-root", recordData())
                    "supplied" -> createSecret(server.options, "nsf-root", recordData(), secrets)
                    else -> createSecret(server.options, "nsf-root", recordData(), copiedSecrets)
                }
            }

            assertTrue(failure.message!!.startsWith("Unable to create record - folder key for nsf-root not found."))
            assertEquals(if (mode == "supplied") emptyList() else listOf("get_secret"), server.paths())
            assertFalse(server.paths().contains("create_secret"))
        }
    }

    @Test
    fun createSecret2UsesTheDriveBodyAndKeepsUtf8JsonUnchanged() {
        for (title in listOf("New record", "界".repeat(160), "x".repeat(401))) {
            val server = Server()
            server.storage.delete(KEY_OWNER_PUBLIC_KEY)
            val data = recordData(title)

            createSecret2(server.options, CreateOptions("nsf-root"), data, listOf(driveFolder(server)))

            assertDriveCreate(server, data)
            assertEquals(listOf("create_secret"), server.paths())
        }
    }

    @Test
    fun createSecret2UsesTheGrantedTargetFolderKeyForNsfSubfolders() {
        val server = Server()
        val childKey = getRandomBytes(32)
        val data = recordData()
        val child = KeeperFolder(childKey, "nsf-child", null, "Child", true, true)

        createSecret2(
            server.options, CreateOptions("nsf-root", "nsf-child"), data,
            listOf(driveFolder(server), child)
        )

        assertDriveCreate(server, data, childKey)
        val payload = server.payload("create_secret")
        assertEquals("nsf-root", content(payload, "folderUid"))
        assertEquals("nsf-child", content(payload, "subFolderUid"))
        assertFails { decrypt(bytes(payload, "recordKey"), server.driveKey) }
    }

    @Test
    fun createSecret2UsesTheDirectlySharedNsfTargetWhenTheParentKeyCannotDecrypt() {
        val server = Server()
        val targetKey = getRandomBytes(32)
        server.storage.delete(KEY_OWNER_PUBLIC_KEY)
        server.responses["get_secret"] = response(listOf(
            server.folder(
                "nsf-parent", server.driveKey, null, """{"name":"Parent"}""", true,
                wrappedKey = ByteArray(15)
            ),
            server.driveFolder(uid = "nsf-target", key = targetKey)
        ))
        val data = recordData()

        createSecret2(server.options, CreateOptions("nsf-parent", "nsf-target"), data)

        assertDriveCreate(server, data, targetKey)
        val payload = server.payload("create_secret")
        assertEquals("nsf-parent", content(payload, "folderUid"))
        assertEquals("nsf-target", content(payload, "subFolderUid"))
        assertFails { decrypt(bytes(payload, "recordKey"), server.driveKey) }
        assertEquals(listOf("get_folders", "get_secret", "create_secret"), server.paths())
    }

    @Test
    fun createSecret2FindsAnNsfFolderMissingFromGetFolders() {
        val server = Server()
        val data = recordData()
        server.responses["get_secret"] = response(listOf(server.driveFolder(
            records = listOf(server.record("existing", getRandomBytes(32), server.driveKey))
        )))

        createSecret2(server.options, CreateOptions("nsf-root"), data)

        assertDriveCreate(server, data)
        assertEquals(listOf("get_folders", "get_secret", "create_secret"), server.paths())
        assertFalse(server.payload("get_secret").containsKey("requestedFolders"))
        assertFalse(server.payload("get_secret").containsKey("requestedRecords"))
    }

    @Test
    fun createSecret2DoesNotUseAnNsfParentKeyForAnUnlistedChild() {
        val server = Server()

        assertFailsWith<SecretsManagerException> {
            createSecret2(
                server.options, CreateOptions("nsf-root", "ungranted-child"), recordData(),
                listOf(driveFolder(server))
            )
        }

        assertFalse(server.paths().contains("create_secret"))
    }

    @Test
    fun createSecret2RefusesAnNsfFolderWhenItsLookupKeyCannotDecrypt() {
        val server = Server()
        server.responses["get_secret"] = response(listOf(server.folder(
            "nsf-root", server.driveKey, null, """{"name":"Drive"}""", true,
            wrappedKey = ByteArray(15)
        )))
        val folder = KeeperFolder(server.driveKey, "nsf-root", null, "Drive", useGcm = true)

        val failure = assertFailsWith<SecretsManagerException> {
            createSecret2(server.options, CreateOptions("nsf-root"), recordData(), listOf(folder))
        }

        assertTrue(failure.message!!.startsWith("Unable to create record - folder key for nsf-root not found."))
        assertEquals(listOf("get_secret"), server.paths())
        assertFalse(server.paths().contains("create_secret"))
    }

    @Test
    fun classicRecordCreatesKeepTheOwnerAndSharedFolderKeyWraps() {
        for (legacy in listOf(false, true)) {
            val server = Server()
            val data = recordData()
            if (legacy) {
                val record = KeeperRecord(
                    getRandomBytes(32), "existing", "classic-root", server.rootKey, null, recordData(), 1
                )
                createSecret(server.options, "classic-root", data, KeeperSecrets(AppData("", ""), listOf(record)))
            } else {
                createSecret2(
                    server.options, CreateOptions("classic-root", "classic-child"), data,
                    listOf(
                        KeeperFolder(server.rootKey, "classic-root", null, "Classic"),
                        KeeperFolder(server.childKey, "classic-child", "classic-root", "Child")
                    )
                )
            }

            val payload = server.payload("create_secret")
            val wrapped = bytes(payload, "recordKey")
            assertEquals(125, wrapped.size)
            val rawKey = privateDecrypt(wrapped, server.ownerKeys.private.encoded)
            assertContentEquals(rawKey, decrypt(bytes(payload, "folderKey"), server.rootKey))
            assertContentEquals(
                stringToBytes(Json.encodeToString(data)),
                decrypt(webBytes(payload, "data"), rawKey)
            )
            assertEquals(listOf("create_secret"), server.paths())
        }
    }

    @Test
    fun nsfFolderCreateAndRenameRefuseBeforeAnyRequest() {
        val server = Server()
        val folder = driveFolder(server)

        val create = assertFailsWith<SecretsManagerException> {
            createFolder(server.options, CreateOptions("nsf-root"), "Private new name", listOf(folder))
        }
        val update = assertFailsWith<SecretsManagerException> {
            updateFolder(server.options, "nsf-root", "Private new name", listOf(folder))
        }

        assertEquals(CREATE_REFUSED, create.message)
        assertEquals(UPDATE_REFUSED, update.message)
        assertEquals(emptyList(), server.paths())
        assertFalse(create.message!!.contains(folder.name))
        assertFalse(update.message!!.contains(folder.name))
    }

    @Test
    fun folderCreateAlsoRefusesAnNsfTargetAfterAClassicParent() {
        val server = Server()
        val parent = KeeperFolder(server.rootKey, "classic-root", null, "Classic")

        val failure = assertFailsWith<SecretsManagerException> {
            createFolder(
                server.options, CreateOptions("classic-root", "nsf-root"), "New name",
                listOf(parent, driveFolder(server))
            )
        }

        assertEquals(CREATE_REFUSED, failure.message)
        assertEquals(emptyList(), server.paths())
    }

    @Test
    fun renameRefusesConflictingDuplicateFoldersInEitherOrder() {
        val server = Server()
        val classic = KeeperFolder(server.childKey, "nsf-root", "classic-root", "Classic")
        val drive = driveFolder(server)
        for (folders in listOf(listOf(classic, drive), listOf(drive, classic))) {
            val failure = assertFailsWith<SecretsManagerException> {
                updateFolder(server.options, "nsf-root", "New name", folders)
            }
            assertEquals(UPDATE_REFUSED, failure.message)
        }
        assertEquals(emptyList(), server.paths())
    }

    @Test
    fun renameRefusesAClassicSharedRootWithoutAWriteOrMetadataRead() {
        val server = Server()
        val root = KeeperFolder(server.rootKey, "classic-root", null, "Private name")

        val failure = assertFailsWith<SecretsManagerException> {
            updateFolder(server.options, "classic-root", "New name", listOf(root))
        }

        assertTrue(failure.message!!.contains("access_denied"))
        assertTrue(failure.message!!.contains("classic-root"))
        assertFalse(failure.message!!.contains(root.name))
        assertEquals(emptyList(), server.paths())
    }

    @Test
    fun classicFolderCreatesUseCbcEvenWhenTheParentUsesGcm() {
        for (useGcm in listOf(false, true)) {
            val server = Server()
            val parent = KeeperFolder(server.rootKey, "classic-root", null, "Classic", useGcm)

            val uid = createFolder(server.options, CreateOptions("classic-root"), "New child", listOf(parent))

            val payload = server.payload("create_folder")
            val wrapped = webBytes(payload, "sharedFolderKey")
            assertEquals(64, wrapped.size)
            val childKey = decrypt(wrapped, server.rootKey, true)
            assertEquals(32, childKey.size)
            assertFails { decrypt(wrapped, server.rootKey) }
            assertEquals("New child", content(json(decrypt(webBytes(payload, "data"), childKey, true)), "name"))
            assertFails { decrypt(webBytes(payload, "data"), childKey) }
            assertEquals(uid, content(payload, "folderUid"))
            assertEquals("classic-root", content(payload, "sharedFolderUid"))
            assertEquals(listOf("create_folder"), server.paths())
        }
    }

    @Test
    fun classicRenameKeepsAllMetadataAndTheFolderCipher() {
        val metadata = """{"name":"Old","color":"blue","future":{"items":[1,true,null,{"name":"inner"}]},"unknown":42}"""
        for (useGcm in listOf(false, true)) {
            val server = Server()
            server.responses["get_folders"] = response(listOf(
                server.classicRoot(), server.classicChild(metadata, useGcm)
            ))

            updateFolder(server.options, "classic-child", "Renamed")

            val payload = server.payload("update_folder")
            val changed = json(decrypt(webBytes(payload, "data"), server.childKey, !useGcm))
            val expected = JsonObject(Json.parseToJsonElement(metadata).jsonObject + ("name" to JsonPrimitive("Renamed")))
            assertEquals(expected, changed)
            assertEquals(listOf("get_folders", "update_folder"), server.paths())
            assertFalse(changed.toString().contains("isDrive"))
        }
    }

    @Test
    fun suppliedCompleteFoldersNeedNoSecondReadAndKeepCachedMetadata() {
        val server = Server()
        val metadata = """{"name":"Old","color":"green","future":{"kept":true}}"""
        server.responses["get_folders"] = response(listOf(server.classicRoot(), server.classicChild(metadata)))
        val folders = getFolders(server.options)
        server.requests.clear()
        server.respond = { request ->
            if (request.path == "get_folders") error("Unexpected second folder read")
            null
        }

        updateFolder(server.options, "classic-child", "First", folders)
        updateFolder(server.options, "classic-child", "Second", folders)

        assertEquals(listOf("update_folder", "update_folder"), server.paths())
        for ((request, name) in server.requests.zip(listOf("First", "Second"))) {
            val expected = JsonObject(Json.parseToJsonElement(metadata).jsonObject + ("name" to JsonPrimitive(name)))
            assertEquals(expected, json(decrypt(webBytes(request.body, "data"), server.childKey, true)))
        }
        assertEquals("Old", folders.last().name)
        assertEquals(Json.parseToJsonElement(metadata).jsonObject, folders.last().data)
    }

    @Test
    fun aClassicRootWithAnEmptyParentKeepsCbcChildrenReadableAndEditable() {
        val server = Server()
        val root = Json.parseToJsonElement(server.classicRoot()).jsonObject
        val emptyParentRoot = JsonObject(root + ("parent" to JsonPrimitive(""))).toString()
        val metadata = """{"name":"Child","color":"orange","future":{"keep":true}}"""
        server.responses["get_folders"] = response(listOf(emptyParentRoot, server.classicChild(metadata)))
        val folders = getFolders(server.options)

        assertEquals(listOf("classic-root", "classic-child"), folders.map { it.folderUid })
        assertTrue(folders.none { it.useGcm || it.isDrive })
        assertContentEquals(server.childKey, folders.last().folderKey)
        server.requests.clear()

        updateFolder(server.options, "classic-child", "Renamed", folders)

        val expected = JsonObject(Json.parseToJsonElement(metadata).jsonObject + ("name" to JsonPrimitive("Renamed")))
        assertEquals(expected, json(decrypt(webBytes(server.payload("update_folder"), "data"), server.childKey, true)))
        assertEquals(listOf("update_folder"), server.paths())
    }

    @Test
    fun manuallyConstructedFoldersRefreshTheMetadataAndKey() {
        val server = Server()
        val oldKey = getRandomBytes(32)
        val metadata = """{"name":"Current","color":"red"}"""
        server.responses["get_folders"] = response(listOf(
            server.classicRoot(), server.classicChild(metadata, useGcm = true)
        ))
        val oldFolder = KeeperFolder(oldKey, "classic-child", "classic-root", "Old")

        updateFolder(server.options, "classic-child", "Renamed", listOf(oldFolder))

        val encrypted = webBytes(server.payload("update_folder"), "data")
        assertEquals("red", content(json(decrypt(encrypted, server.childKey)), "color"))
        assertEquals("Renamed", content(json(decrypt(encrypted, server.childKey)), "name"))
        assertFails { decrypt(encrypted, oldKey, true) }
        assertEquals(listOf("get_folders", "update_folder"), server.paths())
    }

    @Test
    fun foldersWithoutCompleteMetadataNeverSendANameOnlyRename() {
        for (data in listOf<String?>(null, "[1,2]", """{"name":""")) {
            val server = Server()
            server.responses["get_folders"] = response(listOf(
                server.classicRoot(), server.classicChild(data ?: "").let { row ->
                    if (data == null) JsonObject(Json.parseToJsonElement(row).jsonObject + ("data" to JsonNull)).toString()
                    else row
                }
            ))
            val folder = KeeperFolder(server.childKey, "classic-child", "classic-root", "Private name")

            val failure = assertFailsWith<SecretsManagerException> {
                updateFolder(server.options, "classic-child", "Renamed", listOf(folder))
            }

            assertEquals(listOf("get_folders"), server.paths())
            assertFalse(failure.message!!.contains(folder.name))
            assertFalse(failure.message!!.contains("Renamed"))
        }
    }

    @Test
    fun aRefreshedRootOrNsfFolderCannotUseAnOldChildRename() {
        for (nsf in listOf(false, true)) {
            val server = Server()
            val oldChild = KeeperFolder(server.childKey, "moved-folder", "classic-root", "Old name")
            server.responses["get_folders"] = response(listOf(
                if (nsf) {
                    server.driveFolder(uid = "moved-folder")
                } else {
                    server.folder("moved-folder", server.childKey, null, """{"name":"New root"}""", false)
                }
            ))

            val failure = assertFailsWith<SecretsManagerException> {
                updateFolder(server.options, "moved-folder", "Renamed", listOf(oldChild))
            }

            assertTrue(failure.message!!.contains("access_denied"))
            assertFalse(failure.message!!.contains(oldChild.name))
            assertEquals(listOf("get_folders"), server.paths())
        }
    }

    @Test
    fun metadataWithoutANameStillKeepsEveryOtherProperty() {
        for (data in listOf("{}", """{"color":"blue","future":null}""")) {
            val server = Server()
            server.responses["get_folders"] = response(listOf(server.classicRoot(), server.classicChild(data)))

            updateFolder(server.options, "classic-child", "Renamed")

            val expected = JsonObject(Json.parseToJsonElement(data).jsonObject + ("name" to JsonPrimitive("Renamed")))
            assertEquals(expected, json(decrypt(webBytes(server.payload("update_folder"), "data"), server.childKey, true)))
        }
    }

    @Test
    fun deleteNsfAndUnknownFoldersReturnsLocalResultsWithoutAWrite() {
        val server = Server()
        server.responses["get_secret"] = response(listOf(server.driveFolder()))

        val response = deleteFolder(server.options, listOf("nsf-root", "unknown"), true)

        assertEquals(listOf("nsf-root", "unknown"), response.folders.map { it.folderUid })
        assertTrue(response.folders.all { it.responseCode == "doesnt_exist" })
        assertEquals(listOf("get_folders"), server.paths())
        assertFalse(server.paths().contains("get_secret"))
    }

    @Test
    fun deleteRootFoldersReturnsAccessDeniedWithoutAWrite() {
        val server = Server()
        server.responses["get_folders"] = response(listOf(server.classicRoot(), server.driveFolder()))

        val response = deleteFolder(server.options, listOf("classic-root", "nsf-root"), true)

        assertTrue(response.folders.all { it.responseCode == "access_denied" })
        assertEquals(listOf("get_folders"), server.paths())
    }

    @Test
    fun deleteMixedFoldersSendsOnlyClassicChildrenAndKeepsCallerOrder() {
        val server = Server()
        server.responses["get_folders"] = response(listOf(server.classicRoot(), server.classicChild()))
        server.responses["delete_folder"] = deleteResponse(item("classic-child", "access_denied", "Not editable"))

        val result = deleteFolder(
            server.options, listOf("unknown", "classic-child", "classic-root", "nsf-root"), true
        )

        assertEquals(listOf("unknown", "classic-child", "classic-root", "nsf-root"), result.folders.map { it.folderUid })
        assertEquals(listOf("doesnt_exist", "access_denied", "access_denied", "doesnt_exist"), result.folders.map { it.responseCode })
        assertEquals("Not editable", result.folders[1].errorMessage)
        val payload = server.payload("delete_folder")
        assertEquals(listOf("classic-child"), payload["folderUids"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertTrue(payload["forceDeletion"]!!.jsonPrimitive.boolean)
        assertEquals(listOf("get_folders", "delete_folder"), server.paths())
    }

    @Test
    fun deleteUsesRawFolderMetadataEvenWhenTheChildCannotDecrypt() {
        val server = Server()
        server.responses["get_folders"] = response(listOf(
            server.classicRoot(),
            server.folder(
                "broken-child", server.childKey, "classic-root", null, false,
                wrappedKey = ByteArray(15), encryptedData = ByteArray(3)
            )
        ))
        server.responses["delete_folder"] = deleteResponse(item("broken-child"))

        val result = deleteFolder(server.options, listOf("broken-child"))

        assertEquals("ok", result.folders.single().responseCode)
        assertEquals(listOf("broken-child"), server.payload("delete_folder")["folderUids"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("get_folders", "delete_folder"), server.paths())
    }

    @Test
    fun deleteMixedResultsKeepDuplicateServerItemsAndServerExtras() {
        val server = Server()
        server.responses["get_folders"] = response(listOf(server.classicRoot(), server.classicChild()))
        server.responses["delete_folder"] = deleteResponse(
            item("classic-child"), item("classic-child", "access_denied"), item("extra", "doesnt_exist")
        )

        val result = deleteFolder(server.options, listOf("unknown", "classic-child", "unknown"))

        assertEquals(listOf("unknown", "classic-child", "classic-child", "extra"), result.folders.map { it.folderUid })
        assertEquals(listOf("doesnt_exist", "ok", "access_denied", "doesnt_exist"), result.folders.map { it.responseCode })
    }

    @Test
    fun deleteTakesACallerUidSnapshotBeforeTheFolderLookup() {
        val server = Server()
        val callerUids = mutableListOf("unknown", "classic-child")
        server.responses["get_folders"] = response(listOf(server.classicRoot(), server.classicChild()))
        server.responses["delete_folder"] = deleteResponse(item("classic-child"))
        server.respond = { request ->
            if (request.path == "get_folders") {
                callerUids.clear()
                callerUids.add("nsf-root")
            }
            null
        }

        val result = deleteFolder(server.options, callerUids)

        assertEquals(listOf("nsf-root"), callerUids)
        assertEquals(listOf("unknown", "classic-child"), result.folders.map { it.folderUid })
        assertEquals(listOf("doesnt_exist", "ok"), result.folders.map { it.responseCode })
        assertEquals(listOf("classic-child"), server.payload("delete_folder")["folderUids"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("get_folders", "delete_folder"), server.paths())
    }

    @Test
    fun folderDeletesAcceptEmptyOrAbsentResultBodies() {
        for (body in listOf("", "{}", "null", "[]", """{"folders":[]}""")) {
            val server = Server()
            server.responses["get_folders"] = response(listOf(server.classicRoot(), server.classicChild()))
            server.responses["delete_folder"] = body

            assertEquals(emptyList(), deleteFolder(server.options, listOf("classic-child")).folders)

            assertEquals(listOf("get_folders", "delete_folder"), server.paths())
        }
    }

    @Test
    fun mixedFolderDeletesKeepLocalRefusalsWhenTheServerHasNoResults() {
        for (body in listOf("", "{}", "null", "[]", """{"folders":[]}""")) {
            val server = Server()
            server.responses["get_folders"] = response(listOf(server.classicRoot(), server.classicChild()))
            server.responses["delete_folder"] = body

            val result = deleteFolder(server.options, listOf("unknown", "classic-child", "classic-root"))

            assertEquals(listOf("unknown", "classic-root"), result.folders.map { it.folderUid })
            assertEquals(listOf("doesnt_exist", "access_denied"), result.folders.map { it.responseCode })
            assertEquals(listOf("get_folders", "delete_folder"), server.paths())
            assertEquals(
                listOf("classic-child"),
                server.payload("delete_folder")["folderUids"]!!.jsonArray.map { it.jsonPrimitive.content }
            )
        }
    }

    @Test
    fun deleteAllAllowedKeepsTheServerResultsAndDuplicateRequestUids() {
        val server = Server()
        server.responses["get_folders"] = response(listOf(server.classicRoot(), server.classicChild()))
        server.responses["delete_folder"] = deleteResponse(item("extra"), item("classic-child", "access_denied"))

        val result = deleteFolder(server.options, listOf("classic-child", "classic-child"))

        assertEquals(listOf("extra", "classic-child"), result.folders.map { it.folderUid })
        assertEquals(
            listOf("classic-child", "classic-child"),
            server.payload("delete_folder")["folderUids"]!!.jsonArray.map { it.jsonPrimitive.content }
        )
    }

    @Test
    fun deleteConflictingDuplicateFoldersAndParentCyclesAreRefused() {
        for (rootsFirst in listOf(false, true)) {
            val server = Server()
            val entries = listOf(
                server.classicChild(uid = "conflict"),
                server.folder("conflict", server.childKey, null, """{"name":"Root"}""", false),
                server.classicChild(uid = "cycle-a", parent = "cycle-b"),
                server.classicChild(uid = "cycle-b", parent = "cycle-a"),
                server.classicChild(uid = "orphan", parent = "absent")
            )
            server.responses["get_folders"] = response(listOf(server.classicRoot()) + if (rootsFirst) entries.reversed() else entries)

            val result = deleteFolder(server.options, listOf("conflict", "cycle-a", "cycle-b", "orphan"))

            assertTrue(result.folders.none { it.responseCode == "ok" })
            assertEquals(listOf("get_folders"), server.paths())
        }
    }

    @Test
    fun failedFolderLookupSendsNoDeleteRequest() {
        val server = Server()
        server.respond = { request ->
            if (request.path == "get_folders") throw java.io.IOException("Dummy transport failure")
            null
        }

        assertFailsWith<java.io.IOException> { deleteFolder(server.options, listOf("classic-child")) }

        assertEquals(listOf("get_folders"), server.paths())
    }

    @Test
    fun emptyDeleteKeepsTheExistingRequestWithoutALookup() {
        val server = Server()

        assertEquals(emptyList(), deleteFolder(server.options, emptyList(), true).folders)

        assertEquals(listOf("delete_folder"), server.paths())
        assertEquals(emptyList(), server.payload("delete_folder")["folderUids"]!!.jsonArray.toList())
        assertTrue(server.payload("delete_folder")["forceDeletion"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun folderDeleteBindsAFreshClientBeforeTheWrite() {
        val server = Server()
        val clientKey = server.storage.getBytes(KEY_CLIENT_KEY)!!
        server.storage.delete(KEY_APP_KEY)
        val folders = Json.parseToJsonElement(response(listOf(server.classicRoot(), server.classicChild()))).jsonObject
        val bindingResponse = JsonObject(folders + mapOf(
            "encryptedAppKey" to JsonPrimitive(bytesToBase64(encrypt(server.appKey, clientKey))),
            "appOwnerPublicKey" to JsonPrimitive(bytesToBase64(extractPublicRaw(server.ownerKeys.public)))
        )).toString()
        var folderReads = 0
        server.respond = { request ->
            if (request.path == "get_folders") {
                if (folderReads++ == 0) bindingResponse else folders.toString()
            } else null
        }
        server.responses["delete_folder"] = deleteResponse(item("classic-child"))

        val result = deleteFolder(server.options, listOf("classic-child"))

        assertEquals("ok", result.folders.single().responseCode)
        assertContentEquals(server.appKey, server.storage.getBytes(KEY_APP_KEY))
        assertNull(server.storage.getBytes(KEY_CLIENT_KEY))
        assertEquals(listOf("get_folders", "get_folders", "delete_folder"), server.paths())
        assertTrue(server.requests[0].body.containsKey("publicKey"))
        assertFalse(server.requests[1].body.containsKey("publicKey"))
    }

    @Test
    fun getFoldersCompletesTheBindingWithASecondRead() {
        val server = Server()
        val clientKey = server.storage.getBytes(KEY_CLIENT_KEY)!!
        server.storage.delete(KEY_APP_KEY)
        val first = Json.parseToJsonElement(response(listOf(server.classicRoot()))).jsonObject
        val bindingResponse = JsonObject(first + mapOf(
            "encryptedAppKey" to JsonPrimitive(bytesToBase64(encrypt(server.appKey, clientKey))),
            "appOwnerPublicKey" to JsonPrimitive(bytesToBase64(extractPublicRaw(server.ownerKeys.public)))
        )).toString()
        val finalResponse = response(listOf(server.classicRoot(), server.classicChild()))
        var folderReads = 0
        server.respond = { request ->
            if (request.path == "get_folders") {
                if (folderReads++ == 0) bindingResponse else finalResponse
            } else null
        }

        val folders = getFolders(server.options)

        assertEquals(listOf("classic-root", "classic-child"), folders.map { it.folderUid })
        assertEquals(listOf("get_folders", "get_folders"), server.paths())
        assertContentEquals(server.appKey, server.storage.getBytes(KEY_APP_KEY))
        assertNull(server.storage.getBytes(KEY_CLIENT_KEY))
        assertTrue(server.requests[0].body.containsKey("publicKey"))
        assertFalse(server.requests[1].body.containsKey("publicKey"))
    }

    @Test
    fun aBindingRefreshFailureSendsNoFolderWrite() {
        val actions: List<(SecretsManagerOptions) -> Unit> = listOf(
            { createFolder(it, CreateOptions("classic-root"), "New child") },
            { updateFolder(it, "classic-child", "Renamed") },
            { deleteFolder(it, listOf("classic-child")) }
        )
        for (action in actions) {
            val server = Server()
            val clientKey = server.storage.getBytes(KEY_CLIENT_KEY)!!
            server.storage.delete(KEY_APP_KEY)
            val folders = Json.parseToJsonElement(response(listOf(server.classicRoot(), server.classicChild()))).jsonObject
            val bindingResponse = JsonObject(folders + mapOf(
                "encryptedAppKey" to JsonPrimitive(bytesToBase64(encrypt(server.appKey, clientKey))),
                "appOwnerPublicKey" to JsonPrimitive(bytesToBase64(extractPublicRaw(server.ownerKeys.public)))
            )).toString()
            val failure = java.io.IOException("Dummy binding refresh failure")
            var folderReads = 0
            server.respond = { request ->
                if (request.path == "get_folders") {
                    if (folderReads++ == 0) bindingResponse else throw failure
                } else null
            }

            assertSame(failure, assertFailsWith<java.io.IOException> { action(server.options) })

            assertEquals(listOf("get_folders", "get_folders"), server.paths())
            assertTrue(server.requests[0].body.containsKey("publicKey"))
            assertFalse(server.requests[1].body.containsKey("publicKey"))
        }
    }

    @Test
    fun aBindingRefreshFailureSendsNoRecordCreate() {
        val actions: List<(SecretsManagerOptions) -> Unit> = listOf(
            { createSecret(it, "nsf-root", recordData()) },
            { createSecret2(it, CreateOptions("nsf-root"), recordData(), emptyList()) }
        )
        for (action in actions) {
            val server = Server()
            val clientKey = server.storage.getBytes(KEY_CLIENT_KEY)!!
            server.storage.delete(KEY_APP_KEY)
            val folders = Json.parseToJsonElement(response(listOf(server.driveFolder()))).jsonObject
            val bindingResponse = JsonObject(folders + mapOf(
                "encryptedAppKey" to JsonPrimitive(bytesToBase64(encrypt(server.appKey, clientKey))),
                "appOwnerPublicKey" to JsonPrimitive(bytesToBase64(extractPublicRaw(server.ownerKeys.public)))
            )).toString()
            val failure = java.io.IOException("Dummy record binding refresh failure")
            var secretReads = 0
            server.respond = { request ->
                if (request.path == "get_secret") {
                    if (secretReads++ == 0) bindingResponse else throw failure
                } else null
            }

            assertSame(failure, assertFailsWith<java.io.IOException> { action(server.options) })

            assertEquals(listOf("get_secret", "get_secret"), server.paths())
            assertTrue(server.requests[0].body.containsKey("publicKey"))
            assertFalse(server.requests[1].body.containsKey("publicKey"))
        }
    }

    @Test
    fun recordDeletesAcceptEmptyOrAbsentResultBodies() {
        for (body in listOf("", "{}", "null", "[]", """{"records":[]}""")) {
            val server = Server()
            server.responses["delete_secret"] = body

            assertEquals(emptyList(), deleteSecret(server.options, listOf("record-uid")).records)

            assertEquals(listOf("delete_secret"), server.paths())
        }
    }

    @Test
    fun recordDeletesKeepDuplicateResultsAndTheirFolderOrder() {
        val server = Server()
        server.responses["delete_secret"] = """{"records":[
            {"recordUid":"same-record","folderUid":"folder-b","responseCode":"access_denied","errorMessage":"Not editable"},
            {"recordUid":"other-record","folderUid":"folder-c","responseCode":"ok"},
            {"recordUid":"same-record","folderUid":"folder-a","responseCode":"ok"}
        ]}"""

        val result = deleteSecret(server.options, listOf("same-record", "other-record"))

        assertEquals(listOf("same-record", "other-record", "same-record"), result.records.map { it.recordUid })
        assertEquals(listOf("folder-b", "folder-c", "folder-a"), result.records.map { it.folderUid })
        assertEquals(listOf("access_denied", "ok", "ok"), result.records.map { it.responseCode })
        assertEquals("Not editable", result.records.first().errorMessage)
        assertEquals(
            listOf("same-record", "other-record"),
            server.payload("delete_secret")["recordUids"]!!.jsonArray.map { it.jsonPrimitive.content }
        )
        assertEquals(listOf("delete_secret"), server.paths())
    }

    @Test
    fun recordUpdateAndDeletePayloadsDoNotDependOnTheDriveMarker() {
        val server = Server()
        val key = getRandomBytes(32)
        val snapshots = mutableListOf<JsonObject>()
        for (drive in listOf(false, true)) {
            val record = KeeperRecord(
                key, "record-uid", "folder-uid", server.driveKey, null,
                recordData("Changed"), 7, isDrive = drive
            )
            updateSecret(server.options, record, UpdateTransactionType.ROTATION)
            val payload = server.payload("update_secret")
            assertEquals(recordData("Changed").let { Json.parseToJsonElement(Json.encodeToString(it)).jsonObject },
                json(decrypt(webBytes(payload, "data"), key)))
            snapshots.add(JsonObject(payload - "data"))
            deleteSecret(server.options, listOf(record.recordUid))
        }

        assertEquals(snapshots[0], snapshots[1])
        assertEquals(
            server.requests.filter { it.path == "delete_secret" }[0].body,
            server.requests.filter { it.path == "delete_secret" }[1].body
        )
    }

    @Test
    fun uploadMetadataPayloadDoesNotDependOnTheDriveMarker() {
        val server = Server()
        val key = getRandomBytes(32)
        val snapshots = mutableListOf<JsonObject>()
        val stop = java.io.IOException("Stop before the file transport")
        server.respond = { request -> if (request.path == "add_file") throw stop else null }
        for (drive in listOf(false, true)) {
            val record = KeeperRecord(
                key, "record-uid", "folder-uid", server.driveKey, null,
                recordData(), 7, isDrive = drive
            )

            assertSame(stop, assertFailsWith<java.io.IOException> {
                uploadFile(server.options, record, KeeperFileUpload("dummy.txt", "Dummy", "text/plain", stringToBytes("contents")))
            })

            val payload = server.payload("add_file")
            val fileKey = privateDecrypt(bytes(payload, "fileRecordKey"), server.ownerKeys.private.encoded)
            assertEquals(32, fileKey.size)
            assertContentEquals(fileKey, decrypt(bytes(payload, "linkKey"), key))
            val fileData = json(decrypt(webBytes(payload, "fileRecordData"), fileKey))
            assertEquals("dummy.txt", content(fileData, "name"))
            assertEquals("Dummy", content(fileData, "title"))
            assertEquals(8, fileData["size"]!!.jsonPrimitive.int)
            val changedRecord = json(decrypt(webBytes(payload, "ownerRecordData"), key))
            val fileRef = changedRecord["fields"]!!.jsonArray.map { it.jsonObject }.first {
                it["type"]!!.jsonPrimitive.content == "fileRef"
            }
            assertEquals(content(payload, "fileRecordUid"), fileRef["value"]!!.jsonArray.single().jsonPrimitive.content)
            assertFalse(payload.containsKey("isDrive"))
            snapshots.add(JsonObject(payload.filterKeys {
                it !in setOf("fileRecordUid", "fileRecordKey", "fileRecordData", "ownerRecordData", "linkKey")
            }))
        }

        assertEquals(snapshots[0], snapshots[1])
        assertEquals(listOf("add_file", "add_file"), server.paths())
    }

    @Test
    fun malformedFolderDiagnosticsDoNotContainDecryptedMetadata() {
        val server = Server()
        val canary = "Private-folder-value"
        server.responses["get_folders"] = response(listOf(
            server.classicRoot(),
            server.classicChild("""{"name":"$canary","future":""")
        ))
        val output = ByteArrayOutputStream()
        val original = System.err
        System.setErr(PrintStream(output, true, "UTF-8"))
        try {
            val loggingOptions = server.options.copy(loggingEnabled = true)
            assertEquals(listOf("classic-root"), getFolders(loggingOptions).map { it.folderUid })
        } finally {
            System.setErr(original)
        }

        val message = output.toString("UTF-8")
        assertTrue(message.contains("classic-child"))
        assertFalse(message.contains(canary))
        assertFalse(message.contains(bytesToBase64(server.childKey)))
    }
}
