package com.keepersecurity.secretsManager.core

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.*
import kotlin.test.*

@ExperimentalSerializationApi
internal class UpdateFolderMetadataTest {

    private val rootUid = "root-uid"
    private val childUid = "child-uid"

    // Fields the web vault stores beside "name". The numeric literal 2.50 checks that values are
    // sent back as written, not re-parsed into a double.
    private val childJson = """{"name":"Old Name","color":"red","extra":{"n":[1,2.50,null]},"flag":true}"""

    private val expectedAfterRename: JsonObject = JsonObject(
        Json.parseToJsonElement(childJson).jsonObject + ("name" to JsonPrimitive("New Name"))
    )

    // A classic shared folder with one subfolder. The subfolder key is wrapped with AES-GCM
    // (60 bytes) or AES-CBC (64 bytes), and its data uses the same cipher.
    private class Vault(val useGcm: Boolean, val childJson: String, rootUid: String, childUid: String) {
        val transmissionKey = ByteArray(32) { it.toByte() }
        val childKey = getRandomBytes(32)
        val requestPaths = mutableListOf<String>()
        val updatePayloads = mutableListOf<JsonObject>()
        var childInVault = true
        val options: SecretsManagerOptions

        init {
            TestStubs.transmissionKeyStub = { transmissionKey }
            val appKey = getRandomBytes(32)
            val rootKey = getRandomBytes(32)
            val encRootKey = bytesToBase64(encrypt(rootKey, appKey))
            val encRootData = bytesToBase64(encrypt(stringToBytes("""{"name":"Root"}"""), rootKey, true))
            val encChildKey = bytesToBase64(encrypt(childKey, rootKey, !useGcm))
            val encChildData = bytesToBase64(encrypt(stringToBytes(childJson), childKey, !useGcm))
            val root = """{"folderUid":"$rootUid","folderKey":"$encRootKey","data":"$encRootData","parent":null,"records":null}"""
            val child = """{"folderUid":"$childUid","folderKey":"$encChildKey","data":"$encChildData","parent":"$rootUid","records":null}"""

            val storage = InMemoryStorage()
            initializeStorage(storage, "US:FAKE_CLIENT_KEY")
            storage.saveBytes(KEY_APP_KEY, appKey)
            options = SecretsManagerOptions(storage, queryFunction = { url, _, payload ->
                val path = url.substringAfterLast('/')
                requestPaths.add(path)
                when (path) {
                    "get_folders" -> {
                        val folders = if (childInVault) "$root,$child" else root
                        val body = """{"encryptedAppKey":null,"folders":[$folders],"records":null}"""
                        KeeperHttpResponse(200, encrypt(stringToBytes(body), transmissionKey))
                    }
                    "update_folder" -> {
                        val sent = bytesToString(decrypt(payload.payload, transmissionKey))
                        updatePayloads.add(Json.parseToJsonElement(sent).jsonObject)
                        KeeperHttpResponse(200, ByteArray(0))
                    }
                    else -> throw IllegalStateException("unexpected request $path")
                }
            })
        }

        // The folder JSON the SDK sent, decrypted with the cipher the folder uses. A wrong cipher
        // fails to decrypt.
        fun sentFolderJson(): JsonObject {
            val encrypted = webSafe64ToBytes(updatePayloads.single()["data"]!!.jsonPrimitive.content)
            return Json.parseToJsonElement(bytesToString(decrypt(encrypted, childKey, !useGcm))).jsonObject
        }
    }

    @Test
    fun testRenameClassicSubfolderKeepsMetadataCbc() {
        val vault = Vault(useGcm = false, childJson = childJson, rootUid = rootUid, childUid = childUid)

        updateFolder(vault.options, childUid, "New Name")

        assertEquals(listOf("get_folders", "update_folder"), vault.requestPaths)
        assertEquals(expectedAfterRename, vault.sentFolderJson())
    }

    @Test
    fun testRenameClassicSubfolderKeepsMetadataGcm() {
        val vault = Vault(useGcm = true, childJson = childJson, rootUid = rootUid, childUid = childUid)

        updateFolder(vault.options, childUid, "New Name")

        assertEquals(listOf("get_folders", "update_folder"), vault.requestPaths)
        assertEquals(expectedAfterRename, vault.sentFolderJson())
    }

    @Test
    fun testSuppliedFolderWithoutDataIsReadAgainOnce() {
        val vault = Vault(useGcm = false, childJson = childJson, rootUid = rootUid, childUid = childUid)
        val supplied = KeeperFolder(vault.childKey, childUid, rootUid, "Old Name", false)

        updateFolder(vault.options, childUid, "New Name", listOf(supplied))

        assertEquals(listOf("get_folders", "update_folder"), vault.requestPaths)
        assertEquals(expectedAfterRename, vault.sentFolderJson())
    }

    @Test
    fun testNoUpdateWhenFolderDataCannotBeRead() {
        val vault = Vault(useGcm = false, childJson = childJson, rootUid = rootUid, childUid = childUid)
        vault.childInVault = false
        val supplied = KeeperFolder(vault.childKey, childUid, rootUid, "Old Name", false)

        val error = assertFailsWith<SecretsManagerException> {
            updateFolder(vault.options, childUid, "New Name", listOf(supplied))
        }

        assertTrue(error.message!!.contains(childUid))
        assertFalse(error.message!!.contains("color"), "the error must not echo folder JSON")
        assertEquals(listOf("get_folders"), vault.requestPaths)
    }
}
