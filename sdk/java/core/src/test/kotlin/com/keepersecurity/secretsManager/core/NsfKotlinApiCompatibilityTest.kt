package com.keepersecurity.secretsManager.core

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.reflect.full.primaryConstructor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class NsfKotlinApiCompatibilityTest {
    @Test
    fun publishedKotlinSourceKeepsItsConstructorAndCopyForms() {
        val key = ByteArray(32)
        val folder = KeeperFolder(key, "folder-uid", name = "Folder")

        assertNull(folder.parentUid)
        assertFalse(folder.useGcm)
        assertFalse(folder.isDrive)
        assertEquals("Named copy", folder.copy(name = "Named copy").name)
        assertEquals("Positional copy", folder.copy(key, "folder-uid", null, "Positional copy").name)
    }

    @Test
    fun legacyCopiesKeepFolderFlagsAndMetadata() {
        val folder = KeeperFolder(ByteArray(32), "folder-uid", name = "Folder", useGcm = true, isDrive = true)
        val metadata = buildJsonObject { put("color", "blue") }
        folder.data = metadata

        val copy = folder.copy(name = "New name")

        assertEquals("New name", copy.name)
        assertTrue(copy.useGcm)
        assertTrue(copy.isDrive)
        assertSame(metadata, copy.data)
        assertNull(folder.copy(folderUid = "other-uid").data)
        assertNull(folder.copy(folderKey = ByteArray(32) { 1 }).data)
        assertNull(folder.copy(parentUid = "other-parent").data)
        assertNull(folder.copy(useGcm = false).data)
    }

    @Test
    fun keeperRecordKeepsPublishedKotlinDefaultsAndCallableReferences() {
        val constructor = ::KeeperRecord
        val copy = KeeperRecord::copy
        val key = ByteArray(32)
        val data = KeeperRecordData("Record", "login", mutableListOf())
        val record = KeeperRecord(key, "record-uid", data = data, revision = 7L)

        assertEquals(record, constructor(key, "record-uid", null, null, null, data, 7L, null, null, false))
        assertEquals(
            record.copy(revision = 8L),
            copy(record, key, "record-uid", null, null, null, data, 8L, null, null, false)
        )
        assertFalse(record.isDrive)
    }

    @Test
    fun keeperRecordKeepsPublishedPrimaryConstructor() {
        assertTrue(KeeperRecord::class.isData)
        val constructor = assertNotNull(KeeperRecord::class.primaryConstructor)
        assertEquals(
            listOf(
                "recordKey", "recordUid", "folderUid", "folderKey", "innerFolderUid",
                "data", "revision", "files", "links", "isEditable"
            ),
            constructor.parameters.map { it.name }
        )
    }
}
