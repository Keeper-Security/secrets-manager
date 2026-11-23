package com.keepersecurity.secretsManager.core;

import org.junit.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class NsfJavaApiCompatibilityTest {
    @Test
    public void keeperFolderKeepsPublishedAndReleaseConstructors() {
        byte[] key = new byte[32];
        KeeperFolder published = new KeeperFolder(key, "folder-uid", null, "Folder");
        KeeperFolder release = new KeeperFolder(key, "folder-uid", null, "Folder", true);
        KeeperFolder drive = new KeeperFolder(key, "folder-uid", null, "Folder", true, true);

        assertSame(key, published.getFolderKey());
        assertEquals("folder-uid", published.getFolderUid());
        assertEquals("Folder", published.getName());
        assertFalse(published.getUseGcm());
        assertFalse(published.isDrive());
        assertTrue(release.getUseGcm());
        assertFalse(release.isDrive());
        assertTrue(drive.getUseGcm());
        assertTrue(drive.isDrive());
        assertEquals("Folder", drive.component4());
        assertTrue(drive.component5());
        assertTrue(drive.component6());
    }

    @Test
    public void keeperFolderKeepsPublishedAndReleaseCopyMethods() {
        byte[] key = new byte[32];
        KeeperFolder folder = new KeeperFolder(key, "folder-uid", null, "Folder", true, true);
        KeeperFolder publishedCopy = folder.copy(key, "folder-uid", null, "Published copy");
        KeeperFolder releaseCopy = folder.copy(key, "folder-uid", null, "Release copy", false);

        assertEquals("Published copy", publishedCopy.getName());
        assertTrue(publishedCopy.getUseGcm());
        assertTrue(publishedCopy.isDrive());
        assertEquals("Release copy", releaseCopy.getName());
        assertFalse(releaseCopy.getUseGcm());
        assertTrue(releaseCopy.isDrive());
    }

    @Test
    public void keeperFolderKeepsPublishedAndReleaseKotlinDefaultSignatures() throws ReflectiveOperationException {
        Class<?> marker = Class.forName("kotlin.jvm.internal.DefaultConstructorMarker");
        Constructor<KeeperFolder> published = KeeperFolder.class.getConstructor(
            byte[].class, String.class, String.class, String.class, int.class, marker
        );
        Constructor<KeeperFolder> release = KeeperFolder.class.getConstructor(
            byte[].class, String.class, String.class, String.class, boolean.class, int.class, marker
        );
        Method publishedCopy = KeeperFolder.class.getMethod(
            "copy$default", KeeperFolder.class, byte[].class, String.class, String.class,
            String.class, int.class, Object.class
        );
        Method releaseCopy = KeeperFolder.class.getMethod(
            "copy$default", KeeperFolder.class, byte[].class, String.class, String.class,
            String.class, boolean.class, int.class, Object.class
        );

        byte[] key = new byte[32];
        KeeperFolder publishedFolder = published.newInstance(key, "folder-uid", "ignored", "Folder", 4, null);
        KeeperFolder releaseFolder = release.newInstance(key, "folder-uid", "ignored", "Folder", true, 4, null);
        assertNull(publishedFolder.getParentUid());
        assertFalse(publishedFolder.getUseGcm());
        assertNull(releaseFolder.getParentUid());
        assertTrue(releaseFolder.getUseGcm());

        KeeperFolder drive = new KeeperFolder(key, "folder-uid", null, "Folder", true, true);
        KeeperFolder oldCopy = (KeeperFolder) publishedCopy.invoke(null, drive, null, null, null, "Published copy", 7, null);
        KeeperFolder newCopy = (KeeperFolder) releaseCopy.invoke(null, drive, null, null, null, "Release copy", false, 23, null);
        assertEquals("Published copy", oldCopy.getName());
        assertTrue(oldCopy.getUseGcm());
        assertTrue(oldCopy.isDrive());
        assertEquals("Release copy", newCopy.getName());
        assertTrue(newCopy.getUseGcm());
        assertTrue(newCopy.isDrive());
    }

    @Test
    public void keeperRecordKeepsPublishedJavaConstructors() {
        byte[] key = new byte[32];
        KeeperRecordData data = recordData();
        List<KeeperFile> files = Collections.emptyList();
        List<KeeperRecordLink> links = Collections.emptyList();
        KeeperRecord[] records = {
            new KeeperRecord(key, "record-uid", "folder-uid", key, null, data, 7L, files, links, true),
            new KeeperRecord(key, "record-uid", "folder-uid", key, null, data, 7L, files, links),
            new KeeperRecord(key, "record-uid", "folder-uid", key, null, data, 7L, files),
            new KeeperRecord(key, "record-uid", "folder-uid", key, null, data, 7L),
            new KeeperRecord(key, "record-uid", "folder-uid", key, data, 7L),
            new KeeperRecord(key, "record-uid", "folder-uid", data, 7L),
            new KeeperRecord(key, "record-uid", data, 7L)
        };

        for (KeeperRecord record : records) {
            assertSame(key, record.getRecordKey());
            assertSame(data, record.getData());
            assertEquals("record-uid", record.getRecordUid());
            assertEquals(7L, record.getRevision());
            assertFalse(record.isDrive());
        }
        assertTrue(records[0].isEditable());
        assertFalse(records[1].isEditable());
    }

    @Test
    public void keeperRecordKeepsPublishedJavaCopyMethod() {
        byte[] key = new byte[32];
        KeeperRecordData data = recordData();
        KeeperRecord record = new KeeperRecord(
            key, "record-uid", "folder-uid", key, null, data, 7L,
            Collections.emptyList(), Collections.emptyList(), true
        );
        KeeperRecord copy = record.copy(
            key, "record-uid", "folder-uid", key, null, data, 8L,
            record.getFiles(), record.getLinks(), record.isEditable()
        );

        assertSame(data, copy.component6());
        assertEquals(8L, copy.component7());
        assertTrue(copy.component10());
        assertFalse(copy.isDrive());
        assertEquals(7L, record.getRevision());
    }

    @Test
    public void keeperRecordKeepsPublishedKotlinDefaultSignatures() throws ReflectiveOperationException {
        Class<?> marker = Class.forName("kotlin.jvm.internal.DefaultConstructorMarker");
        Constructor<KeeperRecord> constructor = KeeperRecord.class.getConstructor(
            byte[].class, String.class, String.class, byte[].class, String.class, KeeperRecordData.class,
            long.class, List.class, List.class, boolean.class, int.class, marker
        );
        Method copy = KeeperRecord.class.getMethod(
            "copy$default", KeeperRecord.class,
            byte[].class, String.class, String.class, byte[].class, String.class, KeeperRecordData.class,
            long.class, List.class, List.class, boolean.class, int.class, Object.class
        );

        byte[] key = new byte[32];
        KeeperRecordData data = recordData();
        int constructorDefaults = (1 << 2) | (1 << 9);
        KeeperRecord record = constructor.newInstance(
            key, "record-uid", "ignored", null, null, data, 7L, null, null, true, constructorDefaults, null
        );
        assertNull(record.getFolderUid());
        assertFalse(record.isEditable());

        int copyDefaults = ((1 << 10) - 1) & ~(1 << 6);
        KeeperRecord copied = (KeeperRecord) copy.invoke(
            null, record, null, null, null, null, null, null, 8L, null, null, true, copyDefaults, null
        );
        assertEquals(record.copy(key, "record-uid", null, null, null, data, 8L, null, null, false), copied);
    }

    @Test
    public void getFoldersKeepsBothJavaOverloads() throws ReflectiveOperationException {
        Method published = SecretsManager.class.getMethod(
            "getFolders", SecretsManagerOptions.class
        );
        Method includeNsf = SecretsManager.class.getMethod(
            "getFolders", SecretsManagerOptions.class, boolean.class
        );

        assertEquals(List.class, published.getReturnType());
        assertEquals(List.class, includeNsf.getReturnType());
        assertTrue(Modifier.isStatic(published.getModifiers()));
        assertTrue(Modifier.isStatic(includeNsf.getModifiers()));
    }

    @Test
    public void keeperSecretsKeepsItsConstructorAndCopyMethod() {
        AppData appData = new AppData("Application", "app");
        List<KeeperRecord> records = Collections.emptyList();
        KeeperSecrets secrets = new KeeperSecrets(appData, records, null, null);
        KeeperSecrets copy = secrets.copy(appData, records, null, null);

        assertSame(appData, secrets.component1());
        assertSame(records, secrets.component2());
        assertEquals(secrets, copy);
        assertTrue(secrets.getFolders().isEmpty());
    }

    private static KeeperRecordData recordData() {
        return new KeeperRecordData("Record", "login", new ArrayList<KeeperRecordField>());
    }
}
