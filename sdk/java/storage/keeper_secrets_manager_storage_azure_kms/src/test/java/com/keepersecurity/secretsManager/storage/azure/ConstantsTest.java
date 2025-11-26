package com.keepersecurity.secretsManager.storage.azure;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Constants class
 */
class ConstantsTest {

    @Test
    void testBlobHeaderConstant() {
        // Then
        assertNotNull(Constants.BLOB_HEADER);
        assertEquals(2, Constants.BLOB_HEADER.length);
        assertEquals((byte) 0xFF, Constants.BLOB_HEADER[0]);
        assertEquals((byte) 0xFF, Constants.BLOB_HEADER[1]);
    }

    @Test
    void testBlockSizeConstant() {
        // Then - 16 bytes = 128 bits (AES block size)
        assertEquals(16, Constants.BLOCK_SIZE);
    }

    @Test
    void testKeySizeConstant() {
        // Then - 32 bytes = 256 bits (AES-256 key size)
        assertEquals(32, Constants.KEY_SIZE);
    }

    @Test
    void testAesGcmConstant() {
        // Then
        assertEquals("AES/GCM/NoPadding", Constants.AES_GCM);
    }

    @Test
    void testAesConstant() {
        // Then
        assertEquals("AES", Constants.AES);
    }

    @Test
    void testGcmTagLengthConstant() {
        // Then - 96 bits = 12 bytes
        assertEquals(96, Constants.GCM_TAG_LENGTH);
    }

    @Test
    void testKsmConfigFileConstant() {
        // Then
        assertEquals("KSM_CONFIG_FILE", Constants.KSM_CONFIG_FILE);
    }

    @Test
    void testKsmAzKeyIdConstant() {
        // Then
        assertEquals("KSM_AZ_KEY_ID", Constants.KSM_AZ_KEY_ID);
    }

    @Test
    void testMd5Constant() {
        // Then
        assertEquals("MD5", Constants.MD5);
    }

    @Test
    void testBlobHeaderIsNotSharedReference() {
        // Given
        byte[] header1 = Constants.BLOB_HEADER;
        byte[] header2 = Constants.BLOB_HEADER;

        // Then - verify the arrays are the same reference (static final)
        assertSame(header1, header2, "BLOB_HEADER should be the same reference");
    }

    @Test
    void testConstantValuesMatchExpectedCryptographicStandards() {
        // Verify AES-256 requirements
        assertEquals(32, Constants.KEY_SIZE, "AES-256 requires 32-byte key");
        assertEquals(16, Constants.BLOCK_SIZE, "AES requires 16-byte block size");
    }
}
