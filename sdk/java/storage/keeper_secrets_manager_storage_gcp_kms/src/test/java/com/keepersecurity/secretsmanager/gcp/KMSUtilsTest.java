package com.keepersecurity.secretsmanager.gcp;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for KMSUtils class
 * Note: These tests focus on object instantiation and basic functionality
 * without making actual HTTP calls to GCP KMS services.
 */
class KMSUtilsTest {

    @Test
    void testKMSUtilsConstructorWithValidConfig() {
        // Given
        GcpSessionConfig config = new GcpSessionConfig(
            "test-project",
            "us-central1", 
            "test-keyring",
            "test-key",
            "1",
            "" // Empty string to use environment credentials (won't make actual calls)
        );

        // When/Then - Constructor should not throw exception with valid config
        assertDoesNotThrow(() -> {
            KMSUtils kmsUtils = new KMSUtils(config);
            assertNotNull(kmsUtils, "KMSUtils instance should be created successfully");
        }, "KMSUtils constructor should not throw exception with valid config");
    }

    @Test
    void testKMSUtilsConstructorWithNullConfig() {
        // When/Then - Constructor with null config should handle gracefully
        assertDoesNotThrow(() -> {
            KMSUtils kmsUtils = new KMSUtils(null);
            // Constructor might handle null config gracefully or store null
            assertNotNull(kmsUtils, "KMSUtils instance should still be created");
        }, "KMSUtils constructor should handle null config gracefully");
    }

    @Test
    void testSetAndGetKeyId() {
        // Given
        GcpSessionConfig config = new GcpSessionConfig(
            "test-project", "us-central1", "test-keyring", "original-key", "1", ""
        );
        KMSUtils kmsUtils = new KMSUtils(config);
        String newKeyId = "new-test-key";

        // When
        kmsUtils.setKeyId(newKeyId);
        String retrievedKeyId = kmsUtils.getKeyId();

        // Then
        assertEquals(newKeyId, retrievedKeyId, "Retrieved keyId should match the set keyId");
    }

    @Test
    void testGetKeyIdWithOriginalValue() {
        // Given
        String originalKeyId = "original-key-id";
        GcpSessionConfig config = new GcpSessionConfig(
            "test-project", "us-central1", "test-keyring", originalKeyId, "1", ""
        );
        KMSUtils kmsUtils = new KMSUtils(config);

        // When
        String retrievedKeyId = kmsUtils.getKeyId();

        // Then
        assertEquals(originalKeyId, retrievedKeyId, "Retrieved keyId should match the original value");
    }

    @Test
    void testSetKeyIdWithNullValue() {
        // Given
        GcpSessionConfig config = new GcpSessionConfig(
            "test-project", "us-central1", "test-keyring", "original-key", "1", ""
        );
        KMSUtils kmsUtils = new KMSUtils(config);

        // When
        kmsUtils.setKeyId(null);
        String retrievedKeyId = kmsUtils.getKeyId();

        // Then
        assertNull(retrievedKeyId, "Retrieved keyId should be null after setting to null");
    }

    @Test
    void testSetKeyIdWithEmptyString() {
        // Given
        GcpSessionConfig config = new GcpSessionConfig(
            "test-project", "us-central1", "test-keyring", "original-key", "1", ""
        );
        KMSUtils kmsUtils = new KMSUtils(config);

        // When
        kmsUtils.setKeyId("");
        String retrievedKeyId = kmsUtils.getKeyId();

        // Then
        assertEquals("", retrievedKeyId, "Retrieved keyId should be empty string after setting to empty string");
    }

    @Test
    void testKMSUtilsWithDifferentConfigurations() {
        // Test various configuration combinations
        String[][] configCombinations = {
            {"project1", "us-central1", "keyring1", "key1", "1", ""},
            {"project2", "europe-west1", "keyring2", "key2", "2", "/path/to/creds.json"},
            {"project3", "asia-southeast1", "keyring3", "key3", "latest", "./credentials.json"}
        };

        for (String[] combo : configCombinations) {
            // Given
            GcpSessionConfig config = new GcpSessionConfig(
                combo[0], combo[1], combo[2], combo[3], combo[4], combo[5]
            );

            // When/Then
            assertDoesNotThrow(() -> {
                KMSUtils kmsUtils = new KMSUtils(config);
                assertNotNull(kmsUtils, "KMSUtils should be created with config: " + String.join(", ", combo));
                assertEquals(combo[3], kmsUtils.getKeyId(), "KeyId should match config for: " + String.join(", ", combo));
            }, "Should handle configuration: " + String.join(", ", combo));
        }
    }

    @Test
    void testEncryptResponseClass() {
        // Given
        String ciphertext = "encrypted-data";
        String initVector = "init-vector";

        // When
        EncryptResponse response = new EncryptResponse(ciphertext, initVector);

        // Then
        assertNotNull(response, "EncryptResponse should be created successfully");
        assertEquals(ciphertext, response.getCiphertext(), "Ciphertext should match");
        assertEquals(initVector, response.getInitializeVector(), "Initialize vector should match");
    }

    @Test
    void testEncryptResponseSetters() {
        // Given
        EncryptResponse response = new EncryptResponse("original-cipher", "original-iv");
        String newCiphertext = "new-encrypted-data";
        String newInitVector = "new-init-vector";

        // When
        response.setCiphertext(newCiphertext);
        response.setInitializeVector(newInitVector);

        // Then
        assertEquals(newCiphertext, response.getCiphertext(), "Ciphertext should be updated");
        assertEquals(newInitVector, response.getInitializeVector(), "Initialize vector should be updated");
    }

    @Test
    void testEncryptResponseWithNullValues() {
        // When/Then
        assertDoesNotThrow(() -> {
            EncryptResponse response = new EncryptResponse(null, null);
            assertNull(response.getCiphertext(), "Ciphertext should be null");
            assertNull(response.getInitializeVector(), "Initialize vector should be null");
        }, "EncryptResponse should handle null values");
    }
} 