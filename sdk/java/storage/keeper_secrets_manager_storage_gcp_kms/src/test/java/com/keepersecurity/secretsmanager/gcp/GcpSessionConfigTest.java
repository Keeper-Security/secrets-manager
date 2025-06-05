package com.keepersecurity.secretsmanager.gcp;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for GcpSessionConfig class
 */
class GcpSessionConfigTest {

    @Test
    void testParameterizedConstructor() {
        // Given
        String projectId = "test-project-123";
        String location = "us-central1";
        String keyRing = "test-keyring";
        String keyId = "test-key";
        String keyVersion = "1";
        String credentialsPath = "/path/to/credentials.json";

        // When
        GcpSessionConfig config = new GcpSessionConfig(
            projectId, location, keyRing, keyId, keyVersion, credentialsPath
        );

        // Then
        assertEquals(projectId, config.getProjectId(), "ProjectId should match constructor parameter");
        assertEquals(location, config.getLocation(), "Location should match constructor parameter");
        assertEquals(keyRing, config.getKeyRing(), "KeyRing should match constructor parameter");
        assertEquals(keyId, config.getKeyId(), "KeyId should match constructor parameter");
        assertEquals(keyVersion, config.getKeyVersion(), "KeyVersion should match constructor parameter");
        assertEquals(credentialsPath, config.getCredentialsPath(), "CredentialsPath should match constructor parameter");
    }

    @Test
    void testSettersAndGetters() {
        // Given
        GcpSessionConfig config = new GcpSessionConfig(
            "initial-project", "initial-location", "initial-keyring", 
            "initial-key", "1", "/initial/path"
        );

        String newProjectId = "new-project-456";
        String newLocation = "europe-west1";
        String newKeyRing = "production-keyring";
        String newKeyId = "production-key";
        String newKeyVersion = "2";
        String newCredentialsPath = "/secure/credentials.json";

        // When
        config.setProjectId(newProjectId);
        config.setLocation(newLocation);
        config.setKeyRing(newKeyRing);
        config.setKeyId(newKeyId);
        config.setKeyVersion(newKeyVersion);
        config.setCredentialsPath(newCredentialsPath);

        // Then
        assertEquals(newProjectId, config.getProjectId(), "ProjectId getter should return value set by setter");
        assertEquals(newLocation, config.getLocation(), "Location getter should return value set by setter");
        assertEquals(newKeyRing, config.getKeyRing(), "KeyRing getter should return value set by setter");
        assertEquals(newKeyId, config.getKeyId(), "KeyId getter should return value set by setter");
        assertEquals(newKeyVersion, config.getKeyVersion(), "KeyVersion getter should return value set by setter");
        assertEquals(newCredentialsPath, config.getCredentialsPath(), "CredentialsPath getter should return value set by setter");
    }

    @Test
    void testSettersWithNullValues() {
        // Given
        GcpSessionConfig config = new GcpSessionConfig(
            "initial-project", "initial-location", "initial-keyring", 
            "initial-key", "1", "/initial/path"
        );

        // When - set all to null
        config.setProjectId(null);
        config.setLocation(null);
        config.setKeyRing(null);
        config.setKeyId(null);
        config.setKeyVersion(null);
        config.setCredentialsPath(null);

        // Then
        assertNull(config.getProjectId(), "ProjectId should be null after setting to null");
        assertNull(config.getLocation(), "Location should be null after setting to null");
        assertNull(config.getKeyRing(), "KeyRing should be null after setting to null");
        assertNull(config.getKeyId(), "KeyId should be null after setting to null");
        assertNull(config.getKeyVersion(), "KeyVersion should be null after setting to null");
        assertNull(config.getCredentialsPath(), "CredentialsPath should be null after setting to null");
    }

    @Test
    void testSettersWithEmptyStrings() {
        // Given
        GcpSessionConfig config = new GcpSessionConfig(
            "initial-project", "initial-location", "initial-keyring", 
            "initial-key", "1", "/initial/path"
        );

        // When
        config.setProjectId("");
        config.setLocation("");
        config.setKeyRing("");
        config.setKeyId("");
        config.setKeyVersion("");
        config.setCredentialsPath("");

        // Then
        assertEquals("", config.getProjectId(), "ProjectId should handle empty string");
        assertEquals("", config.getLocation(), "Location should handle empty string");
        assertEquals("", config.getKeyRing(), "KeyRing should handle empty string");
        assertEquals("", config.getKeyId(), "KeyId should handle empty string");
        assertEquals("", config.getKeyVersion(), "KeyVersion should handle empty string");
        assertEquals("", config.getCredentialsPath(), "CredentialsPath should handle empty string");
    }

    @Test
    void testConstructorWithNullValues() {
        // When/Then - constructor should accept null values
        assertDoesNotThrow(() -> {
            GcpSessionConfig config = new GcpSessionConfig(null, null, null, null, null, null);
            assertNull(config.getProjectId());
            assertNull(config.getLocation());
            assertNull(config.getKeyRing());
            assertNull(config.getKeyId());
            assertNull(config.getKeyVersion());
            assertNull(config.getCredentialsPath());
        }, "Constructor should accept null values without throwing exception");
    }

    @Test
    void testKeyVersionHandling() {
        // Test different key version formats
        String[] keyVersions = {"1", "2", "10", "latest"};

        for (String keyVersion : keyVersions) {
            // Given/When
            GcpSessionConfig config = new GcpSessionConfig(
                "test-project", "us-central1", "test-keyring", "test-key", keyVersion, "/path/to/credentials.json"
            );

            // Then
            assertEquals(keyVersion, config.getKeyVersion(),
                "Should accept key version: " + keyVersion);
        }
    }

    @Test
    void testLocationFormats() {
        // Test various GCP location formats
        String[] locations = {
            "us-central1", "us-east1", "us-west1",
            "europe-west1", "europe-central2",
            "asia-southeast1", "asia-northeast1",
            "global"
        };

        for (String location : locations) {
            // Given/When
            GcpSessionConfig config = new GcpSessionConfig(
                "test-project", location, "test-keyring", "test-key", "1", "/path/to/credentials.json"
            );

            // Then
            assertEquals(location, config.getLocation(),
                "Should accept location format: " + location);
        }
    }

    @Test
    void testCredentialsPathFormats() {
        // Test various credential file paths
        String[] credentialsPaths = {
            "/path/to/credentials.json",
            "./credentials.json",
            "../config/gcp-credentials.json",
            "/absolute/path/to/service-account.json",
            "" // empty string for environment variable credentials
        };

        for (String credentialsPath : credentialsPaths) {
            // Given/When
            GcpSessionConfig config = new GcpSessionConfig(
                "test-project", "us-central1", "test-keyring", "test-key", "1", credentialsPath
            );

            // Then
            assertEquals(credentialsPath, config.getCredentialsPath(),
                "Should accept credentials path: " + credentialsPath);
        }
    }
} 