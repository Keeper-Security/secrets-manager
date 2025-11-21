package com.keepersecurity.secretsManager.storage.aws;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AwsSessionConfig class
 */
class AwsSessionConfigTest {

    @Test
    void testParameterizedConstructor() {
        // Given
        String awsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

        // When
        AwsSessionConfig config = new AwsSessionConfig(awsAccessKeyId, awsSecretAccessKey);

        // Then
        assertEquals(awsAccessKeyId, config.getAwsAccessKeyId(), "AwsAccessKeyId should match constructor parameter");
        assertEquals(awsSecretAccessKey, config.getAwsSecretAccessKey(), "AwsSecretAccessKey should match constructor parameter");
    }

    @Test
    void testSettersAndGetters() {
        // Given
        AwsSessionConfig config = new AwsSessionConfig(
            "initial-access-key-id",
            "initial-secret-access-key"
        );

        String newAccessKeyId = "AKIAI44QH8DHBEXAMPLE";
        String newSecretAccessKey = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY";

        // When
        config.setAwsAccessKeyId(newAccessKeyId);
        config.setAwsSecretAccessKey(newSecretAccessKey);

        // Then
        assertEquals(newAccessKeyId, config.getAwsAccessKeyId(), "AwsAccessKeyId getter should return value set by setter");
        assertEquals(newSecretAccessKey, config.getAwsSecretAccessKey(), "AwsSecretAccessKey getter should return value set by setter");
    }

    @Test
    void testSettersWithNullValues() {
        // Given
        AwsSessionConfig config = new AwsSessionConfig(
            "initial-access-key-id",
            "initial-secret-access-key"
        );

        // When - set all to null
        config.setAwsAccessKeyId(null);
        config.setAwsSecretAccessKey(null);

        // Then
        assertNull(config.getAwsAccessKeyId(), "AwsAccessKeyId should be null after setting to null");
        assertNull(config.getAwsSecretAccessKey(), "AwsSecretAccessKey should be null after setting to null");
    }

    @Test
    void testSettersWithEmptyStrings() {
        // Given
        AwsSessionConfig config = new AwsSessionConfig(
            "initial-access-key-id",
            "initial-secret-access-key"
        );

        // When
        config.setAwsAccessKeyId("");
        config.setAwsSecretAccessKey("");

        // Then
        assertEquals("", config.getAwsAccessKeyId(), "AwsAccessKeyId should handle empty string");
        assertEquals("", config.getAwsSecretAccessKey(), "AwsSecretAccessKey should handle empty string");
    }

    @Test
    void testConstructorWithNullValues() {
        // When/Then - constructor should accept null values
        assertDoesNotThrow(() -> {
            AwsSessionConfig config = new AwsSessionConfig(null, null);
            assertNull(config.getAwsAccessKeyId());
            assertNull(config.getAwsSecretAccessKey());
        }, "Constructor should accept null values without throwing exception");
    }

    @Test
    void testAccessKeyIdFormats() {
        // Test various AWS access key ID formats
        String[] accessKeyIds = {
            "AKIAIOSFODNN7EXAMPLE",  // Standard format
            "ASIATESTACCESSKEY",  // Temporary security credentials
            "AROATEST",  // Assumed role
            "AIDAI",  // IAM user
            "AGPAI"  // IAM group
        };

        for (String accessKeyId : accessKeyIds) {
            // Given/When
            AwsSessionConfig config = new AwsSessionConfig(
                accessKeyId,
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            );

            // Then
            assertEquals(accessKeyId, config.getAwsAccessKeyId(),
                "Should accept access key ID format: " + accessKeyId);
        }
    }

    @Test
    void testSecretAccessKeyFormats() {
        // Test various secret access key formats
        String[] secretAccessKeys = {
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  // Standard 40-char
            "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",  // Standard format
            "1234567890abcdefghijklmnopqrstuvwxyz1234"  // 40 alphanumeric
        };

        for (String secretAccessKey : secretAccessKeys) {
            // Given/When
            AwsSessionConfig config = new AwsSessionConfig(
                "AKIAIOSFODNN7EXAMPLE",
                secretAccessKey
            );

            // Then
            assertEquals(secretAccessKey, config.getAwsSecretAccessKey(),
                "Should accept secret access key format: " + secretAccessKey);
        }
    }

    @Test
    void testImmutabilityOfConstructorParameters() {
        // Given
        String originalAccessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String originalSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

        // When
        AwsSessionConfig config = new AwsSessionConfig(originalAccessKeyId, originalSecretAccessKey);

        // Verify initial values
        assertEquals(originalAccessKeyId, config.getAwsAccessKeyId());
        assertEquals(originalSecretAccessKey, config.getAwsSecretAccessKey());

        // Change via setters
        config.setAwsAccessKeyId("NEWKEYIDEXAMPLE");
        config.setAwsSecretAccessKey("newSecretKeyExample");

        // Then - original strings should be unaffected (this is just a sanity check)
        assertEquals("AKIAIOSFODNN7EXAMPLE", originalAccessKeyId, "Original variable should be unchanged");
        assertEquals("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", originalSecretAccessKey, "Original variable should be unchanged");
    }

    @Test
    void testConfigurationUpdate() {
        // Given - initial development credentials
        AwsSessionConfig config = new AwsSessionConfig(
            "AKIADEVKEYEXAMPLE",
            "devSecretKeyExample/1234567890"
        );

        assertEquals("AKIADEVKEYEXAMPLE", config.getAwsAccessKeyId());
        assertEquals("devSecretKeyExample/1234567890", config.getAwsSecretAccessKey());

        // When - update to production credentials
        config.setAwsAccessKeyId("AKIAPRODKEYEXAMPLE");
        config.setAwsSecretAccessKey("prodSecretKeyExample/0987654321");

        // Then - should reflect production credentials
        assertEquals("AKIAPRODKEYEXAMPLE", config.getAwsAccessKeyId());
        assertEquals("prodSecretKeyExample/0987654321", config.getAwsSecretAccessKey());
    }
}
