package com.keepersecurity.secretsManager.storage.oracle;

import com.oracle.bmc.Region;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for OracleSessionConfig class
 */
class OracleSessionConfigTest {

    @Test
    void testParameterizedConstructor() {
        // Given
        String configPath = "~/.oci/config";
        String cryptoEndpoint = "https://test-crypto.kms.us-ashburn-1.oraclecloud.com";
        String managementEndpoint = "https://test-mgmt.kms.us-ashburn-1.oraclecloud.com";
        String vaultId = "ocid1.vault.oc1.test.12345";
        String keyId = "ocid1.key.oc1.test.67890";
        String keyVersionId = "1";
        Region region = Region.US_ASHBURN_1;

        // When
        OracleSessionConfig config = new OracleSessionConfig(
            configPath, cryptoEndpoint, managementEndpoint, vaultId, keyId, keyVersionId, region
        );

        // Then
        assertEquals(configPath, config.getConfigPath(), "ConfigPath should match constructor parameter");
        assertEquals(cryptoEndpoint, config.getCryptoEndpoint(), "CryptoEndpoint should match constructor parameter");
        assertEquals(managementEndpoint, config.getManagementEndpoint(), "ManagementEndpoint should match constructor parameter");
        assertEquals(vaultId, config.getVaultId(), "VaultId should match constructor parameter");
        assertEquals(keyId, config.getKeyId(), "KeyId should match constructor parameter");
        assertEquals(keyVersionId, config.getKeyVersionId(), "KeyVersionId should match constructor parameter");
        assertEquals(region, config.getRegion(), "Region should match constructor parameter");
    }

    @Test
    void testSettersAndGetters() {
        // Given
        OracleSessionConfig config = new OracleSessionConfig(
            "initial-config", "initial-crypto", "initial-mgmt",
            "initial-vault", "initial-key", "1", Region.US_ASHBURN_1
        );

        String newConfigPath = "~/.oci/production-config";
        String newCryptoEndpoint = "https://production-crypto.kms.us-phoenix-1.oraclecloud.com";
        String newManagementEndpoint = "https://production-mgmt.kms.us-phoenix-1.oraclecloud.com";
        String newVaultId = "ocid1.vault.oc1.prod.98765";
        String newKeyId = "ocid1.key.oc1.prod.54321";
        String newKeyVersionId = "2";
        Region newRegion = Region.US_PHOENIX_1;

        // When
        config.setConfigPath(newConfigPath);
        config.setCryptoEndpoint(newCryptoEndpoint);
        config.setManagementEndpoint(newManagementEndpoint);
        config.setVaultId(newVaultId);
        config.setKeyId(newKeyId);
        config.setKeyVersionId(newKeyVersionId);
        config.setRegion(newRegion);

        // Then
        assertEquals(newConfigPath, config.getConfigPath(), "ConfigPath getter should return value set by setter");
        assertEquals(newCryptoEndpoint, config.getCryptoEndpoint(), "CryptoEndpoint getter should return value set by setter");
        assertEquals(newManagementEndpoint, config.getManagementEndpoint(), "ManagementEndpoint getter should return value set by setter");
        assertEquals(newVaultId, config.getVaultId(), "VaultId getter should return value set by setter");
        assertEquals(newKeyId, config.getKeyId(), "KeyId getter should return value set by setter");
        assertEquals(newKeyVersionId, config.getKeyVersionId(), "KeyVersionId getter should return value set by setter");
        assertEquals(newRegion, config.getRegion(), "Region getter should return value set by setter");
    }

    @Test
    void testSettersWithNullValues() {
        // Given
        OracleSessionConfig config = new OracleSessionConfig(
            "initial-config", "initial-crypto", "initial-mgmt",
            "initial-vault", "initial-key", "1", Region.US_ASHBURN_1
        );

        // When - set all to null
        config.setConfigPath(null);
        config.setCryptoEndpoint(null);
        config.setManagementEndpoint(null);
        config.setVaultId(null);
        config.setKeyId(null);
        config.setKeyVersionId(null);
        config.setRegion(null);

        // Then
        assertNull(config.getConfigPath(), "ConfigPath should be null after setting to null");
        assertNull(config.getCryptoEndpoint(), "CryptoEndpoint should be null after setting to null");
        assertNull(config.getManagementEndpoint(), "ManagementEndpoint should be null after setting to null");
        assertNull(config.getVaultId(), "VaultId should be null after setting to null");
        assertNull(config.getKeyId(), "KeyId should be null after setting to null");
        assertNull(config.getKeyVersionId(), "KeyVersionId should be null after setting to null");
        assertNull(config.getRegion(), "Region should be null after setting to null");
    }

    @Test
    void testSettersWithEmptyStrings() {
        // Given
        OracleSessionConfig config = new OracleSessionConfig(
            "initial-config", "initial-crypto", "initial-mgmt",
            "initial-vault", "initial-key", "1", Region.US_ASHBURN_1
        );

        // When
        config.setConfigPath("");
        config.setCryptoEndpoint("");
        config.setManagementEndpoint("");
        config.setVaultId("");
        config.setKeyId("");
        config.setKeyVersionId("");

        // Then
        assertEquals("", config.getConfigPath(), "ConfigPath should handle empty string");
        assertEquals("", config.getCryptoEndpoint(), "CryptoEndpoint should handle empty string");
        assertEquals("", config.getManagementEndpoint(), "ManagementEndpoint should handle empty string");
        assertEquals("", config.getVaultId(), "VaultId should handle empty string");
        assertEquals("", config.getKeyId(), "KeyId should handle empty string");
        assertEquals("", config.getKeyVersionId(), "KeyVersionId should handle empty string");
    }

    @Test
    void testConstructorWithNullValues() {
        // When/Then - constructor should accept null values
        assertDoesNotThrow(() -> {
            OracleSessionConfig config = new OracleSessionConfig(null, null, null, null, null, null, null);
            assertNull(config.getConfigPath());
            assertNull(config.getCryptoEndpoint());
            assertNull(config.getManagementEndpoint());
            assertNull(config.getVaultId());
            assertNull(config.getKeyId());
            assertNull(config.getKeyVersionId());
            assertNull(config.getRegion());
        }, "Constructor should accept null values without throwing exception");
    }

    @Test
    void testKeyVersionHandling() {
        // Test different key version formats
        String[] keyVersions = {"1", "2", "10", "latest"};

        for (String keyVersion : keyVersions) {
            // Given/When
            OracleSessionConfig config = new OracleSessionConfig(
                "~/.oci/config",
                "https://crypto.kms.us-ashburn-1.oraclecloud.com",
                "https://mgmt.kms.us-ashburn-1.oraclecloud.com",
                "ocid1.vault.oc1.test.12345",
                "ocid1.key.oc1.test.67890",
                keyVersion,
                Region.US_ASHBURN_1
            );

            // Then
            assertEquals(keyVersion, config.getKeyVersionId(),
                "Should accept key version: " + keyVersion);
        }
    }

    @Test
    void testRegionFormats() {
        // Test various Oracle Cloud regions
        Region[] regions = {
            Region.US_ASHBURN_1,
            Region.US_PHOENIX_1,
            Region.UK_LONDON_1,
            Region.EU_FRANKFURT_1,
            Region.AP_TOKYO_1,
            Region.AP_SYDNEY_1,
            Region.CA_TORONTO_1
        };

        for (Region region : regions) {
            // Given/When
            OracleSessionConfig config = new OracleSessionConfig(
                "~/.oci/config",
                "https://crypto.kms." + region.getRegionId() + ".oraclecloud.com",
                "https://mgmt.kms." + region.getRegionId() + ".oraclecloud.com",
                "ocid1.vault.oc1.test.12345",
                "ocid1.key.oc1.test.67890",
                "1",
                region
            );

            // Then
            assertEquals(region, config.getRegion(),
                "Should accept region: " + region.getRegionId());
        }
    }

    @Test
    void testConfigPathFormats() {
        // Test various config file paths
        String[] configPaths = {
            "~/.oci/config",
            "/home/user/.oci/config",
            "./oci-config",
            "../config/oci-config",
            "/absolute/path/to/oci-config",
            "" // empty string for default config location
        };

        for (String configPath : configPaths) {
            // Given/When
            OracleSessionConfig config = new OracleSessionConfig(
                configPath,
                "https://crypto.kms.us-ashburn-1.oraclecloud.com",
                "https://mgmt.kms.us-ashburn-1.oraclecloud.com",
                "ocid1.vault.oc1.test.12345",
                "ocid1.key.oc1.test.67890",
                "1",
                Region.US_ASHBURN_1
            );

            // Then
            assertEquals(configPath, config.getConfigPath(),
                "Should accept config path: " + configPath);
        }
    }

    @Test
    void testOcidFormats() {
        // Test various OCID formats for vault and key
        String vaultId = "ocid1.vault.oc1.iad.aaaaaaaabcdefghijklmnopqrstuvwxyz";
        String keyId = "ocid1.key.oc1.iad.zyxwvutsrqponmlkjihgfedcbaaaaaa";

        // Given/When
        OracleSessionConfig config = new OracleSessionConfig(
            "~/.oci/config",
            "https://crypto.kms.us-ashburn-1.oraclecloud.com",
            "https://mgmt.kms.us-ashburn-1.oraclecloud.com",
            vaultId,
            keyId,
            "1",
            Region.US_ASHBURN_1
        );

        // Then
        assertEquals(vaultId, config.getVaultId(), "Should accept full OCID vault format");
        assertEquals(keyId, config.getKeyId(), "Should accept full OCID key format");
    }
}
