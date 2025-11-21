package com.keepersecurity.secretsManager.storage.azure;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AzureSessionConfig class
 */
class AzureSessionConfigTest {

    @Test
    void testDefaultConstructor() {
        // When
        AzureSessionConfig config = new AzureSessionConfig();

        // Then
        assertNull(config.getTenantId(), "TenantId should be null for default constructor");
        assertNull(config.getClientId(), "ClientId should be null for default constructor");
        assertNull(config.getClientSecret(), "ClientSecret should be null for default constructor");
        assertNull(config.getKeyVaultUrl(), "KeyVaultUrl should be null for default constructor");
    }

    @Test
    void testParameterizedConstructor() {
        // Given
        String tenantId = "12345678-1234-1234-1234-123456789012";
        String clientId = "87654321-4321-4321-4321-210987654321";
        String clientSecret = "test-client-secret-value";
        String keyVaultUrl = "https://test-keyvault.vault.azure.net/";

        // When
        AzureSessionConfig config = new AzureSessionConfig(
            tenantId, clientId, clientSecret, keyVaultUrl
        );

        // Then
        assertEquals(tenantId, config.getTenantId(), "TenantId should match constructor parameter");
        assertEquals(clientId, config.getClientId(), "ClientId should match constructor parameter");
        assertEquals(clientSecret, config.getClientSecret(), "ClientSecret should match constructor parameter");
        assertEquals(keyVaultUrl, config.getKeyVaultUrl(), "KeyVaultUrl should match constructor parameter");
    }

    @Test
    void testSettersAndGetters() {
        // Given
        AzureSessionConfig config = new AzureSessionConfig(
            "initial-tenant", "initial-client", "initial-secret", "https://initial.vault.azure.net/"
        );

        String newTenantId = "98765432-8765-8765-8765-987654321098";
        String newClientId = "11223344-1122-1122-1122-112233445566";
        String newClientSecret = "new-secret-value";
        String newKeyVaultUrl = "https://production-keyvault.vault.azure.net/";

        // When
        config.setTenantId(newTenantId);
        config.setClientId(newClientId);
        config.setClientSecret(newClientSecret);
        config.setKeyVaultUrl(newKeyVaultUrl);

        // Then
        assertEquals(newTenantId, config.getTenantId(), "TenantId getter should return value set by setter");
        assertEquals(newClientId, config.getClientId(), "ClientId getter should return value set by setter");
        assertEquals(newClientSecret, config.getClientSecret(), "ClientSecret getter should return value set by setter");
        assertEquals(newKeyVaultUrl, config.getKeyVaultUrl(), "KeyVaultUrl getter should return value set by setter");
    }

    @Test
    void testSettersWithNullValues() {
        // Given
        AzureSessionConfig config = new AzureSessionConfig(
            "initial-tenant", "initial-client", "initial-secret", "https://initial.vault.azure.net/"
        );

        // When - set all to null
        config.setTenantId(null);
        config.setClientId(null);
        config.setClientSecret(null);
        config.setKeyVaultUrl(null);

        // Then
        assertNull(config.getTenantId(), "TenantId should be null after setting to null");
        assertNull(config.getClientId(), "ClientId should be null after setting to null");
        assertNull(config.getClientSecret(), "ClientSecret should be null after setting to null");
        assertNull(config.getKeyVaultUrl(), "KeyVaultUrl should be null after setting to null");
    }

    @Test
    void testSettersWithEmptyStrings() {
        // Given
        AzureSessionConfig config = new AzureSessionConfig(
            "initial-tenant", "initial-client", "initial-secret", "https://initial.vault.azure.net/"
        );

        // When
        config.setTenantId("");
        config.setClientId("");
        config.setClientSecret("");
        config.setKeyVaultUrl("");

        // Then
        assertEquals("", config.getTenantId(), "TenantId should handle empty string");
        assertEquals("", config.getClientId(), "ClientId should handle empty string");
        assertEquals("", config.getClientSecret(), "ClientSecret should handle empty string");
        assertEquals("", config.getKeyVaultUrl(), "KeyVaultUrl should handle empty string");
    }

    @Test
    void testConstructorWithNullValues() {
        // When/Then - constructor should accept null values
        assertDoesNotThrow(() -> {
            AzureSessionConfig config = new AzureSessionConfig(null, null, null, null);
            assertNull(config.getTenantId());
            assertNull(config.getClientId());
            assertNull(config.getClientSecret());
            assertNull(config.getKeyVaultUrl());
        }, "Constructor should accept null values without throwing exception");
    }

    @Test
    void testKeyVaultUrlFormats() {
        // Test various Azure Key Vault URL formats
        String[] keyVaultUrls = {
            "https://test-keyvault.vault.azure.net/",
            "https://production-keyvault.vault.azure.net/",
            "https://keyvault-dev.vault.azure.net/",
            "https://my-kv.vault.azure.net",
            "https://keyvault.vault.usgovcloudapi.net/",  // Azure Government
            "https://keyvault.vault.azure.cn/"  // Azure China
        };

        for (String keyVaultUrl : keyVaultUrls) {
            // Given/When
            AzureSessionConfig config = new AzureSessionConfig(
                "12345678-1234-1234-1234-123456789012",
                "87654321-4321-4321-4321-210987654321",
                "test-secret",
                keyVaultUrl
            );

            // Then
            assertEquals(keyVaultUrl, config.getKeyVaultUrl(),
                "Should accept Key Vault URL format: " + keyVaultUrl);
        }
    }

    @Test
    void testTenantIdFormats() {
        // Test various Azure tenant ID formats
        String[] tenantIds = {
            "12345678-1234-1234-1234-123456789012",  // Standard GUID
            "common",  // Multi-tenant
            "organizations",  // Work/school accounts
            "consumers"  // Personal Microsoft accounts
        };

        for (String tenantId : tenantIds) {
            // Given/When
            AzureSessionConfig config = new AzureSessionConfig(
                tenantId,
                "87654321-4321-4321-4321-210987654321",
                "test-secret",
                "https://test-keyvault.vault.azure.net/"
            );

            // Then
            assertEquals(tenantId, config.getTenantId(),
                "Should accept tenant ID format: " + tenantId);
        }
    }
}
