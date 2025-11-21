import { AzureKeyValueStorage } from '../src/AzureKeyValueStorage';
import { AzureSessionConfig } from '../src/AzureSessionConfig';

// Mock Azure SDK modules
jest.mock('@azure/identity');
jest.mock('@azure/keyvault-keys');
jest.mock('fs', () => ({
    promises: {
        readFile: jest.fn(),
        writeFile: jest.fn(),
        mkdir: jest.fn(),
        access: jest.fn(),
    }
}));

describe('AzureKeyValueStorage', () => {
    describe('constructor', () => {
        it('should create instance with valid parameters', () => {
            // Given
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key/version1';
            const configFileLocation = './test-config.json';
            const azSessionConfig = new AzureSessionConfig('tenant-id', 'client-id', 'client-secret');

            // When/Then - Constructor should not throw
            expect(() => {
                new AzureKeyValueStorage(keyId, configFileLocation, azSessionConfig, null);
            }).not.toThrow();
        });

        it('should create instance with null config file location', () => {
            // Given
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key/version1';
            const azSessionConfig = new AzureSessionConfig('tenant-id', 'client-id', 'client-secret');

            // When/Then
            expect(() => {
                new AzureKeyValueStorage(keyId, null, azSessionConfig, null);
            }).not.toThrow();
        });

        it('should create instance with null session config', () => {
            // Given
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key/version1';
            const configFileLocation = './test-config.json';

            // When/Then
            expect(() => {
                new AzureKeyValueStorage(keyId, configFileLocation, null, null);
            }).not.toThrow();
        });

        it('should create instance with all null optional parameters', () => {
            // Given
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key/version1';

            // When/Then
            expect(() => {
                new AzureKeyValueStorage(keyId, null, null, null);
            }).not.toThrow();
        });
    });

    describe('constructor with various key ID formats', () => {
        it('should accept key ID with version', () => {
            // Given - Key ID with specific version
            const keyId = 'https://my-vault.vault.azure.net/keys/my-key/fe4fdcab688c479a9aa80f01ffeac26';

            // When/Then
            expect(() => {
                new AzureKeyValueStorage(keyId, null, null, null);
            }).not.toThrow();
        });

        it('should accept key ID without version', () => {
            // Given - Key ID without version (uses latest)
            const keyId = 'https://my-vault.vault.azure.net/keys/my-key';

            // When/Then
            expect(() => {
                new AzureKeyValueStorage(keyId, null, null, null);
            }).not.toThrow();
        });

        it('should accept key ID with different vault names', () => {
            // Given
            const vaultNames = [
                'test-vault',
                'production-vault',
                'my-vault-123'
            ];

            vaultNames.forEach(vaultName => {
                const keyId = `https://${vaultName}.vault.azure.net/keys/test-key`;

                // When/Then
                expect(() => {
                    new AzureKeyValueStorage(keyId, null, null, null);
                }).not.toThrow();
            });
        });
    });

    describe('interface implementation', () => {
        let storage: AzureKeyValueStorage;

        beforeEach(() => {
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key';
            const azSessionConfig = new AzureSessionConfig('tenant-id', 'client-id', 'client-secret');
            storage = new AzureKeyValueStorage(keyId, null, azSessionConfig, null);
        });

        it('should have getString method', () => {
            expect(storage.getString).toBeDefined();
            expect(typeof storage.getString).toBe('function');
        });

        it('should have saveString method', () => {
            expect(storage.saveString).toBeDefined();
            expect(typeof storage.saveString).toBe('function');
        });

        it('should have getBytes method', () => {
            expect(storage.getBytes).toBeDefined();
            expect(typeof storage.getBytes).toBe('function');
        });

        it('should have saveBytes method', () => {
            expect(storage.saveBytes).toBeDefined();
            expect(typeof storage.saveBytes).toBe('function');
        });

        it('should have getObject method', () => {
            expect(storage.getObject).toBeDefined();
            expect(typeof storage.getObject).toBe('function');
        });

        it('should have saveObject method', () => {
            expect(storage.saveObject).toBeDefined();
            expect(typeof storage.saveObject).toBe('function');
        });
    });

    describe('configuration file paths', () => {
        it('should handle absolute config file paths', () => {
            // Given
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key';
            const configFileLocation = '/absolute/path/to/config.json';

            // When/Then
            expect(() => {
                new AzureKeyValueStorage(keyId, configFileLocation, null, null);
            }).not.toThrow();
        });

        it('should handle relative config file paths', () => {
            // Given
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key';
            const configFileLocations = [
                './config.json',
                '../config.json',
                '../../nested/config.json'
            ];

            configFileLocations.forEach(configFileLocation => {
                // When/Then
                expect(() => {
                    new AzureKeyValueStorage(keyId, configFileLocation, null, null);
                }).not.toThrow();
            });
        });
    });

    describe('session config variations', () => {
        it('should handle session config with empty strings', () => {
            // Given
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key';
            const azSessionConfig = new AzureSessionConfig('', '', '');

            // When/Then
            expect(() => {
                new AzureKeyValueStorage(keyId, null, azSessionConfig, null);
            }).not.toThrow();
        });

        it('should handle session config with partial values', () => {
            // Given
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key';

            // Test with only tenant ID
            const config1 = new AzureSessionConfig('tenant-only', '', '');
            expect(() => {
                new AzureKeyValueStorage(keyId, null, config1, null);
            }).not.toThrow();

            // Test with only client ID
            const config2 = new AzureSessionConfig('', 'client-only', '');
            expect(() => {
                new AzureKeyValueStorage(keyId, null, config2, null);
            }).not.toThrow();

            // Test with only secret
            const config3 = new AzureSessionConfig('', '', 'secret-only');
            expect(() => {
                new AzureKeyValueStorage(keyId, null, config3, null);
            }).not.toThrow();
        });
    });
});
