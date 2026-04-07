import { AzureKeyValueStorage } from '../src/AzureKeyValueStorage';
import { AzureSessionConfig } from '../src/AzureSessionConfig';
import { CryptographyClient } from '@azure/keyvault-keys';
import * as utils from '../src/utils';

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

    // KSM-844: Regression tests — saveConfig() must propagate encryption errors to callers
    describe('saveConfig() error propagation — KSM-844 regression', () => {
        let storage: AzureKeyValueStorage;

        beforeEach(() => {
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key';
            storage = new AzureKeyValueStorage(keyId, null, null, null);
            // Seed private config so saveConfig can compute hashes without hitting loadConfig
            (storage as any).config = {};
        });

        afterEach(() => {
            jest.restoreAllMocks();
        });

        it('saveString() should throw when encryption fails', async () => {
            // Given: encryption fails at the Azure KMS layer
            jest.spyOn(utils, 'encryptBuffer').mockRejectedValue(new Error('Azure KMS encryption failed'));
            jest.spyOn(storage, 'readStorage').mockResolvedValue({});

            // When/Then: error must propagate to the caller, not be silently swallowed
            await expect(storage.saveString('key', 'value')).rejects.toThrow();
        });

        it('changeKey() should throw and roll back to the original key when encryption fails', async () => {
            // Given
            const originalKeyId = 'https://test-vault.vault.azure.net/keys/test-key';
            const newKeyId = 'https://bad-vault.vault.azure.net/keys/bad-key';
            jest.spyOn(utils, 'encryptBuffer').mockRejectedValue(new Error('Azure KMS encryption failed'));

            // When
            await expect(storage.changeKey(newKeyId)).rejects.toThrow('Failed to change the key');

            // Then: original key must be restored (rollback path is now reachable)
            expect((storage as any).keyId).toBe(originalKeyId);
        });
    });

    // KSM-844: utils.ts error propagation — encryptBuffer() and decryptBuffer() must throw, not swallow
    describe('utils.ts error propagation — KSM-844 regression', () => {
        let mockLogger: any;

        beforeEach(() => {
            mockLogger = { debug: jest.fn(), error: jest.fn(), warn: jest.fn(), info: jest.fn() };
        });

        afterEach(() => {
            jest.restoreAllMocks();
        });

        it('encryptBuffer() should throw when wrapKey fails', async () => {
            // Given: Azure wrapKey fails
            const mockClient = new (CryptographyClient as jest.MockedClass<typeof CryptographyClient>)('url', null as any);
            (mockClient.wrapKey as jest.Mock).mockRejectedValue(new Error('Azure KMS wrapKey failed'));

            // When/Then: encryptBuffer must propagate the error, not return an empty buffer
            await expect(utils.encryptBuffer(mockClient, 'test-message', mockLogger)).rejects.toThrow();
        });

        it('decryptBuffer() should throw when unwrapKey fails', async () => {
            // Given: construct a minimal valid blob to pass header/structure validation
            const header = Buffer.from('\xff\xff', 'latin1');
            const makePart = (data: Buffer) => {
                const len = Buffer.alloc(2);
                len.writeUInt16BE(data.length, 0);
                return Buffer.concat([len, data]);
            };
            const blob = Buffer.concat([
                header,
                makePart(Buffer.alloc(16, 0xAA)), // wrappedKey
                makePart(Buffer.alloc(16, 0xBB)), // nonce
                makePart(Buffer.alloc(16, 0xCC)), // tag
                makePart(Buffer.alloc(4, 0xDD)),  // ciphertext
            ]);

            // Azure unwrapKey fails
            const mockClient = new (CryptographyClient as jest.MockedClass<typeof CryptographyClient>)('url', null as any);
            (mockClient.unwrapKey as jest.Mock).mockRejectedValue(new Error('Azure KMS unwrapKey failed'));

            // When/Then: decryptBuffer must propagate the error, not return an empty string
            await expect(utils.decryptBuffer(mockClient, blob, mockLogger)).rejects.toThrow();
        });
    });

    // KSM-850: Regression tests — getBytes() must return empty Uint8Array for zero-length values
    describe('getBytes() zero-length Uint8Array — KSM-850 regression', () => {
        let storage: AzureKeyValueStorage;

        beforeEach(() => {
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key';
            storage = new AzureKeyValueStorage(keyId, null, null, null);
        });

        afterEach(() => {
            jest.restoreAllMocks();
        });

        it('getBytes() should return a defined empty Uint8Array for a key storing zero-length bytes', async () => {
            // Given: empty Uint8Array was previously saved (stored as empty base64 string "")
            jest.spyOn(storage, 'readStorage').mockResolvedValue({ emptyKey: '' });

            // When
            const result = await storage.getBytes('emptyKey');

            // Then: must return Uint8Array(0), not undefined
            expect(result).toBeDefined();
            expect(result).toBeInstanceOf(Uint8Array);
            expect(result!.length).toBe(0);
        });

        it('getBytes() should still return undefined for a key that was never saved', async () => {
            // Given: key is absent from storage
            jest.spyOn(storage, 'readStorage').mockResolvedValue({});

            // When
            const result = await storage.getBytes('missingKey');

            // Then
            expect(result).toBeUndefined();
        });

        it('contains() and getBytes() must be consistent: if contains returns true, getBytes must return defined', async () => {
            // Given: empty Uint8Array stored
            jest.spyOn(storage, 'readStorage').mockResolvedValue({ emptyKey: '' });

            // When
            const exists = await storage.contains('emptyKey');
            const value = await storage.getBytes('emptyKey');

            // Then
            expect(exists).toBe(true);
            expect(value).toBeDefined();
        });
    });

    // KSM-835: Regression tests for delete() and contains() — incorrect `in` operator usage
    describe('delete() and contains() — KSM-835 regression', () => {
        let storage: AzureKeyValueStorage;
        let mockConfig: Record<string, string>;

        beforeEach(() => {
            const keyId = 'https://test-vault.vault.azure.net/keys/test-key';
            storage = new AzureKeyValueStorage(keyId, null, null, null);

            // Seed config with known key/value pair
            mockConfig = { clientId: 'abc', appKey: 'xyz' };

            // Bypass Azure KMS: spy on readStorage/saveStorage directly
            jest.spyOn(storage, 'readStorage').mockResolvedValue(mockConfig);
            jest.spyOn(storage, 'saveStorage').mockResolvedValue(undefined);
        });

        afterEach(() => {
            jest.restoreAllMocks();
        });

        it('delete() should remove an existing key from config', async () => {
            // When
            await storage.delete('clientId');

            // Then — key must be gone from the config object
            expect('clientId' in mockConfig).toBe(false);
        });

        it('contains() should return true for an existing key', async () => {
            // When
            const result = await storage.contains('clientId');

            // Then
            expect(result).toBe(true);
        });

        it('contains() should return false for a missing key', async () => {
            // When
            const result = await storage.contains('nonexistent');

            // Then
            expect(result).toBe(false);
        });
    });
});
